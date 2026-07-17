"""Shared pipeline factory for CLI commands.

Builds a ``Pipeline`` backed by the default SQLite store and an AI engine
selected from ``RuntimeConfig`` (ADR-0022 / issue #54):

- ``ai_enabled`` true  → the real ``OpenAIEngine`` (local-first; degrades
  gracefully to ``ai_status="unavailable"`` when the endpoint is unreachable).
- ``ai_enabled`` false → a rules-only ``DisabledAIEngine`` (core-owned,
  ``firewatch_core.adapters.ai_disabled`` — relocated here from this module
  by issue #39) that reports ``ai_status="disabled"`` and never contacts an
  inference endpoint.
- ``ai_enabled`` true but engine CONSTRUCTION fails → the same
  ``DisabledAIEngine``, constructed with ``fault=True`` (issue #40 AC4): this
  is a FAULT (admin wanted AI, the engine could not be built), never a choice,
  so it reports ``ai_status="unavailable"``, not ``"disabled"``.

Issue #150 — enrichment wiring:
  The pipeline is constructed with a geo enricher so that geo enrichment
  fires automatically after every live collect cycle.  The enricher is
  selected from ``RuntimeConfig.geo_provider`` (ADR-0039):

  - ``geo_provider="offline"`` (default, ADR-0039): ``MmdbGeoEnricher`` — reads
    DB-IP Lite MMDB files downloaded once on first run; zero network egress
    after that. Air-gapped operators copy the files in manually (MI-4/#385).
  - ``geo_provider="online"``: ``GeoEnricher`` — calls ip-api.com.
    EGRESS DISCLOSURE: the free tier uses plaintext HTTP and sends the IPs
    being looked up to ip-api.com.

  Rule descriptions are promoted from source_kv by the pipeline itself
  (no factory change needed for that path — source-agnostic, always active).

Core imports are at module level (not deferred): this module is itself imported
only when a CLI command (``run`` / ``sync`` / ``serve``) executes — ``main``
defers the command-module imports — so importing core here does not slow
``firewatch --help`` or ``firewatch new-source``.

Issue #75 (ADR-0067 D6 + Amendment 1) — enforcement-posture defaults:
  When a plugin ``registry`` is supplied, ``_build_pipeline`` derives
  ``source_type -> SourceMetadata.enforcement`` for every loaded plugin and wires
  it into the ``Pipeline`` as ``posture_defaults`` (Phase A: plugin defaults only —
  the per-instance override, issue #44, is Phase B and does not touch this seam).
  ``registry`` is optional and defaults to ``None`` — a caller that omits it (or a
  test that never passes it) gets the pre-#75 pipeline unchanged.
"""
from __future__ import annotations

import logging
from pathlib import Path

from firewatch_sdk import EnforcementPostureLiteral, SourcePlugin

from firewatch_core.adapters.ai_disabled import DisabledAIEngine
from firewatch_core.adapters.ai_openai import OpenAIEngine
from firewatch_core.adapters.geo_enricher import GeoEnricher
from firewatch_core.adapters.sqlite_store import SQLiteEventStore
from firewatch_core.config_store import JsonFileConfigStore
from firewatch_core.pipeline import Pipeline

logger = logging.getLogger("firewatch.cli.pipeline_factory")

# Default data directory for the MMDB files (sibling to the DB file).
# MI-4/#385 will document this path and the air-gapped copy-in workflow.
_MMDB_DIR_NAME = "geo_data"


def _build_pipeline(
    config_file: Path | str | None = None,
    registry: dict[str, SourcePlugin] | None = None,
) -> object:
    """Construct and return a ``Pipeline`` for CLI use.

    - ``SQLiteEventStore`` at ``firewatch_events.db`` next to the config file
      (current directory when ``config_file`` is ``None``).
    - The AI engine is selected from ``RuntimeConfig.ai_enabled`` (resolved via
      the config service, so env vars / config file apply): the real
      ``OpenAIEngine`` when enabled, else a rules-only ``DisabledAIEngine``.
    - Issue #75 (ADR-0067 D6): when *registry* is supplied, every loaded
      plugin's ``SourceMetadata.enforcement`` default is wired into the
      ``Pipeline`` as ``posture_defaults`` so qualified Tier-2 verdicts get an
      honest, posture-specific disposition label instead of the generic
      "block status unknown". *registry* is optional — omitting it (as the
      pre-#75 callers do) yields the pre-#75 pipeline unchanged.

    Returns a plain ``object`` to keep callers decoupled from the concrete
    ``Pipeline`` type.
    """
    # DB path lives next to the config file when one is provided.
    db_dir = Path(config_file).parent if config_file is not None else Path(".")
    db_path = db_dir / "firewatch_events.db"

    runtime = JsonFileConfigStore(config_file=config_file).get_runtime()

    ai_engine: object
    if runtime.ai_enabled:
        try:
            ai_engine = OpenAIEngine(
                base_url=runtime.ollama_base_url,
                model=runtime.ollama_model,
            )
        except Exception as exc:
            # A misconfigured (e.g. non-local, ADR-0022) base_url raises at
            # construction. Fail safe to rules-only rather than crashing the
            # runtime — the deterministic rule+detection score is the floor.
            # Issue #40 AC4: this is a FAULT (AI was wanted), never a choice —
            # fault=True so the stamping authority (ai_status.py) reports
            # ai_status="unavailable", not "disabled".
            logger.error(
                "AI engine construction failed (%s); falling back to rules-only "
                "scoring (ai_status='unavailable'). Check runtime.ollama_base_url.",
                exc,
            )
            ai_engine = DisabledAIEngine(fault=True)
    else:
        logger.info(
            "ai_enabled=false — building a rules-only pipeline "
            "(no inference endpoint will be contacted)."
        )
        ai_engine = DisabledAIEngine()

    store = SQLiteEventStore(db_path=db_path)
    geo_enricher = _build_geo_enricher(store=store, db_dir=db_dir, runtime=runtime)
    # MK-2 (ADR-0044): the verdict ledger uses its own aiosqlite connection to the
    # same DB file (ADR-0023 §F — single loop, one connection per role). Construct it
    # here so it is the SAME instance the pipeline writes to and the read API /
    # attestation strip read from (run.py/serve.py pass ``pipeline.ledger`` to create_app).
    from firewatch_core.adapters.ledger.sqlite_ledger import SqliteAnalysisLedger

    ledger = SqliteAnalysisLedger(db_path=db_path)
    posture_defaults: dict[str, EnforcementPostureLiteral | None] = (
        {type_key: plugin.metadata().enforcement for type_key, plugin in registry.items()}
        if registry
        else {}
    )
    return Pipeline(
        store=store,
        ai_engine=ai_engine,
        enrichers=[geo_enricher],
        ledger=ledger,
        posture_defaults=posture_defaults,
    )


def _build_geo_enricher(
    store: SQLiteEventStore,
    db_dir: Path,
    runtime: object,
) -> object:
    """Select and construct the geo enricher from ``runtime.geo_provider`` (ADR-0039).

    - ``offline`` (default): ``MmdbGeoEnricher`` backed by DB-IP Lite MMDB files
      stored in ``<db_dir>/geo_data/``. First-run download is handled lazily
      inside the enricher on the first ``enrich()`` call.
    - ``online``: ``GeoEnricher`` (ip-api.com). Egress disclosure: the free tier
      uses plaintext HTTP and sends the looked-up IPs to ip-api.com.

    Returns a plain ``object`` to keep callers decoupled from the concrete type.
    """
    import typing

    provider: str = "offline"
    if hasattr(runtime, "geo_provider"):
        provider = str(getattr(runtime, "geo_provider"))

    if provider == "online":
        logger.info(
            "geo_provider=online — using ip-api.com enricher. "
            "EGRESS DISCLOSURE: free tier is plaintext HTTP; IPs are sent to ip-api.com."
        )
        return GeoEnricher(store=store)

    # offline (default)
    from firewatch_core.adapters.geo_mmdb import MmdbGeoEnricher

    mmdb_dir = db_dir / _MMDB_DIR_NAME
    city_db = mmdb_dir / "dbip-city-lite.mmdb"
    asn_db = mmdb_dir / "dbip-asn-lite.mmdb"

    logger.info(
        "geo_provider=offline — using DB-IP Lite MMDB enricher (ADR-0039). "
        "MMDB dir: %s",
        mmdb_dir,
    )
    _ = typing  # suppress unused-import; typing used for runtime hasattr check
    return MmdbGeoEnricher(store=store, city_db_path=city_db, asn_db_path=asn_db)
