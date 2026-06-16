"""Shared pipeline factory for CLI commands.

Builds a ``Pipeline`` backed by the default SQLite store and an AI engine
selected from ``RuntimeConfig`` (ADR-0022 / issue #54):

- ``ai_enabled`` true  → the real ``OpenAIEngine`` (local-first; degrades
  gracefully to ``ai_status="unavailable"`` when the endpoint is unreachable).
- ``ai_enabled`` false → a rules-only ``_DisabledAIEngine`` that reports
  ``ai_status="disabled"`` and never contacts an inference endpoint.

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
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from firewatch_core.adapters.ai_openai import OpenAIEngine
from firewatch_core.adapters.geo_enricher import GeoEnricher
from firewatch_core.adapters.sqlite_store import SQLiteEventStore
from firewatch_core.config_store import JsonFileConfigStore
from firewatch_core.pipeline import Pipeline

logger = logging.getLogger("firewatch.cli.pipeline_factory")

# Default data directory for the MMDB files (sibling to the DB file).
# MI-4/#385 will document this path and the air-gapped copy-in workflow.
_MMDB_DIR_NAME = "geo_data"


class _DisabledAIEngine:
    """Rules-only AI engine used when ``ai_enabled`` is False (ADR-0022, #54).

    Reports ``ai_status="disabled"`` and never contacts an inference endpoint.
    This is distinct from the *unreachable* case: when AI is enabled but the
    endpoint is down, the real ``OpenAIEngine`` reports ``ai_status="unavailable"``.
    Either way the AI contribution is additive-only (ADR-0015) — a non-concrete
    ``threat_level="UNKNOWN"`` so it can never de-escalate the rule+detection score.
    """

    async def is_available(self) -> bool:
        return False

    async def analyze_concise(  # noqa: PLR0913
        self,
        ip: str,
        total_events: int,
        blocked_events: int,
        rules_triggered: int,
        first_seen: str,
        last_seen: str,
        samples: list[dict[str, Any]],
        security_mode: bool = False,
        correlations: list[Any] | None = None,
    ) -> dict[str, Any]:
        return {"ai_status": "disabled", "threat_level": "UNKNOWN"}

    async def analyze_detailed(  # noqa: PLR0913
        self,
        ip: str,
        total_events: int,
        blocked_events: int,
        rules_triggered: int,
        first_seen: str,
        last_seen: str,
        samples: list[dict[str, Any]],
        security_mode: bool = False,
        correlations: list[Any] | None = None,
    ) -> dict[str, Any]:
        return {"ai_status": "disabled", "threat_level": "UNKNOWN"}


def _build_pipeline(config_file: Path | str | None = None) -> object:
    """Construct and return a ``Pipeline`` for CLI use.

    - ``SQLiteEventStore`` at ``firewatch_events.db`` next to the config file
      (current directory when ``config_file`` is ``None``).
    - The AI engine is selected from ``RuntimeConfig.ai_enabled`` (resolved via
      the config service, so env vars / config file apply): the real
      ``OpenAIEngine`` when enabled, else a rules-only ``_DisabledAIEngine``.

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
            logger.error(
                "AI engine construction failed (%s); falling back to rules-only "
                "scoring (ai_status='disabled'). Check runtime.ollama_base_url.",
                exc,
            )
            ai_engine = _DisabledAIEngine()
    else:
        logger.info(
            "ai_enabled=false — building a rules-only pipeline "
            "(no inference endpoint will be contacted)."
        )
        ai_engine = _DisabledAIEngine()

    store = SQLiteEventStore(db_path=db_path)
    geo_enricher = _build_geo_enricher(store=store, db_dir=db_dir, runtime=runtime)
    # MK-2 (ADR-0044): the verdict ledger uses its own aiosqlite connection to the
    # same DB file (ADR-0023 §F — single loop, one connection per role). Construct it
    # here so it is the SAME instance the pipeline writes to and the read API /
    # attestation strip read from (run.py/serve.py pass ``pipeline.ledger`` to create_app).
    from firewatch_core.adapters.ledger.sqlite_ledger import SqliteAnalysisLedger

    ledger = SqliteAnalysisLedger(db_path=db_path)
    return Pipeline(
        store=store, ai_engine=ai_engine, enrichers=[geo_enricher], ledger=ledger
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
