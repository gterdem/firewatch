"""Pipeline — orchestrates collect → store → score → analyze.

The Pipeline is the only place that knows the order of operations. Ported from
``legacy/core/pipeline.py`` (ingest + analyze_ip) with the ECS rename
``source_module`` → ``source_type`` (ADR-0016). ``run_pull_cycle`` is net-new: it drives one
watermark-bounded pull for a single source instance.

Error-handling policy:
  - A failed AI analysis returns a rules-only score, never aborts (ADR-0003 fail-safe).
  - Storage failures ARE fatal — if events can't be stored, propagate.
  - Enricher failures are caught per-enricher, logged at WARNING, and never abort
    the cycle (ADR-0003 fail-safe — issue #150).
Each stage is timed with ``time.monotonic()`` and logged at INFO.

Issue #132 additions:
  - ``_format_location()`` — build a city/country string from a geo row; guard
    non-public IPs (RFC 1918 / loopback / link-local) so they never expose a
    location derived from a public-geo API call that should never have been made.
  - ``analyze_ip`` — resolves ``ThreatScore.location`` from the ip_geo cache.
  - ``analyze_ip_detailed`` — adds ``detections`` (recent raw rows, capped at
    _MAX_DETECTIONS) and ``location`` to the result dict.

Issue #150 additions:
  - ``enrichers`` parameter on ``__init__`` — a list of ``Enricher`` instances
    called after every successful ingest in ``run_pull_cycle``.  Wires
    ``GeoEnricher`` into the live collect path so collected public IPs get
    geo-resolved and persisted to ``ip_geo``.
  - Rule-description promotion in ``run_pull_cycle`` — after ingest, reads the
    plugin's source_kv ``rule_descriptions`` namespace and upserts into the
    global ``rule_descriptions`` table so ``GET /rules`` returns non-empty data.

Issue #209 additions:
  - ``build_score_breakdown`` is called alongside ``merge_score`` in both
    ``analyze_ip`` and ``analyze_ip_detailed`` to populate ``score_breakdown``
    (ADR-0036 D4).  The breakdown is an additive field; no scores change.

Issue #250 additions:
  - ``_record_score_snapshot()`` — writes a timestamped snapshot to the
    ``score_history`` table after ``analyze_ip`` computes a score.  This is an
    *observation* of the scoring output and never influences scoring inputs.
    Fail-safe: store errors are caught and logged at WARNING (ADR-0003).
  - ``analyze_ip`` — reads back ``score_delta`` (signed change over the default
    1h window) and populates ``ThreatScore.score_delta`` (additive field; None
    for new actors with no prior snapshot).
  - The ``list_threats`` route uses ``store.get_bulk_score_deltas`` (one
    aggregate query for all IPs) rather than calling ``analyze_ip`` per IP,
    satisfying EARS E4 (no per-IP N+1 on the list endpoint).

Issue #52 additions (ADR-0070 D4 — trailing analysis windows):
  - ``analyze_ip`` / ``analyze_ip_detailed`` fetch each actor's FULL lifetime event
    list once (unchanged — ``first_seen``/``last_seen``/``total_events``/
    ``blocked_events`` keep lifetime semantics), then slice it in-process into two
    trailing windows at the fetch/slice seam: ``W_STATE`` (24h, feeds
    ``run_rules``/``build_score_breakdown``/``decide()``) and ``W_CAMPAIGN`` (7d,
    feeds ``detect()``).  This closes the lifetime-persistence defect — an actor
    blocked ten times over six months no longer permanently scores
    ``brute_force``/Tier-3.  ``run_rules``/``detect``/``decide`` gain NO
    time-filtering logic of their own: the golden tests call them directly on
    in-memory lists, so windowing anywhere but the pipeline seam would move the
    oracle (ADR-0070 D4).  ``Pipeline.__init__`` takes an optional ``clock``
    callable (default: the real wall clock) so tests can pin "now" deterministically.

MK-2 additions (ADR-0044):
  - ``ledger`` optional parameter on ``__init__`` — an ``AnalysisLedger``-protocol
    object (``SqliteAnalysisLedger`` in production; None for tests that don't need it).
  - ``_record_analysis()`` — fail-safe hook called AFTER ``merge_score`` from both
    ``analyze_ip`` and ``analyze_ip_detailed`` when the AI produced a validated result
    (ai_status != "unavailable").  Fallback envelopes are never persisted (ADR-0044 §3).
  - Uses ``analyze_concise_with_meta`` / ``analyze_detailed_with_meta`` on the engine
    when available (i.e. when the concrete ``OpenAIEngine`` is wired) to capture prompt
    text, response text, latency, and token usage for the ledger row.  The standard
    AIEngine port methods are used as the fallback when meta methods are absent.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import time
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol
from urllib.parse import urlparse

from pydantic import BaseModel

from firewatch_sdk import (
    AIEngine,
    EventStore,
    Notifier,
    PluginContext,
    PullSource,
    ScoreBreakdownItem,
    SecurityEvent,
    SourcePlugin,
    ThreatScore,
)

from firewatch_core.sync_state import persist_sync_state
from firewatch_core.ai.stage_events import (
    FailReason,
    FailedFact,
    GeneratingFact,
    ProjectedFact,
    PromptBuiltFact,
    ReceivedFact,
    RequestSentFact,
    StageName,
    StageEmitter,
    ValidatedFact,
)
from firewatch_core.detector import detect
from firewatch_core.escalation.decider import decide as _decide_escalation
from firewatch_core.ports.analysis_ledger import AnalysisLedger, AnalysisRecord
from firewatch_core.scoring import (
    MAX_DETAILED_EVENTS,
    build_detailed_samples,
    build_samples,
    build_score_breakdown,
    merge_score,
    run_rules,
)

logger = logging.getLogger("firewatch.pipeline")

# Maximum recent-log rows returned in analyze_ip_detailed's detections[] array.
# Keeps the HTTP response payload reasonable while covering the "Recent Logs"
# table that the UI renders (which shows at most 8 rows — issue #132 DC-1).
_MAX_DETECTIONS = 50

# Heartbeat interval for the generating stage (ADR-0046 D4).
# Emitted every N seconds while Ollama is generating.
_GENERATING_HEARTBEAT_INTERVAL_S = 2.0

# ── Trailing analysis windows (issue #52, ADR-0070 D4 — Revision 1 meaning) ──
#
# W_STATE / W_CAMPAIGN are PROVISIONAL engineering estimates (ADR-0070 D5) —
# NOT settled/calibrated values. The #50 volume-oracle manifest is the ledger
# of record for these numbers, not this module. Code-declared only — NOT
# operator-tunable (ADR-0070 D6). Documented in docs/escalation-and-triage-model.md.
#
# W_STATE  feeds run_rules / build_score_breakdown / decide() — "what is this
#          actor's CURRENT threat state?" (score, band, tier reflect the
#          trailing day, not the actor's lifetime). Revision 1 (issue #53):
#          also the window R1 `attempt_pressure` (detector.py) peak-checks its
#          decayed attempt intensity against — duplicated there as
#          `detector._PRESSURE_WINDOW` (not imported, to avoid a
#          detector<->pipeline circular import) and pinned equal by a
#          dedicated cross-file test.
# W_CAMPAIGN feeds detect() — the correlation rules' own fetch horizon
#          (`ids_then_brute_force`, `brute_force_then_login`,
#          `multi_source_attack`, `ssh_login_failure_intense`, R1
#          `attempt_pressure`). Revision 1 (ADR-0070): this is also the
#          episode-counting memory the future R2/R3 campaign rules (#54) will
#          use for recidivism — "is this actor WAGING A CAMPAIGN?", a longer
#          memory than the state window's "current state" question. λ̂ itself
#          needs no horizon (an event this old has already decayed to ~0 at
#          H=30min); the horizon exists so recidivism has bounded, declared
#          memory (ADR-0070 D4).
#
# H (the intensity half-life) and θ_press (the R1 firing threshold) are
# code-declared in `firewatch_core.attempts` (ADR-0070 D5) — not here, since
# `detector.py`/`attempts.py` cannot import this module (pipeline.py imports
# `detect` from detector.py at module load time; the reverse import would be
# circular). See `attempts.py`'s own named-constants block.
#
# The window is applied HERE, at the pipeline fetch/slice seam, and ONLY here:
# run_rules/detect/decide stay pure functions with NO time-filtering logic of
# their own — they never drop an event from consideration based on `now`.
# tests/golden calls them directly on in-memory lists — windowing inside those
# functions would move the golden oracle (ADR-0070 D4). R1's peak-intensity
# check (issue #53) is not an exception to this: every attempt still
# contributes to the decayed sum regardless of age (nothing is filtered out of
# the input list); `now`/window only bound which time(s) the *maximum* is
# evaluated over — the pipeline's `now` anchor is passed through to `detect()`
# exactly as it already is to `run_rules`/`decide()` via the windowed slices.
W_STATE = timedelta(hours=24)
W_CAMPAIGN = timedelta(days=7)


class PullPlugin(SourcePlugin, PullSource, Protocol):
    """A pull-flavored source plugin: the common ``SourcePlugin`` surface plus
    ``PullSource.collect``. (Python has no intersection type, so the loader's pull
    instances are described by this combined Protocol for ``run_pull_cycle``.)"""


def _ms_since(start: float) -> float:
    """Milliseconds elapsed since a ``time.monotonic()`` start point."""
    return round((time.monotonic() - start) * 1000, 2)


def _window_slice(
    events: list[SecurityEvent], now: datetime, window: timedelta
) -> list[SecurityEvent]:
    """Return the subset of *events* at or after ``now - window`` (ADR-0070 D4).

    Pure, in-process slice — the ONLY place the trailing analysis windows are
    applied. Naive timestamps (should not occur in production; see
    ``adapters/sqlite/_base.py::_row_to_security_event``) are treated as UTC so
    a mixed naive/aware comparison never raises.
    """
    cutoff = now - window
    return [
        e for e in events
        if (e.timestamp if e.timestamp.tzinfo is not None else e.timestamp.replace(tzinfo=timezone.utc))
        >= cutoff
    ]


def _is_public_ip(ip_str: str) -> bool:
    """Return True only for globally-routable, non-multicast IPv4/IPv6 addresses.

    Non-public addresses (RFC 1918, loopback, link-local, ULA, unspecified,
    multicast) must NOT be sent to a public geo API, and their location must
    not be surfaced in the UI — there is no meaningful geo for them.

    Mirrors the guard in ``adapters/geo_enricher.py::_is_non_public`` (kept
    separate so pipeline.py does not import a concrete adapter).
    """
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_global and not addr.is_multicast
    except ValueError:
        return False


def _format_location(geo_row: dict[str, Any] | None) -> str | None:
    """Build a human-readable location string from a geo cache row.

    Returns ``"<city>, <country>"`` when both are non-empty, ``"<country>"``
    or ``"<city>"`` when only one is present, and ``None`` when the row is
    absent or both fields are empty strings.
    """
    if geo_row is None:
        return None
    city = str(geo_row.get("city") or "").strip()
    country = str(geo_row.get("country") or "").strip()
    if city and country:
        return f"{city}, {country}"
    return city or country or None


def _endpoint_host_from_engine(engine: AIEngine) -> str:
    """Extract host:port from the engine's base_url (ADR-0044 §Security).

    Returns only the host:port component — never credentials, scheme, or path.
    Falls back to "unknown" when the engine has no ``base_url`` attribute.
    """
    raw_url: str = getattr(engine, "base_url", "") or ""
    if not raw_url:
        return "unknown"
    try:
        parsed = urlparse(raw_url)
        host = parsed.hostname or "unknown"
        port = parsed.port
        return f"{host}:{port}" if port else host
    except Exception:
        return "unknown"


class Pipeline:
    """Orchestrates the FireWatch data flow."""

    def __init__(
        self,
        store: EventStore,
        ai_engine: AIEngine,
        notifier: Notifier | None = None,
        enrichers: list[Any] | None = None,
        ledger: AnalysisLedger | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Create the pipeline.

        Parameters
        ----------
        store:
            The EventStore for persisting and querying events.
        ai_engine:
            The AI engine for threat analysis.
        notifier:
            Optional notifier for threshold-gated alert dispatch.
        enrichers:
            Optional list of ``Enricher``-protocol objects (e.g. ``GeoEnricher``)
            called after every successful ingest in ``run_pull_cycle`` (issue #150).
            Each enricher is called with the ingested events; failures are caught
            per-enricher and logged at WARNING (ADR-0003 fail-safe).
        ledger:
            Optional ``AnalysisLedger`` for persisting validated AI analyses
            (MK-2, ADR-0044).  When None, ledger writes are silently skipped —
            the analysis path is unaffected (additive-only, no-op when absent).
        clock:
            Optional zero-arg callable returning the current ``datetime`` (issue
            #52, ADR-0070 D4) — the "now" the trailing ``W_STATE``/``W_CAMPAIGN``
            analysis windows are measured from.  Defaults to the real wall clock
            (``datetime.now(timezone.utc)``).  Tests inject a fixed instant so
            windowing assertions are deterministic (no wall-clock flakiness).
        """
        self.store = store
        self.ai_engine = ai_engine
        self.notifier = notifier
        self.enrichers: list[Any] = list(enrichers) if enrichers else []
        self.ledger = ledger
        self._clock: Callable[[], datetime] = clock or (lambda: datetime.now(timezone.utc))

    # ── Ingest ────────────────────────────────────────────────────

    async def ingest(self, events: list[SecurityEvent]) -> int:
        """Persist events. Returns the number of newly inserted rows.

        Storage failures are fatal — exceptions propagate up to the caller. Do not wrap
        this in try/except.
        """
        t_start = time.monotonic()
        count = await self.store.save_many(events)
        logger.info(
            "pipeline.ingest events=%d inserted=%d save=%sms",
            len(events), count, _ms_since(t_start),
        )
        return count

    # ── Collect (watermark-bounded pull) ──────────────────────────

    async def run_pull_cycle(
        self, plugin: PullPlugin, cfg: BaseModel, source_id: str, ctx: PluginContext
    ) -> int:
        """Run one watermark-bounded pull for a single source instance.

        Reads the watermark for the composite ``(source_type, source_id)`` key
        (ADR-0007/0016), collects raw events since it, normalizes each via the plugin, and
        ingests them. Advances the watermark to the newest raw seen. Returns the number of
        rows inserted.

        ``ctx`` is the per-instance capability carrier (ADR-0027), minted by the
        caller (supervisor for scheduled pulls; a single-shot/CLI caller mints its own
        via ``scoped_kv(store, plugin.metadata().type_key)``).  This method is a
        pass-through conduit on the pull path — it does NOT mint ``ctx`` (ADR-0027
        §3: one minter pattern; the pipeline does not own the trust boundary).
        """
        source_type = plugin.metadata().type_key
        since = await self.store.get_watermark(source_type, source_id)

        events: list[SecurityEvent] = []
        latest: datetime | None = None
        async for raw in plugin.collect(cfg, since, ctx):
            events.append(plugin.normalize(raw, source_id))
            if latest is None or raw.received_at > latest:
                latest = raw.received_at

        inserted = await self.ingest(events)

        if latest is not None:
            await self.store.set_watermark(latest.isoformat(), source_type, source_id)

        # Post-ingest enrichment and rule-description promotion (issue #150).
        # Only run when events were actually collected this cycle — skip on empty
        # cycles to avoid unnecessary store reads and API calls.
        if events:
            await self._run_enrichers(events)
            await self._promote_rule_descriptions(source_type)

        # Issue #707: persist last-sync stamp to the durable KV store so that
        # any caller (supervisor loop, manual sync, cmd_sync_once, or any future
        # background path) records the stamp even across process restarts.
        # Fail-safe: a KV write error must never abort an ingest cycle (ADR-0003).
        import time as _time
        _status = "ok" if inserted > 0 else "no_data"
        await persist_sync_state(
            store=self.store,
            source_type=source_type,
            source_id=source_id,
            ts=_time.time(),
            ingested=inserted,
            status=_status,
            last_error=None,
        )

        logger.info(
            "pipeline.run_pull_cycle source=%s/%s collected=%d inserted=%d watermark=%s",
            source_type, source_id, len(events), inserted,
            latest.isoformat() if latest else since,
        )
        return inserted

    # ── Startup backfill (issue #637) ────────────────────────────────

    async def startup_backfill(self) -> None:
        """Backfill geo for historical IPs on startup (issue #637).

        Calls ``backfill_geo()`` on each enricher that exposes it — decoupled
        from the hot pull cycle so IPs ingested before geo was working (or before
        the MMDB files were present) are resolved on the next process start.

        Design notes:
        - Called ONCE from cmd_run after supervisor.startup() (startup concern,
          not the hot path).
        - Enrichers that do not expose ``backfill_geo`` are silently skipped
          (backward-compatible: a new enricher type that doesn't implement
          backfill is not broken by this call).
        - Fail-safe (ADR-0003): an enricher's backfill_geo() exception is caught,
          logged at WARNING, and the next enricher still runs.  Never raises.
        """
        for enricher in self.enrichers:
            backfill_fn = getattr(enricher, "backfill_geo", None)
            if backfill_fn is None:
                continue
            try:
                await backfill_fn()
            except Exception:
                logger.warning(
                    "pipeline.startup_backfill: enricher %r raised during backfill — skipping",
                    getattr(enricher, "name", repr(enricher)),
                    exc_info=True,
                )
        logger.info(
            "pipeline.startup_backfill: backfill pass complete for %d enricher(s)",
            len(self.enrichers),
        )

    # ── Post-ingest helpers ───────────────────────────────────────────

    async def _run_enrichers(self, events: list[SecurityEvent]) -> None:
        """Call each configured enricher in order (issue #150).

        Fail-safe (ADR-0003): an enricher exception is caught, logged at WARNING,
        and the next enricher still runs.  Never raises to the caller.
        """
        for enricher in self.enrichers:
            try:
                await enricher.enrich(events)
            except Exception:
                logger.warning(
                    "pipeline._run_enrichers: enricher %r raised — skipping",
                    getattr(enricher, "name", repr(enricher)),
                    exc_info=True,
                )

    async def _promote_rule_descriptions(self, source_type: str) -> None:
        """Promote plugin-written rule descriptions from source_kv to the global table.

        After each pull cycle the pipeline reads
        ``source_kv(source_type, "rule_descriptions")`` — the namespace the
        plugin is expected to write its SID→msg catalog into via ``ctx.kv`` —
        and upserts the entries into the global ``rule_descriptions`` table
        (``source_type='_global'``) so ``GET /rules`` returns non-empty data.

        This is source-agnostic: any plugin that writes to
        ``ctx.kv.put("rule_descriptions", sid, msg)`` will have its catalog
        automatically promoted.  Fail-safe: any store error is caught and logged
        at WARNING; never raises (ADR-0003).
        """
        try:
            descs = await self.store.source_kv_get_all(source_type, "rule_descriptions")
            if descs:
                await self.store.upsert_rule_descriptions(descs)
                logger.debug(
                    "pipeline._promote_rule_descriptions: promoted %d rule desc(s) from %s",
                    len(descs), source_type,
                )
        except Exception:
            logger.warning(
                "pipeline._promote_rule_descriptions: failed for source_type=%s",
                source_type,
                exc_info=True,
            )

    # ── Score history helpers (issue #250) ───────────────────────

    async def _record_score_snapshot(self, ip: str, score: int) -> None:
        """Record a timestamped snapshot of *score* for *ip* (issue #250).

        Called AFTER ``analyze_ip`` computes and returns a score — this is an
        observation of the scoring output and NEVER an input to scoring.  Calling
        order is enforced by the call site (after ``merge_score``).

        Fail-safe (ADR-0003): store errors are caught and logged at WARNING; the
        score is still returned to the caller even if the snapshot cannot be
        persisted.  A missing snapshot only means ``score_delta`` will be ``None``
        on the next /threats call for this IP — not a correctness failure.

        The store's ``record_score_snapshot`` piggybacks pruning inline, so no
        separate retention scheduler is needed (issue #250 "Retention" criterion).
        """
        try:
            record_fn = getattr(self.store, "record_score_snapshot", None)
            if record_fn is not None:
                await record_fn(ip, score, datetime.now(timezone.utc))
        except Exception:
            logger.warning(
                "pipeline._record_score_snapshot: failed for ip=%s score=%d",
                ip, score, exc_info=True,
            )

    async def _get_score_delta(self, ip: str, score: int) -> int | None:
        """Return the signed score delta for *ip* over the default window.

        Reads ``get_bulk_score_deltas`` for a single IP.  Returns ``None`` when
        no prior snapshot exists in the window (new actor semantics).

        Fail-safe: store errors or missing method return ``None`` (additive-only
        — a missing delta is surfaced as a null new-actor, not an error).
        """
        try:
            bulk_fn = getattr(self.store, "get_bulk_score_deltas", None)
            if bulk_fn is None:
                return None
            deltas = await bulk_fn(
                ips=[ip],
                current_scores={ip: score},
                window_hours=1,
            )
            return deltas.get(ip)  # int | None
        except Exception:
            logger.debug(
                "pipeline._get_score_delta: failed for ip=%s — returning None",
                ip, exc_info=True,
            )
            return None

    # ── Analysis ledger helper (MK-2, ADR-0044) ──────────────────

    async def _record_analysis(
        self,
        *,
        ip: str,
        kind: str,
        ai_result: dict[str, Any],
        score: int,
        score_derivation: str,
        meta: Any | None,
    ) -> None:
        """Persist one validated AI analysis to the ledger (MK-2, ADR-0044).

        Called AFTER ``merge_score`` — never alters scoring.  The ledger write
        is fail-safe: any exception is caught and logged at WARNING; the analysis
        result is returned to the caller unchanged (ADR-0003 / ADR-0044 §3).

        Parameters
        ----------
        ip:               Source IP that was analysed.
        kind:             ``"concise"`` or ``"detailed"``.
        ai_result:        The validated+projected dict from the AI engine.
        score:            Merged score computed by ``merge_score``.
        score_derivation: Provenance string from ``merge_score``.
        meta:             ``AnalysisCallMeta`` from ``OpenAIEngine.*_with_meta``,
                          or None when the concrete engine does not expose metadata
                          (e.g. ``FakeAIEngine`` in tests, third-party adapters).
                          When None, prompt/response/usage fields are recorded as
                          empty/null — the row still captures the outcome.
        """
        if self.ledger is None:
            return

        # Skip fallback envelopes — only persist validated analyses (ADR-0044 §3).
        if ai_result.get("ai_status") == "unavailable":
            return

        try:
            # Extract metadata from AnalysisCallMeta when available.
            if meta is not None:
                prompt_text: str = getattr(meta, "prompt_text", "")
                response_text: str = getattr(meta, "response_text", "")
                latency_ms: float = float(getattr(meta, "latency_ms", 0.0))
                prompt_tokens: int | None = getattr(meta, "prompt_tokens", None)
                completion_tokens: int | None = getattr(meta, "completion_tokens", None)
            else:
                prompt_text = ""
                response_text = ""
                latency_ms = 0.0
                prompt_tokens = None
                completion_tokens = None

            model_name: str = getattr(self.ai_engine, "model", "unknown")
            endpoint_host = _endpoint_host_from_engine(self.ai_engine)

            record = AnalysisRecord(
                ip=ip,
                kind=kind,  # type: ignore[arg-type]
                model=model_name,
                endpoint_host=endpoint_host,
                prompt_text=prompt_text,
                response_text=response_text,
                validated_json=ai_result,
                ai_status=str(ai_result.get("ai_status", "ok")),
                threat_level=str(ai_result.get("threat_level", "UNKNOWN")),
                confidence=float(ai_result.get("confidence", 0.0)),
                score=score,
                score_derivation=score_derivation,
                latency_ms=latency_ms,
                prompt_tokens=prompt_tokens,
                completion_tokens=completion_tokens,
                created_at=datetime.now(timezone.utc),
            )
            await self.ledger.save(record)
        except Exception:
            logger.warning(
                "pipeline._record_analysis: ledger write failed for ip=%s kind=%s",
                ip, kind, exc_info=True,
            )

    # ── Geo helper ───────────────────────────────────────────────

    async def _resolve_geo(
        self, ip: str
    ) -> tuple[str | None, int | None, str | None]:
        """Resolve geo fields for *ip* from the ip_geo cache in a single lookup.

        Returns a 3-tuple ``(location, asn, as_name)`` where:
        - ``location`` is the human-readable city/country string (or ``None``).
        - ``asn``      is the integer AS number (or ``None``).
        - ``as_name``  is the AS operator name string (or ``None``).

        All three fields are ``None`` when:
        - The IP is not publicly routable (RFC 1918, loopback, etc.).
        - No geo row exists in the ip_geo cache.
        - The store does not implement ``get_ip_geo`` (graceful degradation).
        - The provider did not return ASN data for this IP.

        Issue #211: ASN fields added additively alongside the existing location.
        Fail-safe: any store error is caught and logged; returns (None, None, None).
        """
        if not _is_public_ip(ip):
            return None, None, None
        try:
            geo_row = await self.store.get_ip_geo(ip)
            if geo_row is None:
                return None, None, None
            location = _format_location(geo_row)
            asn: int | None = geo_row.get("asn")
            as_name: str | None = geo_row.get("as_name")
            return location, asn, as_name
        except Exception:
            logger.debug("pipeline._resolve_geo: geo lookup failed for ip=%s", ip)
            return None, None, None

    # ── Analyze ───────────────────────────────────────────────────

    async def analyze_ip(self, ip: str, *, use_ai: bool = True) -> ThreatScore:
        """Compute a ThreatScore for an IP. Mirrors the v1 analyzer.analyze_ip.

        Issues exactly ONE AI sample call per IP (ADR-0003).

        Issue #132: resolves ``ThreatScore.location`` from the ip_geo cache for
        globally-routable IPs.  Non-public IPs (RFC 1918 / loopback / etc.) always
        receive ``location=None``.

        Issue #209: populates ``ThreatScore.score_breakdown`` — additive field,
        no score values change (ADR-0036 D4).

        Issue #52 (ADR-0070 D4): ``run_rules``, ``build_score_breakdown``, and
        ``decide()`` see only the trailing ``W_STATE`` (24h) slice of events;
        ``detect()`` sees only the trailing ``W_CAMPAIGN`` (7d) slice.
        ``first_seen``/``last_seen``/``total_events``/``blocked_events`` are
        computed from the FULL lifetime event list and keep their existing
        meaning — only the counting rules are windowed.

        MK-2: after ``merge_score``, records the analysis to the ledger (fail-safe).
        """
        t_total = time.monotonic()

        t_fetch_start = time.monotonic()
        events = await self.store.get_by_ip(ip)  # lifetime fetch — ONE fetch (ADR-0070 D4)
        t_fetch = _ms_since(t_fetch_start)

        if not events:
            logger.info(
                "pipeline.analyze_ip ip=%s fetch=%sms (empty)", ip, t_fetch,
            )
            return ThreatScore(
                source_ip=ip,
                threat_level="LOW",
                score=0,
                total_events=0,
                blocked_events=0,
                attack_types=[],
                first_seen=datetime.now(),
                last_seen=datetime.now(),
            )

        # Lifetime facts (issue #52: unchanged semantics) — computed from the FULL
        # event list, never the windowed views below.
        blocked = [e for e in events if e.action in ("BLOCK", "DROP")]
        timestamps = [e.timestamp for e in events]

        # Issue #52 (ADR-0070 D4): slice the lifetime fetch into the two named
        # trailing windows at THIS seam only — run_rules/detect/decide stay
        # windowing-agnostic (the golden-oracle constraint).
        now = self._clock()
        state_events = _window_slice(events, now, W_STATE)
        campaign_events = _window_slice(events, now, W_CAMPAIGN)

        t_score_start = time.monotonic()
        rule_score, attack_types = run_rules(state_events)
        # Cross-source correlation. Pure functions, fast. `now` anchors R1
        # attempt_pressure's peak-intensity check (ADR-0070 Revision 1, issue #53).
        detections = detect(campaign_events, now=now)
        detection_boost = sum(d.score_delta for d in detections)
        t_score = _ms_since(t_score_start)

        # Switch to "security log" prompt wording when any non-Azure source contributed
        # events for this IP. Pure-Azure IPs keep the legacy WAF prompt → byte-parity.
        sources_seen = {e.source_type for e in events}
        security_mode = bool(sources_seen - {"azure_waf"})

        ai_result: dict[str, Any] | None = None
        ai_meta: Any | None = None
        ai_insights: list[str] = []
        ai_confidence = 0.0
        ai_status = "disabled"
        t_ai = 0.0

        if use_ai:
            samples = build_samples(events)
            if samples:
                t_ai_start = time.monotonic()
                try:
                    # MK-2: prefer *_with_meta when the concrete engine exposes it
                    # (OpenAIEngine) so we capture prompt/response/usage for the ledger.
                    # Fall back to the standard AIEngine port method for other engines.
                    with_meta_fn = getattr(self.ai_engine, "analyze_concise_with_meta", None)
                    if with_meta_fn is not None:
                        _result_pair: tuple[dict[str, Any], Any] = await with_meta_fn(
                            ip=ip,
                            total_events=len(events),
                            blocked_events=len(blocked),
                            rules_triggered=len(samples),
                            first_seen=str(min(timestamps)),
                            last_seen=str(max(timestamps)),
                            samples=samples,
                            security_mode=security_mode,
                            correlations=detections or None,
                        )
                        ai_result, ai_meta = _result_pair
                    else:
                        ai_result = await self.ai_engine.analyze_concise(
                            ip=ip,
                            total_events=len(events),
                            blocked_events=len(blocked),
                            rules_triggered=len(samples),
                            first_seen=str(min(timestamps)),
                            last_seen=str(max(timestamps)),
                            samples=samples,
                            security_mode=security_mode,
                            correlations=detections or None,
                        )

                    ai_confidence = float(ai_result.get("confidence", 0.0))
                    ai_insights = list(ai_result.get("insights", []))
                    ai_status = "active"

                    intent = ai_result.get("intent", "")
                    if intent:
                        ai_insights.insert(0, f"Intent: {intent}")
                    rec = ai_result.get("recommended_action", "")
                    if rec:
                        ai_insights.append(f"Recommended action: {rec}")
                except Exception:
                    # AI failure → rules-only score, never abort.
                    logger.warning("AI analysis failed for %s, rules only", ip)
                    ai_status = "unavailable"
                t_ai = _ms_since(t_ai_start)
            else:
                ai_status = "active"

        score, level, score_derivation = merge_score(
            rule_score, ai_result, detection_boost=detection_boost
        )

        # Issue #209: compute breakdown alongside score (same inputs, additive only).
        # Issue #52: windowed to W_STATE, same as run_rules (ADR-0070 D4).
        score_breakdown: list[ScoreBreakdownItem] = build_score_breakdown(
            state_events, ai_result, detection_boost=detection_boost
        )

        # Issue #648 — ADR-0058 D2: deterministic escalation verdict (fail-safe).
        # A bug in the decider must never abort scoring; escalation is additive.
        # Issue #52: windowed to W_STATE — the verdict reflects the actor's current
        # state, not a lifetime tally (ADR-0070 D4).
        escalation_verdict = None
        try:
            escalation_verdict = _decide_escalation(state_events, detections)
        except Exception:
            logger.warning(
                "pipeline.analyze_ip ip=%s escalation decider failed (fail-safe)",
                ip,
                exc_info=True,
            )

        # Resolve geo fields — issue #132 DC-2 (location) + issue #211 (asn/as_name).
        # NB-4 (security): location, as_name, and city are attacker-influenced data
        # (they derive from the attacker's own IP registration).  They MUST NOT be
        # interpolated into AI prompts without <untrusted_data> sentinel wrapping.
        # format_concise / format_detailed callers: audit any prompt that includes
        # these fields and ensure the sentinel is present.
        location, asn, as_name = await self._resolve_geo(ip)

        # Issue #250: read the signed delta BEFORE recording the new snapshot so
        # that "earliest snapshot in window" means a genuinely prior observation.
        # Recording AFTER ensures the current score feeds future delta reads.
        # Both calls are fail-safe: a store error yields score_delta=None rather
        # than aborting the response (ADR-0003).
        score_delta = await self._get_score_delta(ip, score)
        await self._record_score_snapshot(ip, score)

        # MK-2: persist the validated analysis to the ledger (fail-safe, ADR-0044).
        # Called AFTER merge_score — cannot influence the score.
        if ai_result is not None:
            await self._record_analysis(
                ip=ip,
                kind="concise",
                ai_result=ai_result,
                score=score,
                score_derivation=score_derivation,
                meta=ai_meta,
            )

        logger.info(
            "pipeline.analyze_ip ip=%s events=%d state_events=%d campaign_events=%d "
            "fetch=%sms score=%sms ai=%sms total=%sms level=%s detections=%d derivation=%s",
            ip, len(events), len(state_events), len(campaign_events),
            t_fetch, t_score, t_ai, _ms_since(t_total),
            level, len(detections), score_derivation,
        )

        return ThreatScore(
            source_ip=ip,
            threat_level=level,  # type: ignore[arg-type]
            score=score,
            total_events=len(events),
            blocked_events=len(blocked),
            attack_types=attack_types,
            first_seen=min(timestamps),
            last_seen=max(timestamps),
            source_types=sorted(sources_seen),
            detections=detections,
            ai_insights=ai_insights,
            ai_confidence=round(ai_confidence, 3),
            ai_status=ai_status,  # type: ignore[arg-type]
            location=location,
            score_derivation=score_derivation,  # type: ignore[arg-type]
            score_breakdown=score_breakdown,
            asn=asn,
            as_name=as_name,
            score_delta=score_delta,
            escalation=escalation_verdict,
        )

    # ── Background analyze + alert ───────────────────────────────

    async def background_analyze_and_alert(self, ip: str) -> None:
        """Score an IP and threshold-alert — designed to run off the request path.

        Composed from ``analyze_ip`` (one AI call per IP, ADR-0003) and
        ``notifier.check_and_alert`` (threshold-gated delivery). This method is the
        post-ingest hook fired after a pushed event persists.

        Isolation contract (EARS W-faults):
        - Any exception (AI failure, notifier failure, store read error) is caught,
          logged at ERROR with the IP for correlation, and swallowed. The caller (a
          FastAPI BackgroundTask or async wrapper) must never see this raise — if it
          did it would crash the background task and could surface to the API process.
        - AI offline: ``analyze_ip`` already degrades to rules-only (ADR-0003 fail-safe);
          this method proceeds to ``check_and_alert`` with the degraded score.
        - No notifier: skip the alert step gracefully (Pipeline may have notifier=None).
        """
        try:
            threat = await self.analyze_ip(ip)
            if self.notifier is not None:
                await self.notifier.check_and_alert(threat)
        except Exception:
            logger.exception(
                "pipeline.background_analyze_and_alert failed for ip=%s — "
                "ingest is unaffected; background analysis will retry on next event",
                ip,
            )

    async def analyze_ip_detailed(
        self,
        ip: str,
        *,
        include_ai: bool = True,
        stage_sink: StageEmitter | None = None,
    ) -> dict[str, Any]:
        """Run the deep-analysis path for an IP, returning an augmented result dict.

        Ported from ``legacy/app/analyzer.py:236-286`` (REFERENCE-ONLY).

        Issues exactly ONE ``ai_engine.analyze_detailed`` call per IP (ADR-0003)
        when ``include_ai=True`` AND the engine reports itself available.
        Uses ``build_detailed_samples`` (all rules, 300-char payloads, per-rule
        timestamps + descriptions from ``store.get_rule_descriptions()``) ONLY when
        the AI call will actually be made — skipped otherwise (issue #102).
        ``build_detailed_samples`` is dispatched via ``asyncio.to_thread`` so the
        CPU-bound Python iteration over up to MAX_DETAILED_EVENTS events never holds
        the single event loop (ADR-0023 §F).
        Merges via the SAME additive-only threshold logic as ``analyze_ip``:
        CRITICAL+conf>0.7 → +20, HIGH+conf>0.7 → +10, cap 100.

        Parameters
        ----------
        ip:
            The IP address to analyze.
        include_ai:
            When False, skip the AI engine entirely and return rule-only analysis
            with ``ai_status='skipped'``.  The server NEVER claims AI success when
            the engine was not called (ADR-0035 honesty rule, issue #268).
            Default: True (full deep-analysis path).
        stage_sink:
            Optional ``StageEmitter`` for MK-10 SSE stage-ticker (ADR-0046).
            When provided, validated stage-fact dicts are emitted at each gauntlet
            checkpoint.  ``None`` (default) → no-op; the non-streaming path pays
            only a ``None`` check per emit point.
            Security: only closed-enum stage facts are emitted — never raw model
            text, exception messages, or attacker-sourced data (ADR-0046 D3).

        Return shape (v1 parity — ``legacy/app/analyzer.py:280-286``):
        The AI result dict is augmented with: ``score``, ``threat_level``,
        ``total_events``, ``blocked_events``, ``attack_types``, ``source_ip``.

        Issue #132 additions:
        - ``detections`` — list of raw log dicts (up to ``_MAX_DETECTIONS`` most
          recent rows from ``store.get_by_ip_raw``). Powers the "Recent Logs" table
          in the IP drill-down modal.
        - ``location`` — geo string from the ip_geo cache (None when absent or
          IP is non-public).

        Issue #209 additions:
        - ``score_breakdown`` — list of ``{factor, label, points}`` dicts whose
          points sum to ``score`` (ADR-0036 D4, additive field).

        Issue #268 additions:
        - ``include_ai=False`` fast path — caller (e.g. client that consulted
          GET /health and saw the engine offline) skips the 15s AI wait.
          Result carries ``ai_status='skipped'`` — server honesty (ADR-0035).

        NB-3 (AIEngine fallback contract):
        The caller branches on ``ai_status`` BEFORE any schema validation.
        A fallback envelope (``ai_status == "unavailable"``, ``threat_level == "UNKNOWN"``)
        is outside the closed schema — it signals "no AI contribution" and the result
        receives the rules-only score.  The fallback must NEVER be schema-validated.

        Error handling:
        - Empty IP (no events) → ``{"error": "No logs found"}`` without calling AI.
        - AI call exception → rules-only result, never raises.

        MK-2: after ``merge_score``, records the analysis to the ledger (fail-safe).
        MK-10: emits stage facts through ``stage_sink`` at each gauntlet checkpoint
        (ADR-0046).  ``stream: False`` to the upstream endpoint is UNCHANGED.
        """
        t_total = time.monotonic()

        t_fetch_start = time.monotonic()
        events = await self.store.get_by_ip(ip)
        t_fetch = _ms_since(t_fetch_start)

        if not events:
            logger.info("pipeline.analyze_ip_detailed ip=%s fetch=%sms (empty)", ip, t_fetch)
            if stage_sink is not None:
                await stage_sink.close()
            return {"error": "No logs found"}

        # F1 (DoS-via-legitimate-input hardening): cap to the most-recent
        # MAX_DETAILED_EVENTS events so a pathological IP cannot load unbounded memory
        # into a single coroutine.  Most-recent-N ordering preserves the "all rules"
        # semantics for realistic volumes; the accepted trade-off is that a rule
        # appearing ONLY in events older than this window could be missed.
        if len(events) > MAX_DETAILED_EVENTS:
            events = sorted(events, key=lambda e: e.timestamp, reverse=True)[:MAX_DETAILED_EVENTS]

        blocked = [e for e in events if e.action in ("BLOCK", "DROP")]
        timestamps = [e.timestamp for e in events]

        # Issue #52 (ADR-0070 D4): run_rules/build_score_breakdown see only the
        # trailing W_STATE (24h) slice — the golden-oracle constraint means this
        # slicing happens HERE, never inside run_rules itself. analyze_ip_detailed
        # does not call detect(), so no W_CAMPAIGN slice is needed on this path.
        now = self._clock()
        state_events = _window_slice(events, now, W_STATE)

        t_score_start = time.monotonic()
        rule_score, attack_types = run_rules(state_events)
        t_score = _ms_since(t_score_start)

        # security_mode: any non-azure_waf source → use generalized security prompt.
        sources_seen = {e.source_type for e in events}
        security_mode = bool(sources_seen - {"azure_waf"})

        # Issue #268: when include_ai=False the caller has already determined (via
        # GET /health) that the AI engine is offline — skip the AI path entirely.
        # Issue #102: even on the include_ai=True path, skip expensive sampling when
        # the engine reports itself unavailable.
        # build_detailed_samples is CPU-bound; run it off the event loop via to_thread
        # so it cannot stall concurrent requests (ADR-0023 §F single-loop deployment).
        t_ai_start = time.monotonic()

        # Effective availability: explicitly skipped OR engine unreachable.
        ai_will_run = include_ai and await self.ai_engine.is_available()

        if ai_will_run:
            rule_descs = await self.store.get_rule_descriptions()
            samples = await asyncio.to_thread(build_detailed_samples, events, rule_descs)
        else:
            samples = []

        # MK-10: emit prompt_built once samples are ready (ADR-0046 D3).
        # Security: sample_count is a plain integer — never attacker text.
        if stage_sink is not None and ai_will_run:
            await stage_sink.emit(PromptBuiltFact(sample_count=len(samples)))

        ai_result: dict[str, Any] | None = None
        ai_meta: Any | None = None

        # Issue #313 Fix 1: gate the engine call on ai_will_run (not include_ai).
        # Before this fix the call was gated on `if include_ai:`, so ai=true with
        # Ollama offline still invoked analyze_detailed against an unreachable httpx
        # endpoint under a 120-second timeout — causing the 14–18s symptom.
        # Now: if include_ai=True but is_available()=False, we skip the call and
        # stamp ai_status='unavailable' (ADR-0035 honesty: never claim success when
        # the engine was requested but unreachable).
        if not ai_will_run and include_ai and stage_sink is not None:
            # Engine was requested but is unavailable — emit failed before closing.
            await stage_sink.emit(
                FailedFact(
                    at_stage=StageName.REQUEST_SENT,
                    reason_code=FailReason.ENGINE_UNAVAILABLE,
                )
            )
            await stage_sink.close()

        if ai_will_run:
            # MK-10: emit request_sent — model and endpoint_host from engine config,
            # never from model output (OWASP API8: host:port only, no credentials).
            if stage_sink is not None:
                _model_name = getattr(self.ai_engine, "model", "unknown")
                _endpoint_host = _endpoint_host_from_engine(self.ai_engine)
                await stage_sink.emit(
                    RequestSentFact(model=_model_name, endpoint_host=_endpoint_host)
                )

            # MK-10: heartbeat task — emits generating{elapsed_ms} every
            # _GENERATING_HEARTBEAT_INTERVAL_S while the LLM call is in flight.
            # Cancelled automatically when the LLM call completes (success or error).
            _t_request_start = time.monotonic()

            async def _heartbeat() -> None:
                try:
                    while True:
                        await asyncio.sleep(_GENERATING_HEARTBEAT_INTERVAL_S)
                        if stage_sink is not None:
                            elapsed = round(
                                (time.monotonic() - _t_request_start) * 1000, 2
                            )
                            await stage_sink.emit(GeneratingFact(elapsed_ms=elapsed))
                except asyncio.CancelledError:
                    pass

            _hb_task: asyncio.Task[None] | None = (
                asyncio.ensure_future(_heartbeat()) if stage_sink is not None else None
            )

            try:
                # MK-2: prefer *_with_meta when the concrete engine exposes it.
                with_meta_fn = getattr(self.ai_engine, "analyze_detailed_with_meta", None)
                if with_meta_fn is not None:
                    raw_ai, ai_meta = await with_meta_fn(
                        ip=ip,
                        total_events=len(events),
                        blocked_events=len(blocked),
                        rules_triggered=len(samples),
                        first_seen=str(min(timestamps)),
                        last_seen=str(max(timestamps)),
                        samples=samples,
                        security_mode=security_mode,
                    )
                else:
                    raw_ai = await self.ai_engine.analyze_detailed(
                        ip=ip,
                        total_events=len(events),
                        blocked_events=len(blocked),
                        rules_triggered=len(samples),
                        first_seen=str(min(timestamps)),
                        last_seen=str(max(timestamps)),
                        samples=samples,
                        security_mode=security_mode,
                    )

                # Cancel heartbeat now that the response is in.
                if _hb_task is not None:
                    _hb_task.cancel()

                # MK-10: emit received — latency and optional completion_tokens.
                # Token count comes from ai_meta.completion_tokens (usage block) when
                # the with_meta path is used; None otherwise — never fabricated (ADR-0044 §2).
                if stage_sink is not None:
                    _latency = round((time.monotonic() - _t_request_start) * 1000, 2)
                    _completion_tokens: int | None = (
                        getattr(ai_meta, "completion_tokens", None)
                        if ai_meta is not None
                        else None
                    )
                    await stage_sink.emit(
                        ReceivedFact(
                            latency_ms=_latency,
                            completion_tokens=_completion_tokens,
                        )
                    )

                # NB-3: branch on ai_status BEFORE any schema validation.
                # The fallback envelope (ai_status=="unavailable", threat_level=="UNKNOWN")
                # is deliberately outside the closed schema — treat it as "no AI contribution"
                # and do NOT schema-validate it.
                if raw_ai.get("ai_status") != "unavailable":
                    ai_result = raw_ai
                    # MK-10: validation passed (engine returned a non-fallback result).
                    if stage_sink is not None:
                        await stage_sink.emit(ValidatedFact())
                        await stage_sink.emit(ProjectedFact(field_count=len(raw_ai)))
                else:
                    logger.info(
                        "pipeline.analyze_ip_detailed ip=%s AI returned fallback envelope "
                        "(ai_status=unavailable) — scoring rules-only (NB-3)",
                        ip,
                    )
                    # MK-10: fallback envelope = validation failed path.
                    if stage_sink is not None:
                        await stage_sink.emit(
                            FailedFact(
                                at_stage=StageName.VALIDATED,
                                reason_code=FailReason.VALIDATION_ERROR,
                            )
                        )

            except asyncio.CancelledError:
                # Client disconnect propagates CancelledError — cancel heartbeat,
                # emit cancelled fact, then re-raise so the task is truly cancelled.
                if _hb_task is not None:
                    _hb_task.cancel()
                if stage_sink is not None:
                    await stage_sink.emit(
                        FailedFact(
                            at_stage=StageName.REQUEST_SENT,
                            reason_code=FailReason.CANCELLED,
                        )
                    )
                    await stage_sink.close()
                raise

            except Exception:
                # AI call exception → rules-only, never abort.
                # logger.exception (not .warning) so a misbehaving engine implementation
                # (e.g. returns None, throws from inside the model) surfaces a full traceback
                # in development while still degrading gracefully to a rules-only result.
                if _hb_task is not None:
                    _hb_task.cancel()
                logger.exception("AI detailed analysis failed for %s, rules only", ip)
                if stage_sink is not None:
                    await stage_sink.emit(
                        FailedFact(
                            at_stage=StageName.REQUEST_SENT,
                            reason_code=FailReason.ENGINE_ERROR,
                        )
                    )

        # MK-10: close the emitter so the SSE consumer sees the sentinel and stops
        # waiting.  Called on all exit paths (success, failure, unavailable).
        if stage_sink is not None:
            await stage_sink.close()

        t_ai = _ms_since(t_ai_start)

        # Reuse merge_score (no copy — EARS invariant).
        score, level, score_derivation = merge_score(rule_score, ai_result)

        # Issue #209: compute breakdown with same inputs (no detection_boost on detailed
        # path — detection correlations are not run in analyze_ip_detailed).
        # Issue #52: windowed to W_STATE, same as run_rules (ADR-0070 D4).
        score_breakdown = build_score_breakdown(state_events, ai_result)

        # Issue #132 DC-1: fetch recent raw log rows for the "Recent Logs" table.
        # get_by_ip_raw returns dicts ordered newest-first; cap to _MAX_DETECTIONS.
        try:
            raw_rows = await self.store.get_by_ip_raw(ip)
            detections_rows: list[dict[str, Any]] = raw_rows[:_MAX_DETECTIONS]
        except Exception:
            logger.debug("pipeline.analyze_ip_detailed: get_by_ip_raw failed for ip=%s", ip)
            detections_rows = []

        # Resolve geo fields — issue #132 DC-2 (location) + issue #211 (asn/as_name).
        # NB-4 (security): location, as_name, and city are attacker-influenced data
        # (they derive from the attacker's own IP registration).  They MUST NOT be
        # interpolated into AI prompts without <untrusted_data> sentinel wrapping.
        location, asn, as_name = await self._resolve_geo(ip)

        # MK-2: persist the validated analysis to the ledger (fail-safe, ADR-0044).
        # Called AFTER merge_score — cannot influence the score.
        if ai_result is not None:
            await self._record_analysis(
                ip=ip,
                kind="detailed",
                ai_result=ai_result,
                score=score,
                score_derivation=score_derivation,
                meta=ai_meta,
            )

        logger.info(
            "pipeline.analyze_ip_detailed ip=%s events=%d fetch=%sms score=%sms "
            "ai=%sms total=%sms level=%s include_ai=%s detections_rows=%d derivation=%s",
            ip, len(events), t_fetch, t_score, t_ai, _ms_since(t_total),
            level, include_ai, len(detections_rows), score_derivation,
        )

        # Augment the AI result dict with v1 fields (legacy/app/analyzer.py:280-286).
        # If no AI result (rules-only), start from an empty dict.
        result: dict[str, Any] = dict(ai_result) if ai_result is not None else {}
        result["score"] = score
        result["threat_level"] = level
        result["score_derivation"] = score_derivation  # issue #201 / ADR-0035
        result["score_breakdown"] = [item.model_dump() for item in score_breakdown]
        result["total_events"] = len(events)
        result["blocked_events"] = len(blocked)
        result["attack_types"] = attack_types
        result["source_ip"] = ip
        # Issue #132 extensions:
        result["detections"] = detections_rows
        result["location"] = location
        # Issue #211 extensions: ASN fields (additive, None when absent).
        result["asn"] = asn
        result["as_name"] = as_name
        # ADR-0035 honesty: stamp ai_status to accurately reflect what happened.
        # Three distinct states (issue #268 / #313):
        #   'skipped'     — ai=false (caller opted out; engine never consulted)
        #   'unavailable' — ai=true but engine offline/unreachable (requested but down)
        #   (from ai_result) — engine ran; ai_result carries 'ok' or the engine's own status
        # NB-3 (issue #306): 'skipped' is a pipeline-only stamp — only this block may
        # write it.  If ai_result somehow carries ai_status='skipped' (misbehaving local
        # model), the schema-validation layer in OpenAIEngine will already have triggered
        # the fallback envelope (ai_result=None), but we guard here as defence-in-depth:
        # strip 'skipped' so it cannot propagate from AI output to the caller.
        if not include_ai:
            # Issue #268: explicitly skipped by the caller.
            result["ai_status"] = "skipped"
        elif not ai_will_run:
            # Issue #313 Fix 1: ai=true but is_available()=False — engine was requested
            # but unreachable.  Stamp 'unavailable' so the client knows and never claim
            # success (ADR-0035).
            result["ai_status"] = "unavailable"
        elif result.get("ai_status") == "skipped":
            # NB-3 (issue #306): defence-in-depth — override a misbehaving model's
            # ai_status='skipped' when AI actually ran.  The schema-layer should
            # have caught this first (→ fallback envelope with ai_status='unavailable'),
            # but we guard here too.  We stamp 'unavailable' rather than popping the
            # field to keep the API contract intact (field is required by the TS client).
            result["ai_status"] = "unavailable"
        return result
