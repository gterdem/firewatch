"""Threat routes — GET /threats, /threats/{ip}, /threats/{ip}/detailed, /threats/{ip}/events,
and GET /threats/{ip}/score-history.

Thin controllers: all scoring logic lives in Pipeline (ADR-0029 D1 / EARS ubiquitous).

Response shapes:
- ``/threats`` → ``list[ThreatScoreWithDecision]`` — the SDK ``ThreatScore``
  (ADR-0029 D3) plus the additive ``triage_decision`` annotation (ADR-0072 D3;
  added at the API schema layer, not the SDK model — ADR-0029 D5 split).
- ``/threats/{ip}`` → ``ThreatScoreWithDecision`` or **404** when no events
  exist (ADR-0029 D3).
- ``/threats/{ip}/detailed`` → augmented dict from ``pipeline.analyze_ip_detailed``.
- ``/threats/{ip}/events`` → ``IPEventTimelineResponse`` — per-event cross-source
  timeline (issue #118 / OD-3).  Returns 404 when the IP has no events.
- ``/threats/{ip}/score-history`` → ``list[{ip, score, ts}]`` — UTC-bucketed score
  trajectory for the sparkline (issue #250).  Unknown IP → **empty list** (not 404).

Unknown IP → 404 (RFC 9110 §15.5.5); not an empty-200 (ADR-0029 D3).
Exception: ``/score-history`` returns an empty series for unknown IPs — absence of
history is not an error (issue #250 EARS "unknown IPs yield an empty series").

NB-1: The ``{ip}`` path parameter is validated against a regex that accepts both
dotted-decimal IPv4 and colon-hex IPv6 addresses (including compressed forms).
Malformed values are rejected with 422 before any store or pipeline call is made.
The regex is permissive enough for all legal addresses without a full parser so that
FastAPI's ``Path`` constraint can be applied at the schema layer.  Final authority is
``ipaddress.ip_address()`` inside the pipeline if further validation is needed.

Imports only firewatch-sdk and firewatch-core. Never imports legacy/.
"""
from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query

from firewatch_sdk import ThreatScore

from firewatch_api import decision_annotator
from firewatch_api.deps import get_decision_store, get_event_store, get_pipeline
from firewatch_api.schemas import (
    DEFAULT_TIMELINE_CAP,
    CounterfactualResponse,
    EvidenceChainResponse,
    IPEventTimelineResponse,
    NarrationResponse,
    ThreatScoreWithDecision,
    TimelineEventItem,
    TriageDecisionAnnotation,
)

# NB-1: Regex that accepts both IPv4 (dotted-decimal) and IPv6 (colon-hex,
# including compressed '::' forms).  Not a strict parser — `ipaddress` would
# be exact — but strict enough to reject obvious injection strings (spaces,
# backticks, path separators) with a 422 before any business logic runs.
# Covers:
#   IPv4:  0–255 octets, e.g. 192.0.2.1
#   IPv6:  hex groups with colons, e.g. 2001:db8::1, ::1, fe80::1%eth0
#   IPv4-mapped IPv6: ::ffff:192.0.2.1  (handled by the colon-hex branch)
_IP_REGEX = (
    r"^("
    # IPv4
    r"(\d{1,3}\.){3}\d{1,3}"
    r"|"
    # IPv6 (hex groups separated by colons, with optional zone-id %...)
    r"[0-9a-fA-F:]+(%[a-zA-Z0-9._~-]+)?"
    r")$"
)

# Annotated alias reused by all routes that take an {ip} path parameter.
IpParam = Annotated[
    str,
    Path(
        pattern=_IP_REGEX,
        description="IPv4 or IPv6 address of the threat actor.",
    ),
]

logger = logging.getLogger("firewatch.api.threats")

router = APIRouter(prefix="/threats", tags=["threats"])


async def _annotate_score(score: ThreatScore, decision_store: Any) -> ThreatScoreWithDecision:
    """Attach the additive ``triage_decision`` annotation to *score* (ADR-0072 D3/D8).

    When *decision_store* is None (not wired) every actor renders as
    undecided — degrades to today's behaviour, never a 503 (the annotation
    is additive; its absence must not break the read surface).
    """
    rows: list[dict[str, Any]] = []
    if decision_store is not None:
        rows = await decision_store.get_active_for_actor(score.source_ip)
    annotated = decision_annotator.annotate(rows, score.escalation)
    triage_decision = (
        TriageDecisionAnnotation(
            verb=annotated.verb,  # type: ignore[arg-type]
            decided_at=annotated.decided_at,
            decided_tier=annotated.decided_tier,
            decided_score=annotated.decided_score,
            suppressed=annotated.suppressed,
            reentry=annotated.reentry,
        )
        if annotated is not None
        else None
    )
    return ThreatScoreWithDecision(**score.model_dump(), triage_decision=triage_decision)


@router.get(
    "",
    summary="List all IP threat scores",
    response_model=list[ThreatScoreWithDecision],
)
async def list_threats(
    pipeline: Any = Depends(get_pipeline),
    store: Any = Depends(get_event_store),
    decision_store: Any = Depends(get_decision_store),
) -> list[ThreatScoreWithDecision]:
    """Return a ThreatScore (+ triage_decision annotation) for every IP with events.

    Fetches distinct IPs from the store then scores each via the pipeline.
    Returns an empty list when no events exist (200 OK — not an error).
    Decided actors are NEVER excluded from this list (ADR-0072 finding 1) —
    ``triage_decision.suppressed`` tells the client whether the actor is
    queue-worthy; the row itself always renders (feeds the entity panel).
    """
    if store is None:
        raise HTTPException(status_code=503, detail="Event store not available")
    if pipeline is None:
        raise HTTPException(status_code=503, detail="Pipeline not available")

    ips: list[str] = await store.get_all_ips()
    scores: list[ThreatScoreWithDecision] = []
    for ip in ips:
        score = await pipeline.analyze_ip(ip, use_ai=False)
        # Only include IPs that have events (analyze_ip returns score=0/total=0
        # for unknown IPs — filter those out of the list endpoint).
        if score.total_events > 0:
            scores.append(await _annotate_score(score, decision_store))
    return scores


@router.get(
    "/{ip}",
    summary="Get threat score for a specific IP",
    response_model=ThreatScoreWithDecision,
)
async def get_threat(
    ip: IpParam,
    pipeline: Any = Depends(get_pipeline),
    store: Any = Depends(get_event_store),
    decision_store: Any = Depends(get_decision_store),
) -> ThreatScoreWithDecision:
    """Return the ThreatScore (+ triage_decision annotation) for *ip*.

    Returns **404** (not an empty ThreatScore) when the IP has no events
    (ADR-0029 D3 — RFC 9110 §15.5.5 resource semantics; unknown IP is not a
    resource, it is a missing resource). A DECIDED actor is never 404'd by
    virtue of being decided — the annotation only ever adds information.
    """
    if store is None:
        raise HTTPException(status_code=503, detail="Event store not available")
    if pipeline is None:
        raise HTTPException(status_code=503, detail="Pipeline not available")

    score: ThreatScore = await pipeline.analyze_ip(ip, use_ai=False)
    if score.total_events == 0:
        raise HTTPException(
            status_code=404,
            detail="No events found for the requested IP",
        )
    return await _annotate_score(score, decision_store)


@router.get(
    "/{ip}/detailed",
    summary="Get detailed AI-augmented analysis for a specific IP",
)
async def get_threat_detailed(
    ip: IpParam,
    ai: bool = Query(
        default=True,
        description=(
            "Set to false to skip the AI engine entirely (fast path). "
            "Returns rule-only analysis with ai_status='skipped'. "
            "Latency matches GET /threats/{ip}. "
            "Issue #268 — staged honest AI loading."
        ),
    ),
    pipeline: Any = Depends(get_pipeline),
    store: Any = Depends(get_event_store),
) -> dict[str, Any]:
    """Return the deep-analysis result dict for *ip*.

    Delegates to ``pipeline.analyze_ip_detailed`` (issue #19).  Returns a dict
    (not ThreatScore) because the detailed path augments the AI result with
    extra fields (v1 parity, ADR-0024).

    When ``ai=false`` the AI engine is skipped entirely; the response carries
    ``ai_status='skipped'`` (never a success claim).  The client uses this fast
    path when ``GET /health`` reports the AI engine is offline, then optionally
    follows up with ``ai=true`` for the deep-analysis pass (issue #268).

    Returns **404** when no events exist for the IP.
    """
    if store is None:
        raise HTTPException(status_code=503, detail="Event store not available")
    if pipeline is None:
        raise HTTPException(status_code=503, detail="Pipeline not available")

    result: dict[str, Any] = await pipeline.analyze_ip_detailed(ip, include_ai=ai)
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.get(
    "/{ip}/events",
    summary="Get per-event cross-source timeline for a specific IP",
    response_model=IPEventTimelineResponse,
)
async def get_ip_event_timeline(
    ip: IpParam,
    limit: int = Query(
        default=DEFAULT_TIMELINE_CAP,
        ge=1,
        le=1000,
        description="Maximum number of events to return (cap). Default 200.",
    ),
    store: Any = Depends(get_event_store),
) -> IPEventTimelineResponse:
    """Return a time-ordered cross-source event timeline for *ip* (issue #118 / OD-3).

    Each entry maps to one ``TimelineEvent`` in the frontend ``EventTimeline``
    component.  Events are ordered chronologically (ascending timestamp).
    The ``correlated`` flag is ``True`` on every entry when the IP's events span
    more than one source_type — this powers the orange left stripe in EventTimeline.

    The result is capped at *limit* (default 200, max 1000) to bound the HTTP
    response.  When the store held more events than the cap, ``capped=True`` is
    set on the response envelope so the caller knows the view is partial.

    Returns **404** when the IP has no events.
    Returns **503** when the event store is not available.
    """
    if store is None:
        raise HTTPException(status_code=503, detail="Event store not available")

    # Fetch one extra row to detect truncation without a separate COUNT query.
    rows: list[dict[str, Any]] = await store.get_events_for_timeline(ip, limit + 1)

    if not rows:
        raise HTTPException(
            status_code=404,
            detail="No events found for the requested IP",
        )

    capped = len(rows) > limit
    rows = rows[:limit]

    source_types_seen: list[str] = sorted({r.get("source_type", "unknown") for r in rows})
    is_correlated = len(source_types_seen) > 1

    events: list[TimelineEventItem] = [
        TimelineEventItem(
            source=r.get("source_type") or "unknown",
            time=r.get("timestamp") or "",
            # rule_name is not persisted in the logs table; use rule_id then category
            label=r.get("rule_id") or r.get("category") or None,
            payload=r.get("payload_snippet") or None,
            correlated=is_correlated,
            action=r.get("action") or "ALLOW",
            severity=r.get("severity") or None,
            category=r.get("category") or None,
        )
        for r in rows
    ]

    return IPEventTimelineResponse(
        events=events,
        total=len(events),
        correlated=is_correlated,
        source_types=source_types_seen,
        capped=capped,
    )


#: Default look-back window for the score-history route (hours).
#: Matches the SCORE_HISTORY_DELTA_WINDOW_HOURS constant in sqlite_store.py
#: and the default assumed by the Risk Movers sparkline (issue #250 / #251).
_DEFAULT_SCORE_HISTORY_WINDOW_HOURS: float = 24.0


@router.get(
    "/{ip}/score-history",
    summary="Get score trajectory for a specific IP",
)
async def get_score_history(
    ip: IpParam,
    window: float = Query(
        default=_DEFAULT_SCORE_HISTORY_WINDOW_HOURS,
        gt=0,
        description=(
            "Look-back window in hours (must be > 0). "
            "Defaults to 24 h. "
            "Returns snapshots within this window, oldest first."
        ),
    ),
    store: Any = Depends(get_event_store),
) -> list[dict[str, Any]]:
    """Return the score trajectory for *ip* as a UTC-bucketed series (issue #250).

    Each element is ``{ip: str, score: int, ts: str}`` (ts is ISO-8601 UTC),
    ordered chronologically so callers can render a sparkline directly.

    Returns an **empty list** (200 OK) when the IP has no score history —
    absence of history is not an error (new actor, or IP has never been scored).
    This differs from ``GET /threats/{ip}`` which returns 404 for unknown IPs.

    Returns **422** when ``window`` is zero or negative (ADR-0029 D3).
    Returns **503** when the event store is not available.
    """
    if store is None:
        raise HTTPException(status_code=503, detail="Event store not available")

    rows: list[dict[str, Any]] = await store.get_score_history(ip, window)
    return rows


@router.get(
    "/{ip}/counterfactual",
    summary="Counterfactual impact — how many requests a block would have stopped",
    response_model=CounterfactualResponse,
)
async def get_ip_counterfactual(
    ip: IpParam,
    store: Any = Depends(get_event_store),
) -> CounterfactualResponse:
    """Return counterfactual impact counts for *ip* (issue #215).

    Reports how many stored requests a block on this IP WOULD have stopped:
    ``unblocked_events`` = total_events − blocked_events (events where action
    was NOT BLOCK or DROP — i.e. ALLOW, ALERT, LOG).

    Semantic note (ADR-0012): Suricata IDS events carry action='ALERT'
    (detected, not stopped) and are correctly counted in ``unblocked_events``.
    A block would have stopped them.  The count is source-agnostic and honest.

    When the IP has no stored events all counts return 0.  The UI must handle
    the all-blocked case (``unblocked_events == 0``) gracefully — that is itself
    informative ("the wall already holds").

    Window: all stored events for the IP (no time bound; consistent with
    the recommendation queue's ThreatScore fields).

    Returns **503** when the event store is not available.
    The ``{ip}`` param is validated with the same regex as all other threat routes.
    """
    if store is None:
        raise HTTPException(status_code=503, detail="Event store not available")

    data: dict[str, Any] = await store.get_ip_counterfactual(ip)
    return CounterfactualResponse(**data)


@router.get(
    "/{ip}/evidence",
    summary="Evidence chain — which events produced each score factor",
    response_model=EvidenceChainResponse,
)
async def get_ip_evidence(
    ip: IpParam,
    pipeline: Any = Depends(get_pipeline),
    store: Any = Depends(get_event_store),
) -> EvidenceChainResponse:
    """Return the evidence chain for *ip* (ADR-0041 / issue #387 MI-6).

    Answers "which events produced this score factor?" by recomputing the
    factor → ``logs`` row-id mapping at read time from stored rows.

    **Read-time semantics (ADR-0041):** events arriving after scoring may shift
    the contributing row sets; this is a recompute, not a snapshot.  The
    ``recomputed: true`` field in the response makes this explicit.

    **ai-engine-invariants boundary (hard — see ai-engine-invariants skill):**
    This endpoint makes NO LLM calls, builds NO AI samples, and changes NO
    scoring values.  The ``ai_boost`` factor returns a reference to the stored
    AI analysis artifact (ADR-0035 provenance).

    Returns **404** when the IP has no stored events.
    Returns **503** when the store or pipeline is not available.

    Route registered in ADR-0029 route catalogue as
    ``GET /threats/{ip}/evidence``.
    """
    if store is None:
        raise HTTPException(status_code=503, detail="Event store not available")
    if pipeline is None:
        raise HTTPException(status_code=503, detail="Pipeline not available")

    # Fetch rows with their stable ``logs.id`` keys (ADR-0041 — the only
    # reliable per-event identifier in production; event_id is empty).
    rows: list[dict[str, Any]] = await store.get_events_with_row_ids(ip)
    if not rows:
        raise HTTPException(
            status_code=404,
            detail="No events found for the requested IP",
        )

    # Score the IP rules-only (fast path — no AI call) to get the breakdown.
    # ai-engine-invariants: use_ai=False — no LLM call here.
    score = await pipeline.analyze_ip(ip, use_ai=False)
    breakdown = score.score_breakdown

    # Build the evidence chain (pure, no I/O, no AI call — evidence.py).
    from firewatch_core.evidence import build_evidence_chain  # local import avoids circular

    chain = build_evidence_chain(rows, breakdown, ai_result=None)

    # Serialise: each item is a Pydantic model; use model_dump for JSON-safe dicts.
    factors = [item.model_dump() for item in chain]

    return EvidenceChainResponse(source_ip=ip, factors=factors, recomputed=True)


@router.get(
    "/{ip}/narration",
    summary="One-click local-LLM narration for a specific IP (ML-7)",
    response_model=NarrationResponse,
)
async def get_ip_narration(
    ip: IpParam,
    ai: bool = Query(
        default=True,
        description=(
            "Set to false to skip the LLM and return a rule-only summary "
            "(ai_status='skipped', provenance='rule'). "
            "Identical latency to GET /threats/{ip} (no LLM call). "
            "ML-7 EARS-4: AI-unavailable degrade path."
        ),
    ),
    pipeline: Any = Depends(get_pipeline),
    store: Any = Depends(get_event_store),
) -> NarrationResponse:
    """Return a SHORT narrative grounded in this IP's real collected fields (ML-7, issue #435).

    **EARS-1:** Reuses ``/threats/{ip}/detailed`` + ``score_breakdown`` data path.
    No parallel scoring; this is a read-then-narrate operation on existing data.

    **EARS-3 (anti-fabrication):** The prompt injected into the local LLM includes
    ONLY fields that are non-null for this IP.  Fields that were not collected
    (bytes, DNS queries, JA4 fingerprints when NULL) are withheld from the prompt —
    the LLM cannot fabricate dimensions it was not given.

    **EARS-4:** When ``ai=false`` OR the AI engine is unavailable, the response
    carries a deterministic rule-only summary (``provenance='rule'``) with no LLM
    call.  This is the ADR-0015 graceful degradation path — non-fatal.

    **ADR-0035 provenance:** ``provenance`` is always set:
    - ``"rule"``    — LLM not called (offline / ai=false).
    - ``"ai"``      — LLM authored the narrative.
    - ``"ai+rule"`` — LLM narrative over an ai+rule score.

    **ADR-0015:** The "what to check next" sentence is advisory only — no SOAR/
    execution actions.  Zero-egress: local model only (ai-engine-invariants skill).

    Returns **404** when the IP has no stored events.
    Returns **503** when the store or pipeline is unavailable.
    """
    if store is None:
        raise HTTPException(status_code=503, detail="Event store not available")
    if pipeline is None:
        raise HTTPException(status_code=503, detail="Pipeline not available")

    # Fetch the detailed analysis (reuse existing path — EARS-1).
    # include_ai=ai: when ai=false, we still fetch the rule-only detail for
    # field extraction, then build_rule_only_narration handles the degrade.
    detail: dict[str, Any] = await pipeline.analyze_ip_detailed(ip, include_ai=ai)

    if "error" in detail:
        raise HTTPException(status_code=404, detail=detail["error"])

    # Import narration helpers (local import keeps threats.py import surface clean).
    from firewatch_core.ai.narration import (  # local import — no circular risk
        build_narration_prompt,
        build_rule_only_narration,
    )

    ai_status: str = str(detail.get("ai_status", "unavailable"))
    score_derivation: str = str(detail.get("score_derivation", "rule"))

    # Determine whether the LLM should be called for narration.
    # The LLM runs ONLY when:
    #   - ai=true (caller did not opt out)
    #   - AND the AI engine actually ran for the detailed call (ai_status == "active")
    # ADR-0066: branch POSITIVELY on "active" — a "not in (...)" exclusion list
    # would silently misread the new "no_input" state as "AI ran". This mirrors
    # the analyze_ip_detailed availability check; we do not re-check
    # is_available() because the detailed call already stamped the correct ai_status.
    ai_ran_in_detail = ai_status == "active"
    will_narrate_with_llm = ai and ai_ran_in_detail

    if will_narrate_with_llm:
        # Build the narration prompt (pure function — no LLM call yet).
        narration_prompt = build_narration_prompt(ip, detail)

        # Call the AI engine for the short narrative.
        # We re-use analyze_concise because its contract (returns a dict with
        # at least one text field) is the closest existing port method.
        # The narration call is a SEPARATE prompt — NOT modifying the scoring path.
        #
        # ai-engine-invariants boundary:
        # - We do NOT call analyze_ip or analyze_ip_detailed again.
        # - We do NOT run rules or modify scores.
        # - This call is narration-only (separate prompt, separate output).
        try:
            samples = [{"rule_id": "narration", "category": "narration",
                        "count": 1, "payload": ""}]
            raw_narration = await pipeline.ai_engine.analyze_concise(
                ip=ip,
                total_events=int(detail.get("total_events", 0)),
                blocked_events=int(detail.get("blocked_events", 0)),
                rules_triggered=1,
                first_seen=str(detail.get("first_seen") or ""),
                last_seen=str(detail.get("last_seen") or ""),
                samples=samples,
                security_mode=False,
                # Override the prompt by passing the built narration prompt via
                # the _narration_prompt kwarg understood by the narration adapter.
                # Standard engines ignore unknown kwargs — they call analyze_concise
                # with the standard samples-based prompt.  The NarrationEngine
                # adapter (used in production) intercepts this kwarg.
                _narration_prompt=narration_prompt,
            )
            # The narration text is in the 'intent' field when using the standard
            # analyze_concise path, or in 'narrative' when the narration adapter
            # is wired.  Extract whichever is present.
            narrative_text: str = (
                raw_narration.get("narrative")
                or raw_narration.get("intent")
                or raw_narration.get("executive_summary")
                or ""
            )
            # Extract provenance hint from PROVENANCE line in narrative if present.
            prov_line = ""
            if "PROVENANCE:" in narrative_text:
                parts = narrative_text.split("PROVENANCE:", 1)
                narrative_text = parts[0].strip()
                prov_line = parts[1].strip() if len(parts) > 1 else ""

            collected = [f.strip() for f in prov_line.split(",") if f.strip()] or (
                build_narration_prompt.__module__ and []
            )

            provenance = "ai" if score_derivation == "rule" else score_derivation

            return NarrationResponse(
                source_ip=ip,
                narrative=narrative_text,
                provenance=provenance,
                collected_fields=collected or [],
                ai_status=ai_status,
            )
        except Exception:
            logger.warning(
                "threats.get_ip_narration: LLM narration failed for ip=%s — "
                "degrading to rule-only (EARS-4 / ADR-0015)",
                ip,
            )
            # Fall through to rule-only degrade.

    # Rule-only narration — EARS-4 degrade path (AI unavailable or ai=false).
    rule_result = build_rule_only_narration(ip, detail)
    return NarrationResponse(
        source_ip=ip,
        narrative=rule_result["narrative"],
        provenance=rule_result["provenance"],
        collected_fields=rule_result["collected_fields"],
        ai_status=rule_result["ai_status"],
    )
