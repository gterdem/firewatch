"""API-only response shapes for the FireWatch read and write surfaces.

These types are HTTP-delivery concerns and do NOT belong in firewatch-sdk.
Plugins and core never produce them — the SDK stays delivery-agnostic (ADR-0029 D5).

The pagination envelope mirrors the store's ``get_paginated`` return exactly
(ADR-0029 D2 — expose verbatim, no re-wrapping or key renaming).

Ingest shapes (ADR-0029 D7 — MC.3):
  ``IngestRequest`` / ``BatchIngestRequest`` are the POST /logs request bodies.
  ``IngestResponse`` is the response envelope (inserted + deduped counts, mirroring
  the store's ``save_many`` return contract per ADR-0007/0016).

  The ``data`` field in ``IngestRequest`` is attacker-controlled (ADR-0015 / ADR-0029 D3).
  It is treated as opaque and flows into the plugin's ``normalize()`` and the event's
  ``raw_log`` — never interpolated into log messages as a format string.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Ingest request / response shapes (ADR-0029 D7 — MC.3, issue #88)
# ---------------------------------------------------------------------------

#: Default maximum number of events accepted in a single ``POST /logs/batch``
#: request (ADR-0029 D7.2 / ADR-0006: config-overridable; see ingest.py).
DEFAULT_MAX_BATCH_SIZE: int = 100

# ``source_type`` is aligned to the SDK TYPE_KEY_PATTERN so that ingest
# identifiers are structurally identical to plugin-declared type_keys
# (firewatch_sdk.metadata.TYPE_KEY_PATTERN = r"^[a-z][a-z0-9_]*$").
# This also blocks CR/LF and all control characters (log-injection defence).
_SOURCE_TYPE_PATTERN = r"^[a-z][a-z0-9_]*$"

# ``source_id`` is a human-assigned instance label (approx ECS observer.name).
# It allows word-chars, hyphens, dots, colons, slashes, at-signs, and spaces
# — sufficient for names like "sensor-01", "prod/edge-01", "dc:01" —
# while blocking CR/LF, NUL, and every ASCII control character that could be
# exploited for log-injection (the field is logged via %s in ingest.py).
_SOURCE_ID_PATTERN = r"^[\w\-.:/@ ]+$"


class IngestRequest(BaseModel):
    """Body for ``POST /logs`` (single-event ingest).

    ``source_type`` routes the raw event to the correct plugin's ``normalize()``.
    Constrained to ``_SOURCE_TYPE_PATTERN`` (``^[a-z][a-z0-9_]*$``), which is
    identical to the SDK's TYPE_KEY_PATTERN, so ingest source_type values are
    always structurally valid plugin type_keys.  CR/LF and control characters
    are excluded, preventing log-injection via this field.

    ``source_id`` is the user's named instance (approx ECS observer.name; for labelling
    only, never branched on for detection — ADR-0016 / PLUGIN_CONTRACT.md).
    Constrained to ``_SOURCE_ID_PATTERN`` to block CR/LF and control characters.
    Both constraints apply to every item in ``BatchIngestRequest.events`` as well,
    since that model composes ``IngestRequest`` directly.

    ``data`` is the opaque vendor payload.  It is attacker-controlled (ADR-0015) and
    flows into ``raw_log`` / the plugin's ``normalize()`` — NEVER interpolated into
    log messages as a format string.
    ``received_at`` is optional; defaults to the server's current UTC time when absent.
    """

    source_type: str = Field(
        min_length=1,
        max_length=128,
        pattern=_SOURCE_TYPE_PATTERN,
        description=(
            "Plugin type key — routes to that plugin's normalize() (ADR-0029 D7.1). "
            "Must match ^[a-z][a-z0-9_]*$ (aligned to SDK TYPE_KEY_PATTERN)."
        ),
    )
    source_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=_SOURCE_ID_PATTERN,
        description="User's named instance (labelling/logging only; ADR-0016).",
    )
    data: dict[str, Any] = Field(
        description="Opaque vendor payload. Attacker-controlled; treated as untrusted (ADR-0015).",
    )
    received_at: datetime | None = Field(
        default=None,
        description="Event receipt timestamp (UTC). Defaults to server time when absent.",
    )


class BatchIngestRequest(BaseModel):
    """Body for ``POST /logs/batch`` (bounded-list ingest).

    The list is bounded by ``DEFAULT_MAX_BATCH_SIZE`` (ADR-0029 D7.2 / ADR-0006).
    An over-limit body is rejected with 422 before any persistence.
    Each item in ``events`` is an ``IngestRequest`` and inherits its field
    constraints (source_type / source_id patterns and length bounds).
    """

    events: list[IngestRequest] = Field(
        description="List of raw events to ingest. Bounded by max_batch_size (ADR-0029 D7.2).",
    )


class IngestResponse(BaseModel):
    """Response envelope for ``POST /logs`` and ``POST /logs/batch``.

    Mirrors the ``save_many`` return contract (ADR-0007/0016):
    ``inserted`` = rows actually written; ``deduped`` = events the unique index absorbed
    (i.e. already present — replayed batch is absorbed, not double-counted; ADR-0029 D7.2).
    """

    inserted: int = Field(description="New rows written to the store.")
    deduped: int = Field(description="Events absorbed by dedup (already present).")


class PaginatedLogsResponse(BaseModel):
    """Verbatim projection of ``store.get_paginated``'s return envelope.

    The store owns the shape (ADR-0007); this model is a typed view at the HTTP
    boundary so FastAPI can document it. Keys are NEVER renamed or re-wrapped.

    ``next_cursor`` is an opaque continuation token — clients echo it back via
    the ``cursor`` query parameter.  A ``None`` value means no further pages.
    ``total_matching`` is filter-scoped; ``has_more`` is the primary pagination
    signal.
    """

    logs: list[dict[str, Any]]
    next_cursor: str | None
    has_more: bool
    total_matching: int


class LogsStatsResponse(BaseModel):
    """Filter-scoped totals for the Network Logs header strip (issue #663).

    All three counts are computed from a full table scan over the filtered
    scope — NOT derived from any top-N list (EARS-3).

    ``present_source_types`` is the sorted list of DISTINCT ``source_type``
    values within the filtered scope; used by the frontend source-type facet
    strip (#664).
    """

    total_events: int
    blocked_events: int
    distinct_ips: int
    present_source_types: list[str]


class HealthResponse(BaseModel):
    """Liveness + component status (GET /health).

    ``ollama_connected`` and ``ollama_model`` restore the AI status fields
    dropped in the MB.1 refactor (issue #135).  Field names are kept as
    ``ollama_*`` — the backend rename to ``ai_*`` is explicitly DEFERRED per
    #135; only the user-facing label changes (handled by the frontend).
    """

    status: str
    store: str
    ollama_connected: bool = False
    ollama_model: str | None = None


class ErrorDetail(BaseModel):
    """Structured error body for 4xx/5xx responses.

    Consumed by the React views — type, message, detail are stable field names.
    """

    type: str
    message: str
    detail: str | None = None


# ---------------------------------------------------------------------------
# Cross-source event timeline shapes (issue #118 / OD-3)
# ---------------------------------------------------------------------------

# Default maximum events returned by GET /threats/{ip}/events.
# Keeps the HTTP response bounded; the frontend EventTimeline renders a
# per-IP correlated view, not a full data-export.
DEFAULT_TIMELINE_CAP: int = 200


class TimelineEventItem(BaseModel):
    """One entry in the per-IP cross-source event timeline.

    Field names deliberately match the ``TimelineEvent`` TypeScript interface
    consumed by ``EventTimeline.tsx`` so the frontend can bind the response
    array directly without a client-side mapping step.

    ``source``     — source_type (colours the dot in EventTimeline).
    ``time``       — ISO-8601 UTC timestamp string (monospace column).
    ``label``      — rule_id or category; short descriptor (rule_name not persisted).
    ``payload``    — payload_snippet; attacker-controlled, rendered as text.
    ``correlated`` — True when this IP's events span more than one source_type
                     (powers the orange left stripe in EventTimeline).
    ``action``     — canonical action (ALERT/BLOCK/DROP/ALLOW/LOG); for colour
                     hints the frontend may add in future.
    ``severity``   — event severity level, optional.
    ``category``   — attack category label, optional.
    """

    source: str = Field(description="Plugin source_type — drives the dot colour.")
    time: str = Field(description="ISO-8601 UTC timestamp string.")
    label: str | None = Field(default=None, description="Rule id or category (rule_name not stored).")
    payload: str | None = Field(default=None, description="Payload snippet (attacker-controlled).")
    correlated: bool = Field(
        default=False,
        description="True when the IP appears in more than one source_type.",
    )
    action: str = Field(description="Canonical action (ALERT/BLOCK/DROP/ALLOW/LOG).")
    severity: str | None = Field(default=None, description="Event severity level.")
    category: str | None = Field(default=None, description="Attack category label.")


class CounterfactualResponse(BaseModel):
    """Response envelope for ``GET /threats/{ip}/counterfactual`` (issue #215).

    Reports how many past requests a block on *ip* WOULD have stopped.

    ``total_events``     — total events stored for this IP (all actions).
    ``blocked_events``   — events already stopped (action IN BLOCK/DROP).
    ``unblocked_events`` — events that got through; a block would have stopped
                           these (ALLOW + ALERT + LOG actions).

    Semantic note (ADR-0012): Suricata IDS events carry action='ALERT'
    (detected, not stopped); they are counted in ``unblocked_events`` — this is
    correct because they were NOT blocked.  The count is source-agnostic.

    When ``total_events == 0`` the IP has no stored events; the UI should render
    nothing or an honest zero — never a fabricated count.
    When ``blocked_events == total_events`` all events were already blocked;
    the UI should say so rather than showing a bare "0".

    Window: all stored events for the IP (no time bound; consistent with the
    ThreatScore fields displayed on the recommendation card).
    """

    total_events: int = Field(description="Total events stored for this IP.")
    blocked_events: int = Field(description="Events already stopped (BLOCK/DROP).")
    unblocked_events: int = Field(
        description=(
            "Events that got through (ALLOW/ALERT/LOG) — "
            "what a block would have stopped."
        )
    )


class EvidenceChainResponse(BaseModel):
    """Response envelope for ``GET /threats/{ip}/evidence`` (ADR-0041 / issue #387).

    Returns the evidence chain recomputed at read time from stored ``logs`` rows.
    Each entry in ``factors`` corresponds to one score-breakdown factor and lists
    the ``logs`` row ids that contributed to it.

    ``source_ip``   — the queried IP address.
    ``factors``     — one evidence item per breakdown factor (same order as
                      ``score_breakdown`` on the ThreatScore).  Rule factors carry
                      ``FactorEvidence`` shapes; ``ai_boost`` carries
                      ``AiBoostEvidence`` (a stored-artifact reference, no LLM call).
    ``recomputed``  — always ``True``; reminds callers that events arriving after
                      scoring may shift the contributing row sets (ADR-0041
                      read-time semantics).

    Route: ``GET /threats/{ip}/evidence`` (registered in ADR-0029 route catalogue).
    Read-only: no writes, no AI calls, no sample building (ai-engine-invariants).
    """

    source_ip: str = Field(description="The queried IP address.")
    factors: list[dict[str, Any]] = Field(
        description=(
            "Per-factor evidence items. Rule factors list contributing log_row_ids; "
            "ai_boost is a stored-artifact reference (no LLM call, ADR-0041)."
        )
    )
    recomputed: bool = Field(
        default=True,
        description=(
            "Always True — evidence is recomputed at read time from stored rows "
            "(ADR-0041). Events arriving after scoring may shift the contributing sets."
        ),
    )


class IPEventTimelineResponse(BaseModel):
    """Response envelope for ``GET /threats/{ip}/events``.

    ``events``      — time-ordered list of cross-source events (ascending).
    ``total``       — total events returned (after cap).
    ``correlated``  — True when events span more than one source_type.
    ``source_types``— distinct source types seen for this IP.
    ``capped``      — True when the store had more events than the cap; result is truncated.
    """

    events: list[TimelineEventItem] = Field(description="Time-ordered cross-source events.")
    total: int = Field(description="Number of events in this response (after cap).")
    correlated: bool = Field(
        default=False, description="True when events span more than one source_type."
    )
    source_types: list[str] = Field(
        default_factory=list, description="Distinct source types seen."
    )
    capped: bool = Field(
        default=False,
        description="True when the store had more events than the cap; result is truncated.",
    )


# ---------------------------------------------------------------------------
# Entity-graph shapes (ML-8, issue #436, ADR-0029 D1)
# ---------------------------------------------------------------------------


class GraphNode(BaseModel):
    """One node in the entity graph.

    ``type``  — entity kind: ``"ip"`` | ``"asn"`` | ``"category"``.
    ``id``    — stable identifier for the node (IP string, ``"asn:<N>"``,
                or ``"cat:<value>"``).  Used as the edge endpoint key.
    ``label`` — human-readable display string (equals ``id`` for IPs;
                ``"<as_name> (AS<N>)"`` for ASN nodes when as_name is
                available; the raw category value for category nodes).

    SECURITY (ADR-0029 D3): ``id`` and ``label`` for IP and category nodes
    originate from attacker-controlled telemetry.  Consumers MUST render them
    as text nodes only — no HTML interpolation.
    """

    type: str = Field(
        description="Entity kind: 'ip' | 'asn' | 'category'.",
    )
    id: str = Field(
        description="Stable node identifier (IP, 'asn:<N>', or 'cat:<value>').",
    )
    label: str = Field(
        description="Human-readable display string.",
    )


class GraphEdge(BaseModel):
    """One directed edge in the entity graph.

    ``source`` — id of the source node.
    ``target`` — id of the target node.
    ``weight`` — event count for this relationship (positive integer).
    ``kind``   — edge type: ``"flow"`` (src IP → dst IP),
                 ``"asn"`` (IP → ASN), or ``"category"`` (IP → category).
    """

    source: str = Field(description="Source node id.")
    target: str = Field(description="Target node id.")
    weight: int = Field(description="Event count for this relationship.")
    kind: str = Field(
        description="Edge type: 'flow' | 'asn' | 'category'.",
    )


class EntityGraphResponse(BaseModel):
    """Response envelope for ``GET /logs/graph`` (ML-8, issue #436).

    Returns a bounded node+edge graph connecting source IPs, destination IPs,
    ASNs, and attack categories.  The graph is the link-analysis substrate for
    the ML-9 render.

    ``nodes``     — deduplicated list of ``GraphNode`` items.
    ``edges``     — list of ``GraphEdge`` items, ranked by weight descending
                    within each edge kind.
    ``truncated`` — ``True`` when raw cardinality exceeded ``max_nodes`` or
                    ``max_edges``; the returned subgraph is the highest-weight
                    subset (EARS-3).

    Bounding strategy: the builder caps flow edges at ``max_edges`` (default
    500) and total nodes at ``max_nodes`` (default 200).  Both caps are
    request-overridable within the API's validated range.  NULL destination_ip
    rows are excluded from flow edges (EARS-2).

    SECURITY (ADR-0029 D3): node ids/labels that originate from telemetry are
    attacker-controlled.  Consumers MUST render them as plain text.
    """

    nodes: list[GraphNode] = Field(description="Deduplicated entity nodes.")
    edges: list[GraphEdge] = Field(description="Directed weighted edges.")
    truncated: bool = Field(
        default=False,
        description=(
            "True when raw cardinality exceeded the cap; "
            "returned subgraph is the highest-weight subset (EARS-3)."
        ),
    )


# ---------------------------------------------------------------------------
# Narration shape (ML-7, issue #435, ADR-0035)
# ---------------------------------------------------------------------------


class NarrationResponse(BaseModel):
    """Response envelope for ``GET /threats/{ip}/narration`` (ML-7, issue #435).

    Returns a SHORT narrative grounded ONLY in the IP's real collected fields.

    Anti-fabrication (EARS-3 / ADR-0035):
    - ``narrative``        — text generated by the local LLM (or rule-only fallback).
    - ``provenance``       — ADR-0035 tag: "rule" | "ai" | "ai+rule".
                            "rule" when the LLM was not called (AI unavailable or
                            explicitly skipped); "ai" or "ai+rule" when the LLM produced
                            the narrative.
    - ``collected_fields`` — list of field names actually used to build the prompt.
                            Fields that were NULL/absent are NOT listed.
    - ``ai_status``        — pipeline ai_status at time of this call.
    - ``source_ip``        — the queried IP address.

    Route: ``GET /threats/{ip}/narration`` (ML-7).
    Reuses the ``/threats/{ip}/detailed`` + ``score_breakdown`` path; no new scoring.
    """

    source_ip: str = Field(description="The queried IP address.")
    narrative: str = Field(
        description=(
            "Short (≤ 120 words) narrative grounded in collected fields only. "
            "Advisory — no SOAR/execution actions."
        )
    )
    provenance: str = Field(
        description="ADR-0035 derivation tag: 'rule' | 'ai' | 'ai+rule'.",
    )
    collected_fields: list[str] = Field(
        default_factory=list,
        description=(
            "Field names used to build the prompt / narrative. "
            "Fields that were NULL/absent are NOT listed (anti-fabrication, EARS-3)."
        ),
    )
    ai_status: str = Field(
        description=(
            "Pipeline ai_status: 'ok' (LLM ran), 'unavailable' (offline/degraded), "
            "'skipped' (caller passed ai=false), 'disabled'."
        )
    )
