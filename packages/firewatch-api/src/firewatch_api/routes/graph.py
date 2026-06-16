"""Graph routes — GET /logs/graph (ML-8, issue #436, ADR-0029 D1).

Returns an entity graph connecting source IP → destination IP → ASN → category,
bounded by cardinality caps.  Pure read; no writes or AI calls.

EARS-1  GET /logs/graph returns nodes (IP, ASN, category) and edges (flow,
        asn, category) bounded by max_nodes / max_edges.
EARS-2  Edges use only canonical/persisted fields: destination_ip (ML-1) and
        ASN from ip_geo (populated by the geo enricher — NB-6/issue #211).
        NULL destination_ip rows are excluded from flow edges.
EARS-3  When cardinality exceeds the cap, the response is the highest-weight
        subgraph with ``truncated=True``.

Security note (ADR-0029 D3): node ids/labels that originate from stored
telemetry are attacker-controlled.  Consumers MUST render them as plain text —
no HTML interpolation, no dangerouslySetInnerHTML.

``max_nodes`` and ``max_edges`` are validated/capped by FastAPI's Query
constraints and further coerced to positive ints inside the builder
(defense-in-depth; safe even if the API validation is bypassed).

Imports only firewatch-sdk and firewatch-core. Never imports legacy/.
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query

from firewatch_sdk.models import FilterSpec

from firewatch_core.analytics.entity_graph import (
    DEFAULT_MAX_EDGES,
    DEFAULT_MAX_NODES,
    build_entity_graph,
)

from firewatch_api.deps import get_event_store, logs_filterspec
from firewatch_api.schemas import EntityGraphResponse

logger = logging.getLogger("firewatch.api.graph")

router = APIRouter(prefix="/logs", tags=["logs"])

#: Hard ceiling on max_nodes accepted via query param.
_MAX_NODES_CEILING: int = 1000
#: Hard ceiling on max_edges accepted via query param.
_MAX_EDGES_CEILING: int = 2000


def _require_store(store: Any) -> Any:
    """Raise 503 if the event store is not available."""
    if store is None:
        raise HTTPException(status_code=503, detail="Event store not available")
    return store


@router.get(
    "/graph",
    summary="Entity graph: IP→dst→ASN→category link-analysis substrate (ML-8, issue #436)",
    response_model=EntityGraphResponse,
)
async def get_entity_graph(
    max_nodes: int = Query(
        default=DEFAULT_MAX_NODES,
        ge=1,
        le=_MAX_NODES_CEILING,
        description=(
            f"Maximum number of nodes to return "
            f"(1–{_MAX_NODES_CEILING}, default {DEFAULT_MAX_NODES})."
        ),
    ),
    max_edges: int = Query(
        default=DEFAULT_MAX_EDGES,
        ge=1,
        le=_MAX_EDGES_CEILING,
        description=(
            f"Maximum number of edges to return "
            f"(1–{_MAX_EDGES_CEILING}, default {DEFAULT_MAX_EDGES})."
        ),
    ),
    filters: FilterSpec = Depends(logs_filterspec),
    store: Any = Depends(get_event_store),
) -> dict[str, Any]:
    """Return a bounded entity graph of observed network flows.

    Nodes: source IPs, destination IPs (non-NULL only), ASNs (from ip_geo),
    attack categories (from logs.category).

    Edges:
      ``flow``     — source_ip → destination_ip (weight = event count).
      ``asn``      — IP → ASN (weight = 1 per distinct IP/ASN pair).
      ``category`` — source_ip → category (weight = event count).

    Flow edges are ranked by weight descending so the most-significant links
    survive truncation (EARS-3).  NULL destination_ip rows are excluded from
    flow edges (EARS-2).

    When ``max_nodes`` or ``max_edges`` is exceeded, ``truncated=True`` is set
    in the response.

    Returns 503 when the event store is unavailable.
    Returns 422 when ``max_nodes`` or ``max_edges`` is out of the valid range.

    SECURITY (ADR-0029 D3): node ids/labels from telemetry are attacker-
    controlled.  Render as plain text only.
    """
    _require_store(store)
    return await build_entity_graph(  # type: ignore[return-value]
        store,
        max_nodes=max_nodes,
        max_edges=max_edges,
        filters=filters,
    )
