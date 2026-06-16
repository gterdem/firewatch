"""Entity-graph builder — IP/ASN/category link-analysis substrate (ML-8, issue #436).

Aggregates stored events into a bounded node+edge graph suitable for link-analysis
rendering (ML-9).  The graph connects four entity types:

  source_ip  → (flow)      → destination_ip
  source_ip  → (asn)       → ASN          (via ip_geo table)
  source_ip  → (category)  → category     (via logs.category column)

Design decisions
----------------
* **Read-only, parameterized SQL only.**  All LIMIT clauses bind values via the
  ``?`` placeholder — never f-string interpolated — so the query is
  safe-by-construction even if a future caller bypasses the API's integer
  validation.  The store's ``_read_conn()`` method provides a read-only
  connection (#313).
* **Bounded by default.**  Uncapped graphs can be enormous on a busy sensor;
  ``max_edges`` and ``max_nodes`` keep the HTTP response bounded.  Edges are
  ranked by weight (event count) descending so the most-significant links
  survive truncation.  The ``truncated`` flag in the result is honest: ``True``
  iff cardinality was cut.
* **NULL destination_ip exclusion (EARS-2).**  Rows where ``destination_ip`` is
  NULL carry no destination-dimension signal (e.g. Azure WAF L7-only events).
  They are excluded from flow edges — never coerced to a placeholder.
* **ASN comes from ip_geo (EARS-2).**  ASN fields (``asn`` / ``as_name``) were
  added to ``ip_geo`` in NB-6 (issue #211).  They are NULL for IPs cached
  before NB-6 or for IPs whose geo row has no ASN; those IPs produce no ASN
  node.

Node shape:  ``{type: str, id: str, label: str}``
Edge shape:  ``{source: str, target: str, weight: int, kind: str}``
Result:      ``{nodes: list, edges: list, truncated: bool}``

Imports only ``firewatch-sdk``; no ``legacy/``.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from firewatch_sdk.models import FilterSpec

from firewatch_core.adapters.sqlite._filter_where import build_filter_where

if TYPE_CHECKING:
    # Avoid a hard runtime import; the builder accepts any store-conforming
    # object that exposes the ``_read_conn`` coroutine method.
    from firewatch_core.adapters.sqlite_store import SQLiteEventStore

logger = logging.getLogger("firewatch.core.analytics.entity_graph")

# ---------------------------------------------------------------------------
# Public constants — callers may reference these for their own cap logic.
# ---------------------------------------------------------------------------

#: Default maximum number of nodes in the returned graph.
DEFAULT_MAX_NODES: int = 200

#: Default maximum number of edges in the returned graph.
DEFAULT_MAX_EDGES: int = 500


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def build_entity_graph(
    store: "SQLiteEventStore",
    *,
    max_nodes: int = DEFAULT_MAX_NODES,
    max_edges: int = DEFAULT_MAX_EDGES,
    filters: FilterSpec | None = None,
    start: str | None = None,
    end: str | None = None,
) -> dict[str, Any]:
    """Aggregate stored events into a bounded entity graph.

    Args:
        store: A ``SQLiteEventStore`` instance (or any compatible store that
            exposes ``_read_conn()``).
        max_nodes: Maximum number of distinct nodes to include.  Nodes are
            collected in insertion-priority order (IPs first, then ASN, then
            category).  When ``max_nodes`` is reached, remaining node types
            are omitted.
        max_edges: Maximum number of edges to include.  Flow edges are ranked
            by weight descending; ASN and category edges share the remaining
            budget.
        filters: Optional ``FilterSpec`` to scope the graph to matching rows.
            ``None`` or an empty ``FilterSpec()`` preserves the pre-change
            unfiltered behaviour (golden parity, EARS-3).
        start: Optional ISO-8601 datetime string for ``timestamp >= ?``.
        end:   Optional ISO-8601 datetime string for ``timestamp <= ?``.

    Returns:
        A dict with keys:
          ``nodes``    — list of ``{type, id, label}`` dicts (deduplicated).
          ``edges``    — list of ``{source, target, weight, kind}`` dicts.
          ``truncated``— ``True`` iff the raw cardinality exceeded the caps.
    """
    # Defense-in-depth: coerce to positive ints and bind via ? (not f-string).
    safe_max_nodes = max(1, int(max_nodes))
    safe_max_edges = max(1, int(max_edges))

    db = await store._read_conn()

    # Build the shared WHERE clause once; pass (where_sql, params) to every helper.
    where_sql, where_params = build_filter_where(filters, start=start, end=end)

    flow_edges = await _fetch_flow_edges(db, safe_max_edges, where_sql, where_params)
    asn_edges = await _fetch_asn_edges(db, where_sql, where_params)
    category_edges = await _fetch_category_edges(db, where_sql, where_params)

    # Truncation detection: we fetch up to max_edges + 1 to know if more exist.
    # _fetch_flow_edges returns at most max_edges rows; we detect truncation
    # by checking the raw count from a count query.
    flow_total = await _count_flow_edges(db, where_sql, where_params)
    asn_total = await _count_asn_edges(db, where_sql, where_params)
    cat_total = await _count_category_edges(db, where_sql, where_params)

    # Assemble the edge list: flow first (already ranked by weight), then ASN,
    # then category.  Apply the combined max_edges budget.
    all_edges: list[dict[str, Any]] = flow_edges + asn_edges + category_edges
    edges = all_edges[:safe_max_edges]

    raw_edge_count = flow_total + asn_total + cat_total
    truncated = (
        raw_edge_count > safe_max_edges
        or len(all_edges) > safe_max_edges
    )

    # Collect unique nodes referenced by the (potentially truncated) edge list.
    nodes = _collect_nodes(edges, safe_max_nodes)

    # Fetch ASN metadata for node labels.
    asn_meta = await _fetch_asn_meta(db)

    # Enrich ASN nodes with labels from ip_geo.
    _enrich_asn_node_labels(nodes, asn_meta)

    truncated = truncated or (len(_collect_nodes(all_edges, 10_000)) > safe_max_nodes)

    return {
        "nodes": nodes,
        "edges": edges,
        "truncated": truncated,
    }


# ---------------------------------------------------------------------------
# Private helpers — SQL queries
# ---------------------------------------------------------------------------


async def _fetch_flow_edges(
    db: Any,
    max_edges: int,
    where_sql: str,
    where_params: list[Any],
) -> list[dict[str, Any]]:
    """Return top-(src_ip, dst_ip) flow edges ordered by count desc.

    NULL / empty destination_ip rows are excluded (EARS-2).
    LIMIT is bound via ? placeholder.  The shared ``where_sql`` / ``where_params``
    from ``build_filter_where`` are composed with the dest-guard condition.
    """
    dest_guard = "destination_ip IS NOT NULL AND destination_ip != ''"
    if where_sql:
        # where_sql starts with "WHERE "; strip it and compose with dest_guard.
        extra = where_sql[len("WHERE "):]
        combined_where = f"WHERE {dest_guard} AND {extra}"
    else:
        combined_where = f"WHERE {dest_guard}"
    sql = (
        "SELECT source_ip, destination_ip, COUNT(*) AS weight"
        f" FROM logs {combined_where}"
        " GROUP BY source_ip, destination_ip"
        " ORDER BY weight DESC"
        " LIMIT ?"
    )
    cursor = await db.execute(sql, (*where_params, max(1, int(max_edges))))
    rows = await cursor.fetchall()
    return [
        {
            "source": r["source_ip"],
            "target": r["destination_ip"],
            "weight": int(r["weight"]),
            "kind": "flow",
        }
        for r in rows
    ]


async def _count_flow_edges(
    db: Any,
    where_sql: str,
    where_params: list[Any],
) -> int:
    """Count distinct (src, dst) pairs with non-NULL destination_ip."""
    dest_guard = "destination_ip IS NOT NULL AND destination_ip != ''"
    if where_sql:
        extra = where_sql[len("WHERE "):]
        combined_where = f"WHERE {dest_guard} AND {extra}"
    else:
        combined_where = f"WHERE {dest_guard}"
    sql = (
        "SELECT COUNT(*) AS cnt FROM ("
        f"  SELECT source_ip, destination_ip FROM logs {combined_where}"
        "  GROUP BY source_ip, destination_ip"
        ")"
    )
    cursor = await db.execute(sql, where_params)
    row = await cursor.fetchone()
    return int(row["cnt"]) if row else 0


async def _fetch_asn_edges(
    db: Any,
    where_sql: str,
    where_params: list[Any],
) -> list[dict[str, Any]]:
    """Return ip→asn edges for IPs that have a non-NULL ASN in ip_geo.

    ip_geo is keyed on IP; the join surfaces the ASN for each distinct IP
    that appears in logs and has a geo row with a non-NULL asn.
    The shared WHERE predicate (if any) is applied to the logs side of the join
    so that a source_type or severity filter correctly scopes the ASN edges.
    """
    asn_guard = "g.asn IS NOT NULL"
    if where_sql:
        # where_sql predicates reference bare column names from logs; they are
        # valid on the aliased ``l`` side of the join without modification.
        extra = where_sql[len("WHERE "):]
        combined_where = f"WHERE {asn_guard} AND {extra}"
    else:
        combined_where = f"WHERE {asn_guard}"
    sql = (
        "SELECT DISTINCT l.source_ip, g.asn"
        " FROM logs l"
        f" JOIN ip_geo g ON l.source_ip = g.ip {combined_where}"
    )
    cursor = await db.execute(sql, where_params)
    rows = await cursor.fetchall()
    return [
        {
            "source": r["source_ip"],
            "target": f"asn:{r['asn']}",
            "weight": 1,
            "kind": "asn",
        }
        for r in rows
    ]


async def _count_asn_edges(
    db: Any,
    where_sql: str,
    where_params: list[Any],
) -> int:
    """Count distinct ip→asn edges."""
    asn_guard = "g.asn IS NOT NULL"
    if where_sql:
        extra = where_sql[len("WHERE "):]
        combined_where = f"WHERE {asn_guard} AND {extra}"
    else:
        combined_where = f"WHERE {asn_guard}"
    sql = (
        "SELECT COUNT(*) AS cnt FROM ("
        "  SELECT DISTINCT l.source_ip, g.asn"
        "  FROM logs l"
        f"  JOIN ip_geo g ON l.source_ip = g.ip {combined_where}"
        ")"
    )
    cursor = await db.execute(sql, where_params)
    row = await cursor.fetchone()
    return int(row["cnt"]) if row else 0


async def _fetch_category_edges(
    db: Any,
    where_sql: str,
    where_params: list[Any],
) -> list[dict[str, Any]]:
    """Return ip→category edges from logs.category (canonical stored value).

    Only rows where category IS NOT NULL and not empty are included.
    Weight is the event count for (source_ip, category).
    """
    cat_guard = "category IS NOT NULL AND category != ''"
    if where_sql:
        extra = where_sql[len("WHERE "):]
        combined_where = f"WHERE {cat_guard} AND {extra}"
    else:
        combined_where = f"WHERE {cat_guard}"
    sql = (
        "SELECT source_ip, category, COUNT(*) AS weight"
        f" FROM logs {combined_where}"
        " GROUP BY source_ip, category"
        " ORDER BY weight DESC"
    )
    cursor = await db.execute(sql, where_params)
    rows = await cursor.fetchall()
    return [
        {
            "source": r["source_ip"],
            "target": f"cat:{r['category']}",
            "weight": int(r["weight"]),
            "kind": "category",
        }
        for r in rows
    ]


async def _count_category_edges(
    db: Any,
    where_sql: str,
    where_params: list[Any],
) -> int:
    """Count distinct ip→category edges."""
    cat_guard = "category IS NOT NULL AND category != ''"
    if where_sql:
        extra = where_sql[len("WHERE "):]
        combined_where = f"WHERE {cat_guard} AND {extra}"
    else:
        combined_where = f"WHERE {cat_guard}"
    sql = (
        "SELECT COUNT(*) AS cnt FROM ("
        f"  SELECT source_ip, category FROM logs {combined_where}"
        "  GROUP BY source_ip, category"
        ")"
    )
    cursor = await db.execute(sql, where_params)
    row = await cursor.fetchone()
    return int(row["cnt"]) if row else 0


async def _fetch_asn_meta(db: Any) -> dict[int, str]:
    """Return {asn_int: as_name} for all non-NULL ASNs in ip_geo."""
    sql = "SELECT DISTINCT asn, as_name FROM ip_geo WHERE asn IS NOT NULL"
    cursor = await db.execute(sql)
    rows = await cursor.fetchall()
    return {
        int(r["asn"]): (r["as_name"] or "")
        for r in rows
    }


# ---------------------------------------------------------------------------
# Private helpers — node collection / enrichment
# ---------------------------------------------------------------------------


def _collect_nodes(
    edges: list[dict[str, Any]], max_nodes: int
) -> list[dict[str, Any]]:
    """Derive a deduplicated node list from the edge list, bounded by max_nodes.

    Node type is inferred from the id prefix:
      ``asn:<N>``  → type ``asn``
      ``cat:<V>``  → type ``category``
      otherwise    → type ``ip``

    Labels are id-based by default; ASN labels are enriched separately
    by ``_enrich_asn_node_labels``.
    """
    seen: dict[str, dict[str, Any]] = {}
    for edge in edges:
        for node_id in (edge["source"], edge["target"]):
            if node_id not in seen:
                seen[node_id] = _make_node(node_id)
    # Truncate to max_nodes — order is insertion order (dict is ordered in 3.7+).
    node_list = list(seen.values())[:max_nodes]
    return node_list


def _make_node(node_id: str) -> dict[str, Any]:
    """Build a bare node dict from its id."""
    if node_id.startswith("asn:"):
        return {"type": "asn", "id": node_id, "label": node_id}
    if node_id.startswith("cat:"):
        label = node_id[len("cat:"):]
        return {"type": "category", "id": node_id, "label": label}
    return {"type": "ip", "id": node_id, "label": node_id}


def _enrich_asn_node_labels(
    nodes: list[dict[str, Any]],
    asn_meta: dict[int, str],
) -> None:
    """Mutate ASN nodes in-place to add a human-readable label.

    Label format: ``"<as_name> (AS<asn>)"`` when as_name is non-empty,
    else ``"AS<asn>"``.
    """
    for node in nodes:
        if node["type"] != "asn":
            continue
        asn_str = node["id"][len("asn:"):]
        try:
            asn_int = int(asn_str)
        except ValueError:
            continue
        as_name = asn_meta.get(asn_int, "")
        node["label"] = (
            f"{as_name} (AS{asn_int})" if as_name else f"AS{asn_int}"
        )
