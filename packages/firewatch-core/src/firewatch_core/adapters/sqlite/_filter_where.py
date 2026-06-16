"""Shared WHERE-clause builder for log-aggregate queries (issue #662).

This module extracts the shared predicate construction used by
``get_paginated`` (in ``events.py``) into a reusable helper so that
``get_top_talkers``, ``get_protocol_mix``, ``get_top_pairs``, and
``build_entity_graph`` all apply the **identical** SQL predicate.

Security invariant (B1):
  ``build_filter_where`` appends ONLY static string literals to
  ``conditions``.  Every caller-supplied value is bound via a ``?``
  placeholder collected in ``params``.  The WHERE fragment is safe to
  join into a SQL string because no element ever originates from
  attacker-controlled input.

The helper does NOT build the pagination cursor predicate
(``(timestamp < ? OR …)``), which is meaningful only for ``get_paginated``
and has no equivalent semantics for bounded top-N aggregations.

``anomaly_type`` is also excluded: the EXISTS subquery it generates uses
``l.`` table-alias references (``av.src_ip = l.source_ip``) that are only
valid in the ``get_paginated`` context where the logs table is aliased as
``l``.  Aggregation queries reference the table without an alias.

Exposed API:
    build_filter_where(
        filters: FilterSpec | None,
        *,
        start: str | None = None,
        end:   str | None = None,
    ) -> tuple[str, list[Any]]
        Returns ``(where_clause, params)`` where ``where_clause`` is either
        an empty string (no predicates) or a ``"WHERE …"`` fragment ready
        to embed in a SELECT.

Imports only ``firewatch-sdk``; never ``legacy/``.
"""
from __future__ import annotations

from typing import Any

from firewatch_sdk.models import FilterSpec

from ._base import (
    _BLOCKED_SQL_FRAG,
    _PAGINATED_CONTAINS_MAP,
    _PAGINATED_PREFIX_MAP,
)


def build_filter_where(
    filters: FilterSpec | None,
    *,
    start: str | None = None,
    end: str | None = None,
) -> tuple[str, list[Any]]:
    """Build a parameterised WHERE clause from a ``FilterSpec`` and optional time range.

    Args:
        filters: Optional ``FilterSpec`` instance.  ``None`` or an empty
            ``FilterSpec()`` produces an empty clause (no filtering).
        start:  Optional ISO-8601 datetime string for ``timestamp >= ?``.
        end:    Optional ISO-8601 datetime string for ``timestamp <= ?``.

    Returns:
        A ``(where_clause, params)`` tuple where:
          - ``where_clause`` is ``""`` (no predicates) or ``"WHERE <cond> AND …"``.
          - ``params`` is a list of bound values corresponding to every
            ``?`` placeholder in ``where_clause``, in order.

    Security (B1 invariant):
        ``conditions`` contains only static string literals defined in this
        module.  No element ever originates from caller input.  All caller
        values flow through ``?`` placeholders in ``params``.
    """
    f = filters  # may be None

    conditions: list[str] = []
    params: list[Any] = []

    if f is not None:
        # -- Category filter (same resolution order as get_paginated) --
        # 1. None / "all"  -> no filter
        # 2. legacy shorthand -> rule_id LIKE (compat alias)
        # 3. else -> exact match on stored category column
        if f.category and f.category != "all":
            if f.category in _PAGINATED_PREFIX_MAP:
                conditions.append("rule_id LIKE ?")
                params.append(_PAGINATED_PREFIX_MAP[f.category] + "%")
            elif f.category in _PAGINATED_CONTAINS_MAP:
                conditions.append("rule_id LIKE ?")
                params.append("%" + _PAGINATED_CONTAINS_MAP[f.category] + "%")
            else:
                conditions.append("category = ?")
                params.append(f.category)

        # Exact-match category_name (DEPRECATED synonym)
        if f.category_name:
            conditions.append("category = ?")
            params.append(f.category_name)

        # IP substring match on source_ip
        if f.ip:
            conditions.append("source_ip LIKE ?")
            params.append("%" + f.ip + "%")

        # Rule substring match on rule_id
        if f.rule:
            conditions.append("rule_id LIKE ?")
            params.append("%" + f.rule + "%")

        # Action filter.
        # "blocked" shorthand / "BLOCK" -> BLOCK+DROP (BLOCKED_SQL_FRAG, no params).
        # Other values -> exact match via placeholder.
        if f.action:
            if f.action.lower() == "blocked" or f.action.upper() == "BLOCK":
                conditions.append(_BLOCKED_SQL_FRAG)
            else:
                conditions.append("action = ?")
                params.append(f.action.upper())

        # Severity exact match (lower-cased for normalisation)
        if f.severity:
            conditions.append("severity = ?")
            params.append(f.severity.lower())

        # ML-3 -- destination_ip substring filter
        if f.destination_ip:
            conditions.append("destination_ip LIKE ?")
            params.append("%" + f.destination_ip + "%")

        # ML-3 -- protocol exact match
        if f.protocol:
            conditions.append("protocol = ?")
            params.append(f.protocol)

        # ML-13 -- tls_ja4 exact match (consume-only)
        if f.tls_ja4:
            conditions.append("tls_ja4 = ?")
            params.append(f.tls_ja4)

        # ADR-0055 -- file_sha256 exact match
        if f.file_sha256:
            conditions.append("file_sha256 = ?")
            params.append(f.file_sha256)

        # ADR-0055 -- dns_answer exact match
        if f.dns_answer:
            conditions.append("dns_answer = ?")
            params.append(f.dns_answer)

        # Source identity filters (ADR-0016)
        if f.source_type:
            conditions.append("source_type = ?")
            params.append(f.source_type)

        if f.source_id:
            conditions.append("source_id = ?")
            params.append(f.source_id)

        # Free-text search (same as get_paginated)
        if f.q:
            q_clause = (
                "(source_ip LIKE ? OR rule_id LIKE ? OR payload_snippet LIKE ?"
                " OR rule_id IN ("
                "SELECT key FROM source_kv"
                " WHERE source_type = '_global'"
                " AND namespace = 'rule_descriptions'"
                " AND value LIKE ?"
                "))"
            )
            like = "%" + f.q + "%"
            conditions.append(q_clause)
            params.extend([like, like, like, like])

    # Timestamp range (not in FilterSpec — threaded as separate params)
    if start:
        conditions.append("timestamp >= ?")
        params.append(start)
    if end:
        conditions.append("timestamp <= ?")
        params.append(end)

    # B1 safety invariant: every element of ``conditions`` is a static
    # string literal defined above.  No element originates from caller input.
    # All caller values flow through ? placeholders in params.
    assert all(isinstance(c, str) for c in conditions), (
        "BUG: conditions must contain only static string literals"
    )

    if not conditions:
        return "", []

    where_clause = "WHERE " + " AND ".join(conditions)
    return where_clause, params
