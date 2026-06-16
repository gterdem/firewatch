"""_EventsMixin — logs table writes + row-level reads."""
from __future__ import annotations

from datetime import datetime
from typing import Any

import aiosqlite

from firewatch_sdk.models import FilterSpec, SecurityEvent

from ._base import (
    _BLOCKED_SQL_FRAG,
    _PAGINATED_CONTAINS_MAP,
    _PAGINATED_PREFIX_MAP,
    _row_to_security_event,
)


class _EventsMixin:
    """Handles save_many, get_by_ip*, get_recent, and get_paginated."""

    # Provided by _SchemaMixin — declared here only for type-checkers.
    async def _conn(self) -> aiosqlite.Connection: ...  # pragma: no cover
    async def _read_conn(self) -> aiosqlite.Connection: ...  # pragma: no cover

    async def save_many(self, events: list[SecurityEvent]) -> int:
        """Persist events, skipping duplicates via the UNIQUE index.

        Returns the number of rows actually inserted (post-dedup).
        """
        if not events:
            return 0
        db = await self._conn()
        async with self._write_lock:  # type: ignore[attr-defined]
            before_row = await (
                await db.execute("SELECT COUNT(*) FROM logs")
            ).fetchone()
            before: int = before_row[0] if before_row else 0

            rows = [
                (
                    e.source_ip,
                    e.destination_port if e.destination_port is not None else 0,
                    e.destination_ip,
                    e.protocol or "",
                    e.action,
                    e.rule_id,
                    e.rule_name,
                    e.payload_snippet,
                    e.timestamp.isoformat(),
                    e.source_type,
                    e.source_id,
                    e.severity,
                    e.category,
                    e.bytes_in,
                    e.bytes_out,
                    e.packets_in,
                    e.packets_out,
                    e.flow_duration_ms,
                    e.dns_query,
                    e.dns_rcode,
                    e.tls_ja4,
                    e.tls_ja4s,
                    e.tls_sni,
                    e.tls_version,
                    e.http_method,
                    e.http_host,
                    e.http_url,
                    e.http_user_agent,
                    # ADR-0055 Group E — file IOC (OCSF File.hashes[]/ECS file.hash.*)
                    e.file_sha256,
                    e.file_md5,
                    e.file_sha1,
                    e.file_name,
                    e.file_mime_type,
                    # ADR-0055 Group F — DNS answer (OCSF DNS Activity answers[].rdata)
                    e.dns_answer,
                    # ADR-0055 Group G — JA3 fingerprint (ECS tls.client.ja3)
                    e.tls_ja3,
                )
                for e in events
            ]
            await db.executemany(
                """
                INSERT OR IGNORE INTO logs
                    (source_ip, destination_port, destination_ip, protocol, action,
                     rule_id, rule_name, payload_snippet, timestamp,
                     source_type, source_id, severity, category,
                     bytes_in, bytes_out, packets_in, packets_out, flow_duration_ms,
                     dns_query, dns_rcode,
                     tls_ja4, tls_ja4s, tls_sni, tls_version,
                     http_method, http_host, http_url, http_user_agent,
                     file_sha256, file_md5, file_sha1, file_name, file_mime_type,
                     dns_answer, tls_ja3)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
            await db.commit()

            after_row = await (
                await db.execute("SELECT COUNT(*) FROM logs")
            ).fetchone()
            after: int = after_row[0] if after_row else 0
            return after - before

    async def get_by_ip(self, ip: str) -> list[SecurityEvent]:
        """Return all events for the given IP, ordered by timestamp ascending."""
        db = await self._read_conn()  # read-only — use dedicated read connection (#313)
        cursor = await db.execute(
            "SELECT * FROM logs WHERE source_ip = ? ORDER BY timestamp",
            (ip,),
        )
        rows = await cursor.fetchall()
        return [_row_to_security_event(dict(r)) for r in rows]

    async def get_by_ip_since(
        self, ip: str, cutoff: datetime
    ) -> list[SecurityEvent]:
        """Return events for *ip* at or after *cutoff*, ordered by timestamp ascending.

        Used by the escalation-policy route to derive 24h detection hit-counts
        (issue #650, ADR-0058 D1/D6, ADR-0059 D6).  *cutoff* is an aware UTC
        datetime; it is converted to ISO-8601 for the SQL ``?`` placeholder so
        the comparison is SQLite-safe and no interpolation occurs.

        Security note: both ``ip`` and the cutoff ISO string flow only through
        ``?`` placeholders — no interpolation.
        """
        db = await self._read_conn()  # read-only (#313)
        cursor = await db.execute(
            "SELECT * FROM logs WHERE source_ip = ? AND timestamp >= ? ORDER BY timestamp",
            (ip, cutoff.isoformat()),
        )
        rows = await cursor.fetchall()
        return [_row_to_security_event(dict(r)) for r in rows]

    async def get_events_with_row_ids(self, ip: str) -> list[dict[str, Any]]:
        """Return all events for *ip* as dicts that include the ``logs`` row ``id``.

        This is the additive read query for the evidence-chain builder (ADR-0041).
        The ``id`` column is the only stable per-event identifier in production
        (``SecurityEvent.event_id`` / ``Detection.matched_event_ids`` are empty —
        see ADR-0041 gap analysis).  Evidence is recomputed at read time from these
        rows; nothing is persisted.

        Returns dicts with at minimum:
          ``id``              — ``logs`` integer primary key (the stable event ref).
          ``timestamp``       — ISO-8601 UTC string.
          ``action``          — canonical action.
          ``destination_port``— destination port (may be 0 / None).
          ``rule_id``         — rule identifier (may be None).
          ``payload_snippet`` — payload (may be None).
          ``source_type``     — telemetry source type.
          ``category``        — attack category (may be None).

        Ordered ascending by ``(timestamp, id)`` — consistent with ``get_by_ip``.

        B5 safety invariant: ``ip`` flows only through a ``?`` placeholder.
        All selected columns are hard-coded static names.
        """
        db = await self._read_conn()  # read-only — use dedicated read connection (#313)
        cursor = await db.execute(
            """
            SELECT id, timestamp, action, destination_port,
                   rule_id, payload_snippet, source_type, category
            FROM logs
            WHERE source_ip = ?
            ORDER BY timestamp ASC, id ASC
            """,
            (ip,),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    async def get_events_for_timeline(
        self, ip: str, limit: int = 200
    ) -> list[dict[str, Any]]:
        """Return time-ordered cross-source events for *ip*, capped at *limit*.

        Used by ``GET /threats/{ip}/events`` (issue #118).  Returns only the
        canonical fields needed by the ``EventTimeline`` frontend component:
        ``source_type``, ``timestamp``, ``action``, ``rule_id``,
        ``category``, ``severity``, ``payload_snippet``.
        Note: ``rule_name`` is a SecurityEvent field but is not persisted to the
        ``logs`` table; callers use ``rule_id`` or ``category`` as the label.

        Ordered ascending by ``(timestamp, id)`` so the timeline renders
        chronologically.  The caller enforces the cap by passing ``limit + 1``
        internally to detect truncation, then slicing — but here we pass the
        cap directly and leave truncation detection to the caller passing
        ``limit + 1`` if desired.  For simplicity the route passes the cap as-is
        and sets ``capped=False`` unless the caller passes one more than needed.
        """
        db = await self._read_conn()  # read-only — use dedicated read connection (#313)
        # B4 safety invariant: ``ip`` flows only through a ``?`` placeholder;
        # ``limit`` is an integer (validated by the route layer ≥ 1) and is
        # embedded as a literal integer — never an f-string.  All columns
        # selected are hard-coded static names.
        # Note: ``rule_name`` is a SecurityEvent field but is NOT persisted to
        # the logs table (schema has only ``rule_id``).  The route layer uses
        # ``rule_id`` as the label fallback; no ``rule_name`` column is queried.
        cursor = await db.execute(
            """
            SELECT source_type, source_id, timestamp, action,
                   rule_id, category, severity, payload_snippet
            FROM logs
            WHERE source_ip = ?
            ORDER BY timestamp ASC, id ASC
            LIMIT ?
            """,
            (ip, limit),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    async def get_by_ip_raw(self, ip: str) -> list[dict[str, Any]]:
        """Return all logs for an IP as dicts (dashboard drill-down)."""
        db = await self._read_conn()  # read-only — use dedicated read connection (#313)
        cursor = await db.execute(
            "SELECT * FROM logs WHERE source_ip = ? ORDER BY timestamp DESC",
            (ip,),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    async def get_recent(self, limit: int = 100) -> list[dict[str, Any]]:
        """Most-recent logs, split 50/50 between attack and non-attack rows.

        Ported verbatim from legacy for golden-test parity.
        """
        db = await self._read_conn()  # read-only — use dedicated read connection (#313)
        half = limit // 2
        cursor = await db.execute(
            """
            SELECT * FROM (
                SELECT * FROM logs WHERE rule_id NOT IN ('RateLimitRule', '')
                ORDER BY timestamp DESC LIMIT ?
            )
            UNION ALL
            SELECT * FROM (
                SELECT * FROM logs WHERE rule_id IN ('RateLimitRule', '')
                ORDER BY timestamp DESC LIMIT ?
            )
            ORDER BY timestamp DESC
            """,
            (half, half),
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    async def get_paginated(
        self,
        limit: int = 500,
        filters: FilterSpec | None = None,
    ) -> dict[str, Any]:
        """Cursor-based paginated logs.  Returns the standard envelope dict.

        Supports all FilterSpec fields including source_type and source_id
        (ADR-0016).  Rule-id category filtering is ported from legacy for
        golden-test parity.
        """
        db = await self._read_conn()  # read-only — use dedicated read connection (#313)
        f = filters or FilterSpec()

        conditions: list[str] = []
        count_conditions: list[str] = []
        params: list[Any] = []
        count_params: list[Any] = []

        # Cursor (timestamp|id bookmark).
        # B3 safety invariant: only a well-formed cursor of the shape
        # "<iso_timestamp>|<integer_id>" is applied as a WHERE clause.
        # Any malformed value (wrong separator count, non-integer id, etc.)
        # is silently ignored so the caller receives the first page rather
        # than a ValueError.  The format is:  <anything>|<digits>
        if f.cursor:
            parts = f.cursor.split("|")
            if len(parts) == 2 and parts[1].lstrip("-").isdigit():
                conditions.append(
                    "(timestamp < ? OR (timestamp = ? AND id < ?))"
                )
                params.extend([parts[0], parts[0], int(parts[1])])

        # Category filter — resolution order (issue #325):
        # 1. None / "all"  → no filter (unchanged)
        # 2. legacy shorthand key (sqli/xss/…/geo) → rule_id LIKE (compat alias, unchanged)
        # 3. else → exact parameterized match on the stored ``category`` column.
        #
        # The silent-drop branch is eliminated: every non-"all" value now produces
        # a WHERE clause.  No canonical category value collides with the lowercase
        # legacy keys (e.g. "WAF Rule" vs "sqli"), so the priority order is safe.
        # All values flow through ? placeholders — no string interpolation (EARS-7).
        if f.category and f.category != "all":
            if f.category in _PAGINATED_PREFIX_MAP:
                cond = "rule_id LIKE ?"
                val = _PAGINATED_PREFIX_MAP[f.category] + "%"
                conditions.append(cond)
                params.append(val)
                count_conditions.append(cond)
                count_params.append(val)
            elif f.category in _PAGINATED_CONTAINS_MAP:
                cond = "rule_id LIKE ?"
                val = "%" + _PAGINATED_CONTAINS_MAP[f.category] + "%"
                conditions.append(cond)
                params.append(val)
                count_conditions.append(cond)
                count_params.append(val)
            else:
                # Canonical stored category — exact parameterized match (EARS-3).
                conditions.append("category = ?")
                params.append(f.category)
                count_conditions.append("category = ?")
                count_params.append(f.category)

        # Exact-match category_name
        if f.category_name:
            conditions.append("category = ?")
            params.append(f.category_name)
            count_conditions.append("category = ?")
            count_params.append(f.category_name)

        # IP substring
        if f.ip:
            conditions.append("source_ip LIKE ?")
            params.append("%" + f.ip + "%")
            count_conditions.append("source_ip LIKE ?")
            count_params.append("%" + f.ip + "%")

        # Rule substring
        if f.rule:
            conditions.append("rule_id LIKE ?")
            params.append("%" + f.rule + "%")
            count_conditions.append("rule_id LIKE ?")
            count_params.append("%" + f.rule + "%")

        # Action filter.
        # "blocked" shorthand (case-insensitive) → action IN ('BLOCK','DROP').
        # The definition of BLOCKED_ACTIONS lives in exactly one place at the
        # module level (issue #252); _BLOCKED_SQL_FRAG is derived from it.
        # Exact values (ALLOW/BLOCK/DROP/ALERT/…) keep their previous behaviour:
        # BLOCK still expands to BLOCK+DROP (legacy compat); other values are
        # matched exactly with a parameterised placeholder.
        if f.action:
            if f.action.lower() == "blocked" or f.action.upper() == "BLOCK":
                conditions.append(_BLOCKED_SQL_FRAG)
                count_conditions.append(_BLOCKED_SQL_FRAG)
            else:
                conditions.append("action = ?")
                params.append(f.action.upper())
                count_conditions.append("action = ?")
                count_params.append(f.action.upper())

        # Severity
        if f.severity:
            conditions.append("severity = ?")
            params.append(f.severity.lower())
            count_conditions.append("severity = ?")
            count_params.append(f.severity.lower())

        # ML-3 (issue #431) — destination_ip substring filter (EARS-1).
        # Parameterized LIKE so attacker-controlled values cannot escape the placeholder.
        if f.destination_ip:
            conditions.append("destination_ip LIKE ?")
            params.append("%" + f.destination_ip + "%")
            count_conditions.append("destination_ip LIKE ?")
            count_params.append("%" + f.destination_ip + "%")

        # ML-3 (issue #431) — protocol exact-match filter (EARS-1).
        # Exact match; value flows through a ? placeholder (B1 invariant).
        if f.protocol:
            conditions.append("protocol = ?")
            params.append(f.protocol)
            count_conditions.append("protocol = ?")
            count_params.append(f.protocol)

        # ML-13 (issue #441) — tls_ja4 exact-match filter (EARS-1).
        # JA4 fingerprint is an opaque string; exact match via ? placeholder.
        # Only non-null rows participate — null tls_ja4 means sensor did not emit JA4
        # (consume-only; no computation here, per ADR-0048 sub-decision).
        if f.tls_ja4:
            conditions.append("tls_ja4 = ?")
            params.append(f.tls_ja4)
            count_conditions.append("tls_ja4 = ?")
            count_params.append(f.tls_ja4)

        # ML-10 (issue #438) — anomaly_type inline-lane facet (EARS-2).
        # Filters to rows whose (source_ip, destination_ip, destination_port) triple
        # has a matching entry in anomaly_verdicts with the given anomaly_type.
        # Uses EXISTS subquery (correlated on l.* columns) — no JOIN needed, and the
        # subquery is short-circuiting.  dst_port NULL matching uses IS (not =) so
        # rows where destination_port IS NULL are included when the verdict was stored
        # with dst_port=NULL.  The anomaly_type value flows through a ? placeholder
        # (B1 invariant).  Extensible: ML-11 can store 'volumetric_exfil' verdicts and
        # this same filter will surface them with anomaly_type='volumetric_exfil'.
        if f.anomaly_type:
            exists_cond = (
                "EXISTS ("
                "SELECT 1 FROM anomaly_verdicts av"
                " WHERE av.src_ip = l.source_ip"
                " AND av.dst_ip = l.destination_ip"
                " AND av.dst_port IS l.destination_port"
                " AND av.anomaly_type = ?"
                ")"
            )
            conditions.append(exists_cond)
            params.append(f.anomaly_type)
            count_conditions.append(exists_cond)
            count_params.append(f.anomaly_type)

        # ADR-0055 (issue #602) — file_sha256 exact-match filter (EARS-3).
        # SHA-256 is an opaque hex string; exact match via ? placeholder (B1 invariant).
        # NULL file_sha256 rows are excluded when the filter is active — null means the
        # event has no file IOC context and should not appear in IOC-pivot queries.
        # Ref: OCSF File.hashes[].value (algorithm_id=3); ECS file.hash.sha256
        if f.file_sha256:
            conditions.append("file_sha256 = ?")
            params.append(f.file_sha256)
            count_conditions.append("file_sha256 = ?")
            count_params.append(f.file_sha256)

        # ADR-0055 (issue #602) — dns_answer exact-match filter (EARS-3).
        # dns_answer is a comma-joined string; exact match via ? placeholder (B1 invariant).
        # Enables passive-DNS pivoting: query by the resolved answer value(s).
        # Ref: OCSF DNS Activity answers[].rdata; ECS dns.answers[].data / dns.resolved_ip
        if f.dns_answer:
            conditions.append("dns_answer = ?")
            params.append(f.dns_answer)
            count_conditions.append("dns_answer = ?")
            count_params.append(f.dns_answer)

        # Source identity filters (ADR-0016)
        if f.source_type:
            conditions.append("source_type = ?")
            params.append(f.source_type)
            count_conditions.append("source_type = ?")
            count_params.append(f.source_type)

        if f.source_id:
            conditions.append("source_id = ?")
            params.append(f.source_id)
            count_conditions.append("source_id = ?")
            count_params.append(f.source_id)

        # Free-text search — rule-description lookup now queries source_kv
        # (the authoritative store since ADR-0025).  All three parameters are
        # static string literals; only the LIKE value flows through a placeholder.
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
            count_conditions.append(q_clause)
            count_params.extend([like, like, like, like])

        # B1 safety invariant: `conditions` and `count_conditions` contain
        # ONLY static string literals hard-coded above.  No element ever
        # originates from caller input; all caller values flow through `?`
        # placeholders collected in `params` / `count_params`.
        # The WHERE fragment is therefore safe to join into the SQL string.
        assert all(isinstance(c, str) for c in conditions), (
            "BUG: conditions list must contain only static string literals"
        )
        assert all(isinstance(c, str) for c in count_conditions), (
            "BUG: count_conditions list must contain only static string literals"
        )
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        count_where = (
            ("WHERE " + " AND ".join(count_conditions)) if count_conditions else ""
        )

        count_sql = "SELECT COUNT(*) as cnt FROM logs l " + count_where
        count_cursor = await db.execute(count_sql, count_params)
        count_row = await count_cursor.fetchone()
        total: int = count_row["cnt"] if count_row else 0

        # Issue #334 — inline geo enrichment via local cache (no N+1, no external call).
        #
        # LEFT JOIN ip_geo on source_ip so each log row carries geo_city / geo_country
        # from the local ip_geo cache without a per-row round-trip to the geo provider.
        # ip_geo.ip is a PRIMARY KEY so the join is O(log N) per row — cheap even for
        # 1 000-row pages.  NULL geo fields appear when the IP is not yet in the cache
        # or is non-public; the API consumer must treat them as "unknown" (bare IP only).
        #
        # ML-10 (issue #438) — inline anomaly_flags badge aggregation (EARS-2).
        # A correlated subquery uses GROUP_CONCAT to collect all anomaly_type values
        # for each row's (source_ip, destination_ip, destination_port) triple from
        # the anomaly_verdicts table.  NULL when no verdicts exist; Python splits the
        # CSV into a list (empty list for no flags).  The subquery uses IS (not =) on
        # dst_ip and dst_port so NULL-valued columns match correctly in both directions.
        #
        # Security (B1 safety invariant preserved): the subquery and join add only
        # static column aliases derived from hard-coded literals — no user-supplied
        # value is interpolated into the SQL string.  The WHERE fragment retains its
        # original parameterised form; unqualified column references in `conditions`
        # are unambiguous because ip_geo has no column that overlaps with logs (its
        # only join key is exposed as g.ip, not via SELECT l.*).
        fetch_params: list[Any] = params + [limit + 1]
        where_clause = (" " + where) if where else ""
        data_sql = (
            "SELECT l.*, g.city AS geo_city, g.country AS geo_country,"
            " (SELECT GROUP_CONCAT(av.anomaly_type, ',')"
            "  FROM anomaly_verdicts av"
            "  WHERE av.src_ip = l.source_ip"
            "  AND av.dst_ip IS l.destination_ip"
            "  AND av.dst_port IS l.destination_port"
            " ) AS anomaly_flags_csv"
            " FROM logs l"
            " LEFT JOIN ip_geo g ON l.source_ip = g.ip"
            + where_clause
            + " ORDER BY l.timestamp DESC, l.id DESC LIMIT ?"
        )
        data_cursor = await db.execute(data_sql, fetch_params)
        rows: list[aiosqlite.Row] = list(await data_cursor.fetchall())
        has_more = len(rows) > limit
        # Post-process anomaly_flags_csv: split CSV into a list; drop the raw CSV key.
        # Empty list when no anomaly verdicts exist for this row (EARS-2 badge surface).
        raw_rows = [dict(r) for r in rows[:limit]]
        logs: list[dict[str, Any]] = []
        for raw in raw_rows:
            flags_csv: str | None = raw.pop("anomaly_flags_csv", None)
            raw["anomaly_flags"] = flags_csv.split(",") if flags_csv else []
            logs.append(raw)
        next_cursor = (
            f"{logs[-1]['timestamp']}|{logs[-1]['id']}"
            if has_more and logs
            else None
        )

        return {
            "logs": logs,
            "next_cursor": next_cursor,
            "has_more": has_more,
            "total_matching": total,
        }
