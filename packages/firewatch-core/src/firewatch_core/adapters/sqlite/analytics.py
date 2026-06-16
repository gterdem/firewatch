"""_AnalyticsMixin — read-only aggregate/summary/timeline queries."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import aiosqlite

from firewatch_sdk.models import FilterSpec

from ._base import _BLOCKED_SQL_FRAG
from ._filter_where import build_filter_where


class _AnalyticsMixin:
    """Aggregates: get_all_ips, get_top_*, get_ip_summary, get_stats,
    get_timeline, source_health, get_analytics_*, get_categories*,
    get_ip_counterfactual, and get_attack_dispositions."""

    async def _read_conn(self) -> aiosqlite.Connection: ...  # pragma: no cover

    async def get_all_ips(self) -> list[str]:
        db = await self._read_conn()  # read-only (#313)
        cursor = await db.execute("SELECT DISTINCT source_ip FROM logs")
        rows = await cursor.fetchall()
        return [r["source_ip"] for r in rows]

    async def get_top_pairs(
        self,
        top_n: int = 10,
        filters: FilterSpec | None = None,
        *,
        start: str | None = None,
        end: str | None = None,
    ) -> list[dict[str, Any]]:
        """Top (source_ip -> destination_ip) pairs by event count (ML-3, issue #431).

        Returns the ``top_n`` most-frequent source->destination IP pairs, ordered
        by count descending.  Pairs where ``destination_ip`` is NULL are excluded
        (they carry no destination-dimension signal).

        Response shape: ``[{source_ip: str, destination_ip: str, count: int}]``.

        ``top_n`` is bounded.  The value is coerced to a positive int and bound
        via a ``?`` placeholder, so the query is safe-by-construction regardless
        of the caller (no reliance on ``assert``, which is elided under ``-O``).

        Issue #662: accepts ``filters`` (FilterSpec) and ``start``/``end`` (ISO-8601
        strings) to scope results to matching rows using the shared WHERE predicate.
        ``filters=None`` and no ``start``/``end`` preserve pre-change behaviour.
        """
        db = await self._read_conn()  # read-only (#313)
        # Defense-in-depth (security review, PR #444): coerce to a positive int and
        # bind LIMIT via a placeholder rather than f-string interpolation, so the
        # store is safe-by-construction even if a future caller bypasses the API's
        # FastAPI int validation. int() fails closed on a non-coercible value.
        safe_limit = max(1, int(top_n))
        filter_where, filter_params = build_filter_where(filters, start=start, end=end)
        # The destination_ip IS NOT NULL guard is always applied; if a filter
        # WHERE clause is also present, append it with AND.
        dest_guard = "destination_ip IS NOT NULL AND destination_ip != ''"
        if filter_where:
            # filter_where starts with "WHERE "; strip it and combine with dest_guard.
            extra = filter_where[len("WHERE "):]
            where_clause = f"WHERE {dest_guard} AND {extra}"
        else:
            where_clause = f"WHERE {dest_guard}"
        sql = (
            "SELECT source_ip, destination_ip, COUNT(*) AS count"
            f" FROM logs {where_clause}"
            " GROUP BY source_ip, destination_ip"
            " ORDER BY count DESC"
            " LIMIT ?"
        )
        cursor = await db.execute(sql, (*filter_params, safe_limit))
        rows = await cursor.fetchall()
        return [
            {
                "source_ip": r["source_ip"],
                "destination_ip": r["destination_ip"],
                "count": r["count"],
            }
            for r in rows
        ]

    async def get_top_talkers(
        self,
        top_n: int = 10,
        filters: FilterSpec | None = None,
        *,
        start: str | None = None,
        end: str | None = None,
    ) -> list[dict[str, Any]]:
        """Top source IPs by event count (ML-4, issue #432).

        Returns the ``top_n`` most-active source IPs ordered by total event count
        descending.  Each row carries the source IP, total event count, and blocked
        count so the header strip can render a bar without an extra fetch.

        Response shape: ``[{source_ip: str, count: int, blocked: int}]``.

        ``top_n`` is bounded via a ``?`` placeholder (defense-in-depth, same
        pattern as ``get_top_pairs``).

        Issue #662: accepts ``filters`` (FilterSpec) and ``start``/``end`` (ISO-8601
        strings) to scope results to matching rows using the shared WHERE predicate.
        ``filters=None`` and no ``start``/``end`` preserve pre-change behaviour.

        SECURITY (ADR-0029 D3): ``source_ip`` is attacker-controlled telemetry.
        Callers MUST render it as a text node — never via dangerouslySetInnerHTML.
        """
        db = await self._read_conn()  # read-only (#313)
        safe_limit = max(1, int(top_n))
        filter_where, filter_params = build_filter_where(filters, start=start, end=end)
        sql = (
            "SELECT source_ip,"
            " COUNT(*) AS count,"
            " SUM(CASE WHEN action IN ('BLOCK','DROP') THEN 1 ELSE 0 END) AS blocked"
            f" FROM logs {filter_where}"
            " GROUP BY source_ip"
            " ORDER BY count DESC"
            " LIMIT ?"
        )
        cursor = await db.execute(sql, (*filter_params, safe_limit))
        rows = await cursor.fetchall()
        return [
            {
                "source_ip": r["source_ip"],
                "count": r["count"],
                "blocked": r["blocked"] or 0,
            }
            for r in rows
        ]

    async def get_protocol_mix(
        self,
        top_n: int = 10,
        filters: FilterSpec | None = None,
        *,
        start: str | None = None,
        end: str | None = None,
    ) -> list[dict[str, Any]]:
        """Protocol breakdown by event count (ML-4, issue #432).

        Returns per-protocol event counts ordered by count descending, bounded to
        ``top_n`` rows.  Rows where ``protocol`` is NULL or empty string are
        aggregated under the sentinel ``'(unknown)'`` so sources that do not
        populate the field (e.g. Azure WAF) are honestly represented rather than
        silently dropped.

        NULLIF normalises empty-string protocol values (stored by sources that
        leave the field blank) to NULL before COALESCE, so both NULL and '' are
        bucketed under '(unknown)'.

        Response shape: ``[{protocol: str, count: int}]``.

        ``top_n`` is bounded via a ``?`` placeholder — no f-string interpolation
        of user input (ADR-0029 D3 / defense-in-depth).

        Issue #662: accepts ``filters`` (FilterSpec) and ``start``/``end`` (ISO-8601
        strings) to scope results to matching rows using the shared WHERE predicate.
        ``filters=None`` and no ``start``/``end`` preserve pre-change behaviour.
        """
        db = await self._read_conn()  # read-only (#313)
        safe_limit = max(1, int(top_n))
        filter_where, filter_params = build_filter_where(filters, start=start, end=end)
        protocol_expr = "COALESCE(NULLIF(protocol, ''), '(unknown)')"
        sql = (
            f"SELECT {protocol_expr} AS protocol,"
            " COUNT(*) AS count"
            f" FROM logs {filter_where}"
            f" GROUP BY {protocol_expr}"
            " ORDER BY count DESC"
            " LIMIT ?"
        )
        cursor = await db.execute(sql, (*filter_params, safe_limit))
        rows = await cursor.fetchall()
        return [
            {
                "protocol": r["protocol"],
                "count": r["count"],
            }
            for r in rows
        ]

    async def get_top_ja4(self, top_n: int = 10) -> list[dict[str, Any]]:
        """Top JA4 fingerprints by event count (ML-13, issue #441).

        Returns the ``top_n`` most-frequent JA4 fingerprints ordered by count
        descending.  Rows where ``tls_ja4`` is NULL are excluded (sensor did not
        emit JA4 — consume-only per ADR-0048 sub-decision; never fabricate).

        When all rows have NULL ``tls_ja4`` (most live deployments) this returns
        an empty list — honest, not an error.

        Response shape: ``[{tls_ja4: str, count: int}]``.

        ``top_n`` is bounded via a ``?`` placeholder — no f-string interpolation
        of user input (ADR-0029 D3 / defense-in-depth, same pattern as
        ``get_top_pairs`` / ``get_protocol_mix``).

        SECURITY (ADR-0029 D3): ``tls_ja4`` is a fingerprint string normalised
        from plugin telemetry — consumers MUST render as text nodes only.
        """
        db = await self._read_conn()  # read-only (#313)
        safe_limit = max(1, int(top_n))
        sql = (
            "SELECT tls_ja4, COUNT(*) AS count"
            " FROM logs"
            " WHERE tls_ja4 IS NOT NULL AND tls_ja4 != ''"
            " GROUP BY tls_ja4"
            " ORDER BY count DESC"
            " LIMIT ?"
        )
        cursor = await db.execute(sql, (safe_limit,))
        rows = await cursor.fetchall()
        return [
            {
                "tls_ja4": r["tls_ja4"],
                "count": r["count"],
            }
            for r in rows
        ]

    async def get_ip_summary(self) -> list[dict[str, Any]]:
        db = await self._read_conn()  # read-only (#313)
        cursor = await db.execute(
            """
            SELECT source_ip,
                   COUNT(*) as total_events,
                   SUM(CASE WHEN action IN ('BLOCK','DROP') THEN 1 ELSE 0 END) as blocked,
                   COUNT(DISTINCT rule_id) as rules_triggered,
                   MIN(timestamp) as first_seen,
                   MAX(timestamp) as last_seen
            FROM logs
            GROUP BY source_ip
            ORDER BY last_seen DESC
            """
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    async def get_category_summary(self) -> list[dict[str, Any]]:
        """Unique category names with counts — drives the Network Logs filter dropdown.

        Uses the ``category`` column directly (populated on write).  Rows with a
        NULL category are grouped under 'Other'.  Ported from legacy for parity.
        """
        db = await self._read_conn()  # read-only (#313)
        cursor = await db.execute(
            """
            SELECT COALESCE(category, 'Other') as category, COUNT(*) as count
            FROM logs
            GROUP BY COALESCE(category, 'Other')
            ORDER BY count DESC
            """
        )
        rows = await cursor.fetchall()
        return [{"category": r["category"], "count": r["count"]} for r in rows]

    async def get_categories(self) -> list[dict[str, Any]]:
        """Blocked-event counts grouped by the stored ``category`` column (issue #325).

        The normalize-time ``SecurityEvent.category`` value is the single source of
        truth for every read-time category facet (canonical-schema discipline,
        ADR-0020).  Grouping directly on the stored column guarantees that:

        * Every label in this response is a value that ``?category=<label>`` will
          filter against (EARS-2 shared-vocabulary contract).
        * One-row-per-category is a structural guarantee from ``GROUP BY`` — no
          merge pass needed (structural fix for the #322 class of duplicates).
        * Rows with a NULL ``category`` are aggregated under the sentinel value
          ``'Other'`` via ``COALESCE``.

        Response shape: ``[{category: str, count: int}]``, ordered by count DESC.
        The legacy ``rule_id`` and ``filter`` keys are removed — no frontend or
        backend consumer reads them (``CategoryCount`` type omits them).
        """
        db = await self._read_conn()  # read-only (#313)
        cursor = await db.execute(
            f"""
            SELECT COALESCE(category, 'Other') AS category, COUNT(*) AS count
            FROM logs
            WHERE {_BLOCKED_SQL_FRAG}
            GROUP BY COALESCE(category, 'Other')
            ORDER BY count DESC
            """
        )
        rows = await cursor.fetchall()
        return [{"category": r["category"], "count": r["count"]} for r in rows]

    async def get_timeline(
        self,
        start: str | None,
        end: str | None,
    ) -> list[dict[str, Any]]:
        """Event counts over time.  Daily if span > 48 h, else hourly.

        Ported verbatim from legacy for golden-test parity.
        """
        db = await self._read_conn()  # read-only (#313)
        now = datetime.now(timezone.utc)

        if start:
            raw = start.replace("Z", "+00:00")
            start_dt = (
                datetime.fromisoformat(raw)
                if "T" in raw
                else datetime.fromisoformat(raw + "T00:00:00+00:00")
            )
            if start_dt.tzinfo is None:
                start_dt = start_dt.replace(tzinfo=timezone.utc)
        else:
            start_dt = now - timedelta(hours=12)

        if end:
            raw = end.replace("Z", "+00:00")
            end_dt = (
                datetime.fromisoformat(raw)
                if "T" in raw
                else datetime.fromisoformat(raw + "T23:59:59+00:00")
            )
            if end_dt.tzinfo is None:
                end_dt = end_dt.replace(tzinfo=timezone.utc)
        else:
            end_dt = now

        hours_span = (end_dt - start_dt).total_seconds() / 3600
        use_daily = hours_span > 48

        # Parameterized period expressions for each granularity.
        # Daily:  "YYYY-MM-DD" (10 chars)
        # Hourly: "YYYY-MM-DDTHH:00" (substr 13 + ':00')
        # Both are static string literals — no user input interpolated (ADR-0029 D3).
        start_iso = start_dt.isoformat()
        end_iso = end_dt.isoformat()
        params: tuple[str, str] = (start_iso, end_iso)

        if use_daily:
            period_expr = "substr(timestamp, 1, 10)"
        else:
            period_expr = "substr(timestamp, 1, 13) || ':00'"

        # ── primary counts (ported-verbatim — golden-pinned result shape) ──
        cursor = await db.execute(
            f"""
            SELECT {period_expr} as period,
                   COUNT(*) as total,
                   SUM(CASE WHEN action IN ('BLOCK','DROP') THEN 1 ELSE 0 END) as blocked
            FROM logs
            WHERE timestamp >= ? AND timestamp <= ?
            GROUP BY period
            ORDER BY period
            """,  # noqa: S608  — period_expr is a static literal, not user input
            params,
        )
        rows_map = {r["period"]: r for r in await cursor.fetchall()}

        # ── additive: per-severity counts (issue #247) ──
        # LOWER() normalises mixed-case severity values from different source plugins.
        sev_cursor = await db.execute(
            f"""
            SELECT {period_expr} as period,
                   SUM(CASE WHEN LOWER(severity) = 'critical' THEN 1 ELSE 0 END) as critical,
                   SUM(CASE WHEN LOWER(severity) = 'high'     THEN 1 ELSE 0 END) as high,
                   SUM(CASE WHEN LOWER(severity) = 'medium'   THEN 1 ELSE 0 END) as medium,
                   SUM(CASE WHEN LOWER(severity) = 'low'      THEN 1 ELSE 0 END) as low
            FROM logs
            WHERE timestamp >= ? AND timestamp <= ?
            GROUP BY period
            """,  # noqa: S608  — period_expr is a static literal, not user input
            params,
        )
        sev_map: dict[str, dict[str, int]] = {}
        for r in await sev_cursor.fetchall():
            sev_map[r["period"]] = {
                "critical": r["critical"] or 0,
                "high": r["high"] or 0,
                "medium": r["medium"] or 0,
                "low": r["low"] or 0,
            }

        # ── additive: top category per bucket (mode — highest count row) ──
        cat_cursor = await db.execute(
            f"""
            SELECT {period_expr} as period,
                   category,
                   COUNT(*) as cnt
            FROM logs
            WHERE timestamp >= ? AND timestamp <= ?
              AND category IS NOT NULL
            GROUP BY period, category
            ORDER BY period, cnt DESC
            """,  # noqa: S608  — period_expr is a static literal, not user input
            params,
        )
        top_category_map: dict[str, str | None] = {}
        for r in await cat_cursor.fetchall():
            # Keep only the first (highest cnt) row per period.
            if r["period"] not in top_category_map:
                top_category_map[r["period"]] = r["category"]

        # ── additive: top source IP per bucket (mode — highest count row) ──
        ip_cursor = await db.execute(
            f"""
            SELECT {period_expr} as period,
                   source_ip,
                   COUNT(*) as cnt
            FROM logs
            WHERE timestamp >= ? AND timestamp <= ?
            GROUP BY period, source_ip
            ORDER BY period, cnt DESC
            """,  # noqa: S608  — period_expr is a static literal, not user input
            params,
        )
        top_ip_map: dict[str, str | None] = {}
        for r in await ip_cursor.fetchall():
            if r["period"] not in top_ip_map:
                top_ip_map[r["period"]] = r["source_ip"]

        # ── assemble result rows ──
        _sev_zero: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        result: list[dict[str, Any]] = []
        if use_daily:
            current = start_dt.replace(hour=0, minute=0, second=0, microsecond=0)
            while current <= end_dt:
                key = current.strftime("%Y-%m-%d")
                row = rows_map.get(key)
                result.append({
                    # Golden-pinned fields — byte-identical to pre-#247 output.
                    "hour": key,
                    "total": row["total"] if row else 0,
                    "blocked": row["blocked"] if row else 0,
                    "granularity": "daily",
                    # Additive fields (issue #247).
                    "severity": sev_map.get(key, _sev_zero),
                    "top_category": top_category_map.get(key),
                    "top_source_ip": top_ip_map.get(key),
                })
                current += timedelta(days=1)
        else:
            current = start_dt.replace(minute=0, second=0, microsecond=0)
            while current <= end_dt:
                key = current.strftime("%Y-%m-%dT%H:00")
                row = rows_map.get(key)
                result.append({
                    # Golden-pinned fields — byte-identical to pre-#247 output.
                    "hour": key,
                    "total": row["total"] if row else 0,
                    "blocked": row["blocked"] if row else 0,
                    "granularity": "hourly",
                    # Additive fields (issue #247).
                    "severity": sev_map.get(key, _sev_zero),
                    "top_category": top_category_map.get(key),
                    "top_source_ip": top_ip_map.get(key),
                })
                current += timedelta(hours=1)

        return result

    async def source_health(self) -> list[dict[str, Any]]:
        """Return per-source event aggregates keyed on (source_type, source_id).

        Each entry contains:
          source_type   — plugin type_key (e.g. "suricata")
          source_id     — instance name (e.g. "pi-home")
          event_count   — total rows for this pair
          last_event_at — ISO timestamp of the most recent event, or None

        Implements ADR-0032 Decision D.  The query is a single GROUP BY over
        ``logs`` — the same MAX(timestamp)/COUNT(*) pattern used by
        ``get_ip_summary``.  No source name is hard-coded; the method is
        entirely generic over (source_type, source_id).
        """
        db = await self._read_conn()  # read-only (#313)
        cursor = await db.execute(
            """
            SELECT source_type,
                   source_id,
                   COUNT(*) AS event_count,
                   MAX(timestamp) AS last_event_at
            FROM logs
            GROUP BY source_type, source_id
            ORDER BY source_type, source_id
            """
        )
        rows = await cursor.fetchall()
        return [
            {
                "source_type": r["source_type"],
                "source_id": r["source_id"],
                "event_count": r["event_count"],
                "last_event_at": r["last_event_at"],
            }
            for r in rows
        ]

    async def get_logs_stats(
        self,
        filters: FilterSpec | None = None,
        *,
        start: str | None = None,
        end: str | None = None,
    ) -> dict[str, Any]:
        """Filter-scoped totals for the /logs strip header (issue #663).

        Returns REAL aggregates from a single SQL round-trip, scoped to the
        supplied ``FilterSpec`` and optional time range via the shared
        ``build_filter_where`` predicate.  ``filters=None`` (or an empty
        ``FilterSpec()``) returns whole-store totals.

        Response shape::

            {
                "total_events":          int,   # COUNT(*) over the filtered scope
                "blocked_events":        int,   # COUNT where action IN (BLOCK, DROP)
                "distinct_ips":          int,   # COUNT(DISTINCT source_ip)
                "present_source_types":  list[str],  # sorted DISTINCT source_type
            }

        Security (B1): all caller-supplied values flow through ``?`` placeholders
        via ``build_filter_where`` — no f-string interpolation of user input.

        Issue #663: replaces the front-end top-10 summation hack, which was
        understating real totals by summing only the top-10 talker rows.
        """
        db = await self._read_conn()  # read-only (#313)
        filter_where, filter_params = build_filter_where(filters, start=start, end=end)

        # Single round-trip: COUNT(*), blocked count, COUNT(DISTINCT source_ip)
        stats_sql = (
            "SELECT"
            "  COUNT(*) AS total_events,"
            f"  SUM(CASE WHEN {_BLOCKED_SQL_FRAG} THEN 1 ELSE 0 END) AS blocked_events,"
            "  COUNT(DISTINCT source_ip) AS distinct_ips"
            f" FROM logs {filter_where}"
        )
        row = await (await db.execute(stats_sql, filter_params)).fetchone()

        total_events: int = row["total_events"] if row else 0
        blocked_events: int = (row["blocked_events"] or 0) if row else 0
        distinct_ips: int = row["distinct_ips"] if row else 0

        # Distinct source types in scope — needed by #664 source-type facet strip
        types_sql = (
            "SELECT DISTINCT source_type"
            f" FROM logs {filter_where}"
            " ORDER BY source_type"
        )
        cursor = await db.execute(types_sql, filter_params)
        type_rows = await cursor.fetchall()
        present_source_types = [r["source_type"] for r in type_rows if r["source_type"]]

        return {
            "total_events": total_events,
            "blocked_events": blocked_events,
            "distinct_ips": distinct_ips,
            "present_source_types": present_source_types,
        }

    async def get_stats(self) -> dict[str, Any]:
        """Aggregate stats — the v1 StatsResponse-shaped dict.

        Extended (ADR-0032 / issue #133) to include ``last_updated``:
        the ISO timestamp of the most recent event overall, or ``None``
        when the store is empty.
        """
        db = await self._read_conn()  # read-only (#313)

        row = await (
            await db.execute("SELECT COUNT(*) as cnt FROM logs")
        ).fetchone()
        total_logs: int = row["cnt"] if row else 0

        row = await (
            await db.execute(
                "SELECT COUNT(DISTINCT source_ip) as cnt FROM logs"
            )
        ).fetchone()
        total_ips: int = row["cnt"] if row else 0

        row = await (
            await db.execute(
                "SELECT COUNT(*) as cnt FROM logs WHERE action IN ('BLOCK','DROP')"
            )
        ).fetchone()
        blocked: int = row["cnt"] if row else 0
        blocked_pct = (blocked / total_logs * 100) if total_logs > 0 else 0.0

        cursor = await db.execute(
            """
            SELECT category, COUNT(*) as cnt
            FROM logs
            WHERE action IN ('BLOCK','DROP')
              AND category IS NOT NULL
              AND category != ''
            GROUP BY category
            ORDER BY cnt DESC
            LIMIT 10
            """
        )
        top_rows = await cursor.fetchall()
        top_attack_types = [r["category"] for r in top_rows]

        last_updated_row = await (
            await db.execute("SELECT MAX(timestamp) AS ts FROM logs")
        ).fetchone()
        last_updated: str | None = (
            last_updated_row["ts"] if last_updated_row and last_updated_row["ts"] else None
        )

        return {
            "total_logs": total_logs,
            "total_ips": total_ips,
            "top_attack_types": top_attack_types,
            "blocked_percentage": round(blocked_pct, 2),
            "last_updated": last_updated,
        }

    async def get_analytics_geo(self) -> list[dict[str, Any]]:
        """Return geo-enriched IP points with ASN data and IP provenance class.

        Issue #532: extends the response to include ``asn``, ``as_name``, and
        ``ip_class`` so the frontend can render honest provenance styling
        (hollow/dashed for datacenter, muted for unresolved, solid for residential).

        Classification runs server-side via ``ip_classifier.classify`` — zero
        external network calls (ADR-0047 zero-egress posture).
        """
        from firewatch_core.adapters.ip_classifier import classify  # local import avoids circular

        db = await self._read_conn()  # read-only (#313)
        cursor = await db.execute("""
            SELECT g.ip, g.country, g.city, g.lat, g.lon,
                   g.asn, g.as_name,
                   COUNT(*) as total_events,
                   SUM(CASE WHEN l.action IN ('BLOCK','DROP') THEN 1 ELSE 0 END) as blocked,
                   COUNT(DISTINCT l.rule_id) as rules_triggered
            FROM ip_geo g
            JOIN logs l ON g.ip = l.source_ip
            GROUP BY g.ip
            ORDER BY blocked DESC
        """)
        rows = []
        for r in await cursor.fetchall():
            row = dict(r)
            row["ip_class"] = classify(
                asn=row.get("asn"),
                as_name=row.get("as_name"),
                ip=row.get("ip"),
            )
            rows.append(row)
        return rows

    async def get_analytics_summary(self) -> dict[str, Any]:
        """Return analytics aggregate stats.

        Issue #532: adds ``unresolved_private_count`` — the count of distinct
        source IPs that are either RFC-1918/private or have no geo resolution.
        This makes "Unknown" traffic honest (EARS-4/EARS-5): RFC-1918 traffic
        is counted and labelled, not silently dropped from the map.

        No new table needed — derived at read time from existing columns.
        Zero external network calls (ADR-0047 zero-egress posture).
        """
        db = await self._read_conn()  # read-only (#313)
        cursor = await db.execute("""
            SELECT COUNT(DISTINCT source_ip) as total_ips,
                   COUNT(*) as total_events,
                   SUM(CASE WHEN action IN ('BLOCK','DROP') THEN 1 ELSE 0 END) as total_blocked
            FROM logs
        """)
        row = await cursor.fetchone()
        total_ips: int = row["total_ips"] if row else 0
        total_events: int = row["total_events"] if row else 0
        total_blocked: int = row["total_blocked"] if row else 0

        cursor2 = await db.execute("""
            SELECT g.country,
                   SUM(CASE WHEN l.action IN ('BLOCK','DROP') THEN 1 ELSE 0 END) as blocked
            FROM ip_geo g JOIN logs l ON g.ip = l.source_ip
            GROUP BY g.country ORDER BY blocked DESC LIMIT 1
        """)
        top_country_row = await cursor2.fetchone()

        cursor3 = await db.execute(
            "SELECT COUNT(DISTINCT country) as cnt FROM ip_geo WHERE country != ''"
        )
        countries_row = await cursor3.fetchone()

        cursor4 = await db.execute("""
            SELECT rule_id, COUNT(*) as cnt FROM logs
            WHERE action IN ('BLOCK','DROP')
            GROUP BY rule_id ORDER BY cnt DESC LIMIT 1
        """)
        top_rule_row = await cursor4.fetchone()

        # Issue #532 (EARS-4/EARS-5): count IPs that are either:
        #   - in the logs but NOT in ip_geo (not yet enriched = unresolved), OR
        #   - in ip_geo with no country (private/non-routable, stored as empty string).
        # This gives an honest "N IPs not shown on map" signal so RFC-1918 traffic
        # is visible rather than vanishing silently.
        cursor5 = await db.execute("""
            SELECT COUNT(DISTINCT l.source_ip) as cnt
            FROM logs l
            LEFT JOIN ip_geo g ON l.source_ip = g.ip
            WHERE g.ip IS NULL OR g.country IS NULL OR g.country = ''
        """)
        unresolved_row = await cursor5.fetchone()
        unresolved_private_count: int = unresolved_row["cnt"] if unresolved_row else 0

        return {
            "total_ips": total_ips,
            "total_events": total_events,
            "total_blocked": total_blocked,
            "block_rate": (
                round(total_blocked / total_events * 100, 1) if total_events else 0
            ),
            "top_country": (
                top_country_row["country"] if top_country_row else "Unknown"
            ),
            "unique_countries": countries_row["cnt"] if countries_row else 0,
            "top_rule": top_rule_row["rule_id"] if top_rule_row else "",
            "unresolved_private_count": unresolved_private_count,
        }

    async def get_categories_timeline(
        self,
        start: str | None,
        end: str | None,
    ) -> list[dict[str, Any]]:
        """Blocked events per category per period.  Ported from legacy."""
        now = datetime.now(timezone.utc)
        if start:
            raw = start.replace("Z", "+00:00")
            start_dt = (
                datetime.fromisoformat(raw)
                if "T" in raw
                else datetime.fromisoformat(raw + "T00:00:00+00:00")
            )
            if start_dt.tzinfo is None:
                start_dt = start_dt.replace(tzinfo=timezone.utc)
        else:
            start_dt = now - timedelta(days=7)

        if end:
            raw = end.replace("Z", "+00:00")
            end_dt = (
                datetime.fromisoformat(raw)
                if "T" in raw
                else datetime.fromisoformat(raw + "T23:59:59+00:00")
            )
            if end_dt.tzinfo is None:
                end_dt = end_dt.replace(tzinfo=timezone.utc)
        else:
            end_dt = now

        hours_span = (end_dt - start_dt).total_seconds() / 3600
        use_daily = hours_span > 48

        db = await self._read_conn()  # read-only (#313)
        # B2 safety invariant: no user-supplied value is ever interpolated into
        # the SQL string.  Granularity is selected between two wholly static
        # query constants; all caller values use ? placeholders.
        _DAILY_QUERY = """
            SELECT substr(timestamp, 1, 10) as period,
                   SUM(CASE WHEN rule_id LIKE '942%' THEN 1 ELSE 0 END) as sqli,
                   SUM(CASE WHEN rule_id LIKE '941%' THEN 1 ELSE 0 END) as xss,
                   SUM(CASE WHEN rule_id LIKE '300%' THEN 1 ELSE 0 END) as bot,
                   SUM(CASE WHEN rule_id LIKE '%RateLimit%' THEN 1 ELSE 0 END) as ratelimit,
                   SUM(CASE WHEN rule_id LIKE '%GeoBlock%' THEN 1 ELSE 0 END) as geo,
                   SUM(CASE WHEN rule_id LIKE '930%' THEN 1 ELSE 0 END) as lfi,
                   SUM(CASE WHEN source_type = 'suricata' THEN 1 ELSE 0 END) as ids_alert,
                   COUNT(*) as total
            FROM logs
            WHERE action IN ('BLOCK','DROP')
              AND timestamp >= ? AND timestamp <= ?
            GROUP BY period
            ORDER BY period
        """
        _HOURLY_QUERY = """
            SELECT substr(timestamp, 1, 13) || ':00' as period,
                   SUM(CASE WHEN rule_id LIKE '942%' THEN 1 ELSE 0 END) as sqli,
                   SUM(CASE WHEN rule_id LIKE '941%' THEN 1 ELSE 0 END) as xss,
                   SUM(CASE WHEN rule_id LIKE '300%' THEN 1 ELSE 0 END) as bot,
                   SUM(CASE WHEN rule_id LIKE '%RateLimit%' THEN 1 ELSE 0 END) as ratelimit,
                   SUM(CASE WHEN rule_id LIKE '%GeoBlock%' THEN 1 ELSE 0 END) as geo,
                   SUM(CASE WHEN rule_id LIKE '930%' THEN 1 ELSE 0 END) as lfi,
                   SUM(CASE WHEN source_type = 'suricata' THEN 1 ELSE 0 END) as ids_alert,
                   COUNT(*) as total
            FROM logs
            WHERE action IN ('BLOCK','DROP')
              AND timestamp >= ? AND timestamp <= ?
            GROUP BY period
            ORDER BY period
        """
        query = _DAILY_QUERY if use_daily else _HOURLY_QUERY
        cursor = await db.execute(
            query,
            (start_dt.isoformat(), end_dt.isoformat()),
        )
        rows = await cursor.fetchall()
        return [
            dict(r) | {"granularity": "daily" if use_daily else "hourly"}
            for r in rows
        ]

    async def get_attack_dispositions(
        self, top_n: int = 5
    ) -> list[dict[str, Any]]:
        """Cross-tab of attack category × disposition (action) for the top-N categories.

        Returns rows [{attack_type, action, count}] bounded to top_n attack categories
        plus an "Other" bucket for the tail.  Covers all actions (BLOCK, DROP, ALERT,
        ALLOW, LOG); callers group/label as needed.

        The ``category`` column stores the attack category (populated on write from the
        rule-category mapping).  NULL categories are grouped as 'Other'.

        ADR-0029 D1 read-surface conventions: additive endpoint, no existing shape changed.
        Issue #214.
        """
        db = await self._read_conn()  # read-only (#313)

        # Step 1: find the top-N attack categories by total event count.
        cursor = await db.execute(
            """
            SELECT COALESCE(category, 'Other') AS attack_type, COUNT(*) AS total
            FROM logs
            WHERE category IS NOT NULL
            GROUP BY COALESCE(category, 'Other')
            ORDER BY total DESC
            LIMIT ?
            """,
            (top_n,),
        )
        top_rows = await cursor.fetchall()
        top_cats: list[str] = [r["attack_type"] for r in top_rows]

        if not top_cats:
            return []

        # Step 2: cross-tab for the top categories.
        placeholders = ",".join("?" * len(top_cats))
        cursor = await db.execute(
            f"""
            SELECT COALESCE(category, 'Other') AS attack_type,
                   action,
                   COUNT(*) AS count
            FROM logs
            WHERE COALESCE(category, 'Other') IN ({placeholders})
            GROUP BY COALESCE(category, 'Other'), action
            ORDER BY COALESCE(category, 'Other'), action
            """,
            top_cats,
        )
        top_cross: list[dict[str, Any]] = [dict(r) for r in await cursor.fetchall()]

        # Step 3: aggregate the tail (everything outside top_cats) as "Other".
        cursor = await db.execute(
            f"""
            SELECT action, COUNT(*) AS count
            FROM logs
            WHERE COALESCE(category, 'Other') NOT IN ({placeholders})
            GROUP BY action
            """,
            top_cats,
        )
        tail_rows = await cursor.fetchall()
        other_cross: list[dict[str, Any]] = [
            {"attack_type": "Other", "action": r["action"], "count": r["count"]}
            for r in tail_rows
        ]

        # Step 4: merge to guarantee at most one row per (attack_type, action) key.
        #
        # The collision arises when a stored category is *literally* 'Other' and
        # lands in the top-N (step 2) while tail categories also exist (step 3).
        # Both steps emit rows keyed by attack_type='Other', splitting the count.
        # Fix: accumulate counts into an insertion-ordered dict keyed by the
        # composite (attack_type, action) pair; the original order is preserved.
        merged: dict[tuple[str, str], int] = {}
        for row in top_cross + other_cross:
            key = (row["attack_type"], row["action"])
            merged[key] = merged.get(key, 0) + row["count"]

        return [
            {"attack_type": at, "action": act, "count": cnt}
            for (at, act), cnt in merged.items()
        ]

    async def get_analytics_asn(
        self, top_n: int = 15
    ) -> list[dict[str, Any]]:
        """Return ranked ASN aggregation for the infrastructure lens (issue #533, A2).

        Joins ``ip_geo`` (which carries ``asn`` / ``as_name`` from ADR-0039 / #211)
        with ``logs`` to compute per-ASN event counts, distinct IPs, and blocked rate.

        Returns rows ordered by ``total_events`` descending.  ``top_n`` bounds the
        result set; callers use "view all" pagination or a higher ``top_n`` to see
        the full tail.

        Each row:
            asn           — integer AS number (may be None for unresolved IPs)
            as_name       — AS organization name (may be None)
            total_events  — total log events from all IPs in this ASN
            distinct_ips  — number of distinct source IPs in this ASN
            blocked       — events with action IN ('BLOCK','DROP')
            blocked_pct   — blocked / total_events * 100 rounded to 1 dp (0 when 0 events)

        ADR-0029 D1 read-surface conventions: additive endpoint, no existing shape changed.
        """
        db = await self._read_conn()  # read-only (#313)

        # Group by asn/as_name from ip_geo joined with logs.
        # IPs with NULL asn are grouped together as a single "Unresolved" bucket
        # so the count is honest and visible (EARS-3: no silent drops).
        cursor = await db.execute(
            """
            SELECT g.asn,
                   g.as_name,
                   COUNT(*)                                                       AS total_events,
                   COUNT(DISTINCT l.source_ip)                                   AS distinct_ips,
                   SUM(CASE WHEN l.action IN ('BLOCK','DROP') THEN 1 ELSE 0 END) AS blocked
            FROM ip_geo g
            JOIN logs l ON g.ip = l.source_ip
            GROUP BY g.asn, g.as_name
            ORDER BY total_events DESC
            LIMIT ?
            """,
            (top_n,),
        )
        rows = await cursor.fetchall()
        result: list[dict[str, Any]] = []
        for r in rows:
            total = int(r["total_events"]) if r["total_events"] else 0
            blocked = int(r["blocked"]) if r["blocked"] else 0
            result.append(
                {
                    "asn": r["asn"],          # int or None
                    "as_name": r["as_name"],  # str or None
                    "total_events": total,
                    "distinct_ips": int(r["distinct_ips"]) if r["distinct_ips"] else 0,
                    "blocked": blocked,
                    "blocked_pct": (
                        round(blocked / total * 100, 1) if total else 0.0
                    ),
                }
            )
        return result

    async def get_ip_counterfactual(self, ip: str) -> dict[str, Any]:
        """Return the counterfactual impact counts for *ip* (issue #215).

        Computes, over ALL stored events for this IP:
          - ``total_events``   — total events in the logs table.
          - ``blocked_events`` — events with action IN ('BLOCK', 'DROP').
          - ``unblocked_events`` — total_events − blocked_events;
            i.e. events that a block would have stopped (ALLOW, ALERT, LOG).

        Semantic note (ADR-0012): Suricata IDS events carry action='ALERT'
        (detected, not stopped).  They are correctly counted in ``unblocked_events``
        because they WERE NOT blocked — this is honest per ADR-0012 semantics.
        An operator blocking the IP would have stopped them.  No per-source
        special-casing is applied; the arithmetic is source-agnostic.

        Window: ALL stored events for the IP (no time bound).  The recommendation
        queue already operates on the full-history ThreatScore; this is consistent
        with the card's ``total_events`` / ``blocked_events`` fields.  Adding a
        time-window query param is deferred; the current count is reproducible
        from the evidence link's unfiltered event list (EARS ubiquitous criterion).

        Returns ``{total_events: 0, blocked_events: 0, unblocked_events: 0}`` when
        the IP has no stored events (honest zero; never fabricated).
        """
        db = await self._read_conn()  # read-only (#313)
        cursor = await db.execute(
            """
            SELECT COUNT(*) AS total_events,
                   SUM(CASE WHEN action IN ('BLOCK', 'DROP') THEN 1 ELSE 0 END)
                       AS blocked_events
            FROM logs
            WHERE source_ip = ?
            """,
            (ip,),
        )
        row = await cursor.fetchone()
        total: int = int(row["total_events"]) if row and row["total_events"] else 0
        blocked: int = int(row["blocked_events"]) if row and row["blocked_events"] else 0
        return {
            "total_events": total,
            "blocked_events": blocked,
            "unblocked_events": total - blocked,
        }
