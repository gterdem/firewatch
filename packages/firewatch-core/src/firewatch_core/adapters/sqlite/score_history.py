"""_ScoreHistoryMixin — score_history snapshots/deltas/prune (issue #250)."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import aiosqlite

from ._base import SCORE_HISTORY_RETENTION_DAYS


class _ScoreHistoryMixin:
    """Handles record_score_snapshot, get_score_history,
    get_bulk_score_deltas, and prune_score_snapshots."""

    async def _conn(self) -> aiosqlite.Connection: ...  # pragma: no cover
    async def _read_conn(self) -> aiosqlite.Connection: ...  # pragma: no cover

    async def record_score_snapshot(
        self, ip: str, score: int, ts: datetime
    ) -> None:
        """Persist a timestamped score snapshot for *ip*.

        Called by the pipeline AFTER ``analyze_ip`` computes a score (observation
        of output — never an input to scoring).  The write piggybacks pruning so
        the table self-cleans to ``SCORE_HISTORY_RETENTION_DAYS`` without a
        separate scheduler (issue #250 EARS "Retention" criterion).

        Parameters
        ----------
        ip:    source IP string.
        score: integer 0–100 matching ThreatScore.score.
        ts:    UTC datetime of the snapshot (usually ``datetime.now(UTC)``).

        Security note: ``ip`` and ``ts.isoformat()`` flow only through ``?``
        placeholders.  ``score`` is cast to ``int`` before passing.
        """
        db = await self._conn()
        async with self._write_lock:  # type: ignore[attr-defined]
            await db.execute(
                "INSERT INTO score_history (ip, score, ts) VALUES (?, ?, ?)",
                (ip, int(score), ts.isoformat()),
            )
            # Inline prune: DELETE rows beyond the 7-day retention horizon.
            # Running inside the same lock ensures no write races; the cost is
            # one extra DELETE per score-write which SQLite handles cheaply with
            # the ts index.
            cutoff = (
                ts - timedelta(days=SCORE_HISTORY_RETENTION_DAYS)
            ).isoformat()
            await db.execute(
                "DELETE FROM score_history WHERE ts < ?", (cutoff,)
            )
            await db.commit()

    async def get_score_history(
        self, ip: str, window_hours: float
    ) -> list[dict[str, Any]]:
        """Return per-IP score snapshots within *window_hours* of now.

        Returns rows in ascending time order (oldest first) so callers can
        render a chronological sparkline.  Unknown IPs return ``[]``.

        Each row is a dict ``{ip, score, ts}`` (ts is an ISO-8601 string).

        Parameters
        ----------
        ip:           source IP to query.
        window_hours: look-back window in hours (e.g. 24 for a 24-hour series).

        Security note: ``ip`` flows through a ``?`` placeholder; ``window_hours``
        is used only to compute the cutoff datetime and is never interpolated into
        SQL.
        """
        db = await self._read_conn()  # read-only (#313)
        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=window_hours)
        ).isoformat()
        cursor = await db.execute(
            "SELECT ip, score, ts FROM score_history"
            " WHERE ip = ? AND ts >= ?"
            " ORDER BY ts ASC",
            (ip, cutoff),
        )
        rows = await cursor.fetchall()
        return [{"ip": r["ip"], "score": r["score"], "ts": r["ts"]} for r in rows]

    async def get_bulk_score_deltas(
        self,
        ips: list[str],
        current_scores: dict[str, int],
        window_hours: float,
    ) -> dict[str, int | None]:
        """Compute signed score deltas for a list of IPs in ONE aggregate query.

        For each IP, the delta is ``current_score - earliest_score_in_window``.
        An IP with no prior snapshot in the window receives ``None``
        (semantics = "new actor"; the UI renders a NEW badge).

        A single GROUP BY query is used so this method has O(1) queries
        regardless of the number of IPs — no per-IP N+1 (issue #250 EARS E4).

        Parameters
        ----------
        ips:            list of source IPs to compute deltas for.
        current_scores: mapping of ip → current score (from the pipeline).
        window_hours:   look-back window in hours (default: SCORE_HISTORY_DELTA_WINDOW_HOURS).

        Returns
        -------
        dict[ip, delta | None]:
            delta is a signed integer or None (new actor / no prior snapshot).

        Security note: IPs are passed via a ``?``-placeholder list built with
        ``",".join("?" * len(ips))``.  The placeholder count is an integer derived
        from ``len(ips)`` — it is never user-controlled text.  ``window_hours``
        only feeds timedelta arithmetic, never SQL text.
        """
        if not ips:
            return {}

        db = await self._read_conn()  # read-only (#313)
        cutoff = (
            datetime.now(timezone.utc) - timedelta(hours=window_hours)
        ).isoformat()

        # Single GROUP BY query: for each ip in the window, fetch the earliest
        # snapshot score (MIN(ts) ↔ MIN score by correlation).
        # SQLite guarantees that MIN(ts) and its corresponding score are returned
        # when MIN() is applied to a non-aggregate column in the same SELECT — this
        # is a SQLite-specific extension that matches the "minimum ts row" semantics
        # we need (documented in https://www.sqlite.org/lang_select.html §Bare columns).
        placeholders = ",".join("?" * len(ips))
        # B5 safety invariant: only static string literals appear in the SQL text;
        # all user-controlled values flow through '?' placeholders.
        assert placeholders.replace(",", "").replace("?", "") == "", (
            "BUG: placeholders must contain only '?' and ',' characters"
        )
        # B5 note: the f-string interpolates only `placeholders` which consists
        # solely of '?' characters and commas — no user-controlled text.
        query = (
            "SELECT ip, score AS earliest_score, MIN(ts) AS earliest_ts"
            " FROM score_history"
            f" WHERE ip IN ({placeholders}) AND ts >= ?"
            " GROUP BY ip"
        )
        cursor = await db.execute(query, (*ips, cutoff))
        rows = await cursor.fetchall()

        # Build a lookup from ip → earliest_score for rows that exist in-window.
        prior: dict[str, int] = {r["ip"]: r["earliest_score"] for r in rows}

        result: dict[str, int | None] = {}
        for ip in ips:
            if ip in prior:
                result[ip] = current_scores.get(ip, 0) - prior[ip]
            else:
                result[ip] = None  # new actor

        return result

    async def prune_score_snapshots(self, retention_days: int) -> int:
        """Delete score_history rows older than *retention_days*.

        Returns the number of rows deleted.  Idempotent — safe to call
        repeatedly.  Called inline from ``record_score_snapshot`` so no
        separate scheduler is needed (issue #250 EARS "Retention" criterion).

        Parameters
        ----------
        retention_days: rows with ts < (now - retention_days) are deleted.

        Security note: ``retention_days`` feeds only timedelta arithmetic;
        it never appears as SQL text.
        """
        db = await self._conn()
        cutoff = (
            datetime.now(timezone.utc) - timedelta(days=retention_days)
        ).isoformat()
        async with self._write_lock:  # type: ignore[attr-defined]
            cursor = await db.execute(
                "DELETE FROM score_history WHERE ts < ?", (cutoff,)
            )
            await db.commit()
            return cursor.rowcount
