"""_AnomalyMixin — flow_baseline + anomaly_verdicts (ML-10/ML-11)."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import aiosqlite


class _AnomalyMixin:
    """Handles upsert_flow_baseline, get_flow_baseline_entry,
    record_anomaly_verdict, upsert_flow_baseline_bytes,
    and get_flow_baseline_bytes."""

    async def _conn(self) -> aiosqlite.Connection: ...  # pragma: no cover
    async def _read_conn(self) -> aiosqlite.Connection: ...  # pragma: no cover

    async def upsert_flow_baseline(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None,
        first_seen: str,
        last_seen: str,
    ) -> None:
        """Upsert a (src_ip, dst_ip, dst_port) entry into the rolling flow baseline.

        On the first insert the entry is created with count=1.  On subsequent
        calls with the same key the count is incremented by 1 and last_seen is
        updated to the provided value.  first_seen is preserved (never overwritten).

        This is the write half of the rare-flow (first-seen) detector (EARS-3).
        Core-owned; plugins never call this directly.

        Security (ADR-0029 D3): all values flow through ? placeholders.
        dst_port is bound as an INTEGER (None -> NULL).
        """
        db = await self._conn()
        async with self._write_lock:  # type: ignore[attr-defined]
            await db.execute(
                """
                INSERT INTO flow_baseline (src_ip, dst_ip, dst_port, first_seen, last_seen, count)
                VALUES (?, ?, ?, ?, ?, 1)
                ON CONFLICT(src_ip, dst_ip, dst_port) DO UPDATE SET
                    last_seen = excluded.last_seen,
                    count = count + 1
                """,
                (src_ip, dst_ip, dst_port, first_seen, last_seen),
            )
            await db.commit()

    async def get_flow_baseline_entry(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None,
    ) -> dict[str, Any] | None:
        """Look up a (src_ip, dst_ip, dst_port) triple in the flow baseline.

        Returns the row dict ``{src_ip, dst_ip, dst_port, first_seen, last_seen,
        count}`` when the triple is known, or ``None`` when it is absent.

        This is the read half of the rare-flow (first-seen) detector (EARS-3).

        Security (ADR-0029 D3): all three lookup values flow through ? placeholders.
        dst_port NULL matching: SQLite's ``= ?`` with NULL does not match; we use
        ``IS ?`` which correctly matches NULL = NULL.
        """
        db = await self._read_conn()
        cursor = await db.execute(
            """
            SELECT src_ip, dst_ip, dst_port, first_seen, last_seen, count
            FROM flow_baseline
            WHERE src_ip = ? AND dst_ip = ? AND dst_port IS ?
            """,
            (src_ip, dst_ip, dst_port),
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return dict(row)

    async def record_anomaly_verdict(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int | None,
        anomaly_type: str,
        flag_reason: str | None,
    ) -> None:
        """Persist an anomaly verdict for (src_ip, dst_ip, dst_port, anomaly_type).

        On conflict (same primary key) the flag_reason and updated_at are
        refreshed (upsert).  The anomaly_type is an open string so future
        detectors (ML-11 volumetric exfil, etc.) extend the lane with no
        schema changes (EARS-2 extensibility requirement).

        flag_reason carries the ADR-0035 provenance string for R3 narration (EARS-4).

        Security (ADR-0029 D3): all values flow through ? placeholders.
        """
        db = await self._conn()
        now_iso = datetime.now(timezone.utc).isoformat()
        async with self._write_lock:  # type: ignore[attr-defined]
            await db.execute(
                """
                INSERT INTO anomaly_verdicts
                    (src_ip, dst_ip, dst_port, anomaly_type, flag_reason, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(src_ip, dst_ip, dst_port, anomaly_type) DO UPDATE SET
                    flag_reason = excluded.flag_reason,
                    updated_at  = excluded.updated_at
                """,
                (src_ip, dst_ip, dst_port, anomaly_type, flag_reason, now_iso),
            )
            await db.commit()

    async def upsert_flow_baseline_bytes(
        self,
        src_ip: str,
        dst_ip: str | None,
        dst_port: int | None,
        bytes_in: int | None,
        bytes_out: int | None,
    ) -> None:
        """Update per-flow Welford running byte stats in flow_baseline.

        Uses Welford's online algorithm to maintain a numerically stable running
        mean and M2 (sum of squared deviations) for both bytes_in and bytes_out.
        The sample standard deviation is ``sqrt(M2 / (n - 1))`` for n >= 2.

        Called by ``VolumetricDetector.check_volumetric`` on every event that
        carries at least one non-NULL byte counter.  When both bytes_in and
        bytes_out are None the caller must not call this method (NB-9 contract).

        The row is upserted (created on first observation, updated on subsequent
        ones) so the method is safe to call repeatedly on the same flow key.

        Security (ADR-0029 D3): all values flow through ? placeholders.
        dst_ip and dst_port are bound as-is (None -> NULL).

        Parameters
        ----------
        src_ip:
            Source IP address string.
        dst_ip:
            Destination IP address string, or None if not available.
        dst_port:
            Destination port integer, or None if not available.
        bytes_in:
            Bytes from responder to originator for this event (may be None).
        bytes_out:
            Bytes from originator to responder for this event (may be None).
        """
        # Treat None bytes as 0 for the Welford accumulator so both directions
        # always participate in the running stats.  A caller that sends one
        # direction as None and the other as non-None is considered partially
        # instrumented — the 0 for the missing direction is honest (no bytes
        # were observed on that side from this sensor).
        b_in: float = float(bytes_in) if bytes_in is not None else 0.0
        b_out: float = float(bytes_out) if bytes_out is not None else 0.0

        db = await self._conn()
        async with self._write_lock:  # type: ignore[attr-defined]
            # Read current stats for this flow (needs the write connection so
            # the read is inside the same lock and sees any uncommitted row).
            cursor = await db.execute(
                """
                SELECT bytes_in_mean, bytes_in_m2, bytes_out_mean, bytes_out_m2, bytes_count
                FROM flow_baseline
                WHERE src_ip = ? AND dst_ip IS ? AND dst_port IS ?
                """,
                (src_ip, dst_ip, dst_port),
            )
            row = await cursor.fetchone()

            if row is None or row["bytes_count"] is None:
                # First observation: initialise Welford state (n=1, mean=x, M2=0).
                await db.execute(
                    """
                    INSERT INTO flow_baseline
                        (src_ip, dst_ip, dst_port,
                         first_seen, last_seen, count,
                         bytes_in_mean, bytes_in_m2,
                         bytes_out_mean, bytes_out_m2,
                         bytes_count)
                    VALUES (?, ?, ?, ?, ?, 1, ?, 0.0, ?, 0.0, 1)
                    ON CONFLICT(src_ip, dst_ip, dst_port) DO UPDATE SET
                        bytes_in_mean  = ?,
                        bytes_in_m2    = 0.0,
                        bytes_out_mean = ?,
                        bytes_out_m2   = 0.0,
                        bytes_count    = 1
                    """,
                    (
                        src_ip, dst_ip, dst_port,
                        datetime.now(timezone.utc).isoformat(),
                        datetime.now(timezone.utc).isoformat(),
                        b_in, b_out,
                        # ON CONFLICT update values:
                        b_in, b_out,
                    ),
                )
            else:
                # Welford update step:
                #   n_new  = n + 1
                #   delta  = x - mean_old
                #   mean   = mean_old + delta / n_new
                #   delta2 = x - mean_new
                #   M2     = M2_old + delta * delta2
                n_old: int = row["bytes_count"]
                n_new: int = n_old + 1

                mean_in_old: float = row["bytes_in_mean"] or 0.0
                m2_in_old: float = row["bytes_in_m2"] or 0.0
                delta_in = b_in - mean_in_old
                mean_in_new = mean_in_old + delta_in / n_new
                delta2_in = b_in - mean_in_new
                m2_in_new = m2_in_old + delta_in * delta2_in

                mean_out_old: float = row["bytes_out_mean"] or 0.0
                m2_out_old: float = row["bytes_out_m2"] or 0.0
                delta_out = b_out - mean_out_old
                mean_out_new = mean_out_old + delta_out / n_new
                delta2_out = b_out - mean_out_new
                m2_out_new = m2_out_old + delta_out * delta2_out

                await db.execute(
                    """
                    UPDATE flow_baseline
                    SET bytes_in_mean  = ?,
                        bytes_in_m2    = ?,
                        bytes_out_mean = ?,
                        bytes_out_m2   = ?,
                        bytes_count    = ?
                    WHERE src_ip = ? AND dst_ip IS ? AND dst_port IS ?
                    """,
                    (
                        mean_in_new, m2_in_new,
                        mean_out_new, m2_out_new,
                        n_new,
                        src_ip, dst_ip, dst_port,
                    ),
                )

            await db.commit()

    async def get_flow_baseline_bytes(
        self,
        src_ip: str,
        dst_ip: str | None,
        dst_port: int | None,
    ) -> dict[str, Any] | None:
        """Return per-flow Welford byte stats from flow_baseline.

        Returns a dict with keys:
          ``bytes_count``    — number of observations (int).
          ``bytes_in_mean``  — running mean of bytes_in (float).
          ``bytes_in_m2``    — running M2 for bytes_in (float).
          ``bytes_out_mean`` — running mean of bytes_out (float).
          ``bytes_out_m2``   — running M2 for bytes_out (float).

        Returns None when no byte stats exist for this flow yet (the flow
        is either unknown or has not yet had a byte-carrying event).

        Security (ADR-0029 D3): all lookup values flow through ? placeholders.
        dst_ip and dst_port NULL matching: uses IS ? (matches NULL correctly).
        """
        db = await self._read_conn()
        cursor = await db.execute(
            """
            SELECT bytes_count, bytes_in_mean, bytes_in_m2,
                   bytes_out_mean, bytes_out_m2
            FROM flow_baseline
            WHERE src_ip = ? AND dst_ip IS ? AND dst_port IS ?
              AND bytes_count IS NOT NULL
            """,
            (src_ip, dst_ip, dst_port),
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return dict(row)
