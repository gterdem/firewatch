"""_GeoMixin — ip_geo cache + watermark (sync_state) accessors."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import aiosqlite


class _GeoMixin:
    """Handles get_ips_without_geo, get_ip_geo, upsert_ip_geo,
    get_watermark, and set_watermark."""

    async def _conn(self) -> aiosqlite.Connection: ...  # pragma: no cover
    async def _read_conn(self) -> aiosqlite.Connection: ...  # pragma: no cover
    @staticmethod
    def _watermark_key(source_type: str, source_id: str) -> str: ...  # pragma: no cover

    async def get_ips_without_geo(self) -> list[str]:
        db = await self._read_conn()  # read-only (#313)
        cursor = await db.execute(
            "SELECT DISTINCT source_ip FROM logs"
            " WHERE source_ip NOT IN (SELECT ip FROM ip_geo)"
        )
        return [r["source_ip"] for r in await cursor.fetchall()]

    async def get_ip_geo(self, ip: str) -> dict[str, Any] | None:
        """Return the cached geo row for *ip*, or ``None`` when absent.

        Columns: ``country``, ``city``, ``lat``, ``lon``, ``asn``, ``as_name``.
        Added in issue #132 to populate ``ThreatScore.location``; extended in
        issue #211 to include ASN fields (asn/as_name follow ECS §as naming).
        ``asn``/``as_name`` are ``None`` for rows cached before issue #211 or
        when the provider did not return AS data.
        """
        db = await self._read_conn()  # read-only (#313)
        cursor = await db.execute(
            "SELECT country, city, lat, lon, asn, as_name FROM ip_geo WHERE ip = ?",
            (ip,),
        )
        row = await cursor.fetchone()
        if row is None:
            return None
        return {
            "country": row["country"] or "",
            "city": row["city"] or "",
            "lat": row["lat"] or 0.0,
            "lon": row["lon"] or 0.0,
            "asn": row["asn"],        # int or None
            "as_name": row["as_name"],  # str or None
        }

    async def upsert_ip_geo(self, geo_data: list[dict[str, Any]]) -> None:
        """Persist geo (and ASN) rows for a list of IPs.

        Each dict in *geo_data* may include the additive ASN fields introduced in
        issue #211: ``asn`` (int or None) and ``as_name`` (str or None).  Callers
        that omit these keys receive NULL in the database — no data is lost and no
        exception is raised (backward-compatible).
        """
        if not geo_data:
            return
        db = await self._conn()
        now = datetime.now(timezone.utc).isoformat()
        async with self._write_lock:  # type: ignore[attr-defined]
            await db.executemany(
                "INSERT OR REPLACE INTO ip_geo"
                " (ip, country, city, lat, lon, asn, as_name, updated_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        g["ip"],
                        g.get("country", ""),
                        g.get("city", ""),
                        g.get("lat", 0.0),
                        g.get("lon", 0.0),
                        g.get("asn"),       # None when absent (NULL in DB)
                        g.get("as_name"),   # None when absent (NULL in DB)
                        now,
                    )
                    for g in geo_data
                ],
            )
            await db.commit()

    async def get_watermark(self, source_type: str, source_id: str) -> str | None:
        # WAL snapshot isolation note: the read connection sees a consistent
        # snapshot from before the most-recent write connection commit.  Under WAL
        # the lag is sub-millisecond (one checkpoint cycle, triggered at 1 000 pages
        # by default).  In the worst case a concurrent collect cycle reads a stale
        # watermark and re-ingests one cycle of events; save_many's INSERT OR IGNORE
        # absorbs the duplicates without any data loss or integrity violation.
        # This is acceptable-eventual for a single-process asyncio.Lock-serialized
        # writer (ADR-0007 / issue #313 Fix 2).
        db = await self._read_conn()  # read-only (#313)
        key = self._watermark_key(source_type, source_id)
        cursor = await db.execute(
            "SELECT value FROM sync_state WHERE key = ?", (key,)
        )
        row = await cursor.fetchone()
        return row["value"] if row else None

    async def set_watermark(
        self, ts: str, source_type: str, source_id: str
    ) -> None:
        db = await self._conn()
        key = self._watermark_key(source_type, source_id)
        async with self._write_lock:  # type: ignore[attr-defined]
            await db.execute(
                "INSERT OR REPLACE INTO sync_state (key, value) VALUES (?, ?)",
                (key, ts),
            )
            await db.commit()
