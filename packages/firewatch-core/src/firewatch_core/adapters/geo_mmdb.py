"""MmdbGeoEnricher — offline geo-enrichment via DB-IP Lite MMDB files.

Implements the ``firewatch_sdk.Enricher`` protocol (``name`` + ``enrich``).

Design decisions (ADR-0039)
---------------------------
* Two DB-IP Lite files:
  - IP-to-City Lite (MMDB) — country, city, lat, lon (CC-BY 4.0, no account)
  - IP-to-ASN Lite  (MMDB) — asn, as_name                (CC-BY 4.0, no account)
  DB-IP City Lite does NOT include ASN as of 2026-06-12 (verified at db-ip.com);
  ASN ships separately as the IP-to-ASN Lite database.
* Reader opened once at first ``enrich()`` call (lazy open so construction never
  raises on a missing file — fail-safe posture ADR-0003).
* Field set: exactly today's ``ip_geo`` shape — country, city, lat, lon, asn,
  as_name — persisted via ``store.upsert_ip_geo()``. No new fields (#391 parked).
* First-run download: if the DB files are absent and the host has connectivity,
  ``geo_mmdb_fetch.ensure_dbs()`` is called once to fetch them. After that all
  lookups are local.
* Fail-safe: missing / corrupt / unreadable DB after the download attempt →
  log a WARNING (with copy-in instruction) and return events unchanged. Never raises.
* Private/reserved IP guard: reuses ``geo_ip_utils.is_non_public`` — same guard
  as the online ``GeoEnricher``.
* Attribution: "IP Geolocation by DB-IP" per CC-BY 4.0 (documented in docs).

MMDB field paths used (DB-IP format, verified against community notes):
  City DB: record["country"]["names"]["en"], record["city"]["names"]["en"],
           record["location"]["latitude"], record["location"]["longitude"]
  ASN  DB: record["autonomous_system_number"],
           record["autonomous_system_organization"]
Fields absent in the record are stored as ``None`` (never fabricated).
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import maxminddb

from firewatch_core.adapters.geo_ip_utils import is_non_public
from firewatch_sdk.models import SecurityEvent
from firewatch_sdk.ports import EventStore

logger = logging.getLogger("firewatch.geo_mmdb")

# Copy-in instruction emitted in warnings so air-gapped operators know what to do.
_COPY_IN_HINT = (
    "To use offline geo in an air-gapped environment, download both DB-IP Lite files "
    "(IP-to-City and IP-to-ASN) from https://db-ip.com/db/download/ip-to-city-lite "
    "and https://db-ip.com/db/download/ip-to-asn-lite on a connected box, then copy "
    "them to the FireWatch data directory (see MI-4 / issue #385 for the exact path)."
)


def _extract_city_record(record: dict[str, Any]) -> dict[str, Any]:
    """Extract country/city/lat/lon from a DB-IP City Lite MMDB record.

    DB-IP City Lite field paths (MMDB format):
      country  → record["country"]["names"]["en"]
      city     → record["city"]["names"]["en"]
      lat      → record["location"]["latitude"]
      lon      → record["location"]["longitude"]

    Missing sub-keys → None, never fabricated (EARS criterion).
    """
    country: str | None = None
    city: str | None = None
    lat: float | None = None
    lon: float | None = None

    country_node = record.get("country")
    if isinstance(country_node, dict):
        names = country_node.get("names")
        if isinstance(names, dict):
            raw = names.get("en")
            country = str(raw) if raw is not None else None

    city_node = record.get("city")
    if isinstance(city_node, dict):
        names = city_node.get("names")
        if isinstance(names, dict):
            raw = names.get("en")
            city = str(raw) if raw is not None else None

    location = record.get("location")
    if isinstance(location, dict):
        raw_lat = location.get("latitude")
        raw_lon = location.get("longitude")
        lat = float(raw_lat) if raw_lat is not None else None
        lon = float(raw_lon) if raw_lon is not None else None

    return {"country": country, "city": city, "lat": lat, "lon": lon}


def _extract_asn_record(record: dict[str, Any]) -> dict[str, Any]:
    """Extract asn/as_name from a DB-IP ASN Lite MMDB record.

    DB-IP ASN Lite field paths:
      asn     → record["autonomous_system_number"]   (int)
      as_name → record["autonomous_system_organization"] (str)

    Missing fields → None, never fabricated.
    """
    raw_asn = record.get("autonomous_system_number")
    asn = int(raw_asn) if raw_asn is not None else None

    raw_org = record.get("autonomous_system_organization")
    as_name = str(raw_org) if raw_org is not None else None

    return {"asn": asn, "as_name": as_name}


class MmdbGeoEnricher:
    """Offline geo-enricher backed by DB-IP Lite MMDB files.

    Implements ``firewatch_sdk.Enricher``:
    - ``name: str`` — always ``"geo"``
    - ``async enrich(events) -> list[SecurityEvent]``

    Readers are opened lazily on the first ``enrich()`` call; construction
    never raises even when the files are absent (fail-safe; ADR-0003).

    Parameters
    ----------
    store:
        The ``EventStore`` used to query IPs needing geo and to persist results.
    city_db_path:
        Path to the DB-IP IP-to-City Lite MMDB file.
    asn_db_path:
        Path to the DB-IP IP-to-ASN Lite MMDB file.
    """

    name: str = "geo"

    def __init__(
        self,
        store: EventStore,
        city_db_path: Path,
        asn_db_path: Path,
    ) -> None:
        self._store = store
        self._city_db_path = city_db_path
        self._asn_db_path = asn_db_path
        # Readers opened lazily on first use
        self._city_reader: maxminddb.Reader | None = None
        self._asn_reader: maxminddb.Reader | None = None
        self._open_attempted = False

    # ------------------------------------------------------------------
    # Reader lifecycle
    # ------------------------------------------------------------------

    def _open_readers(self) -> bool:
        """Try to open both MMDB readers. Returns True if both opened successfully.

        Tries a first-run download first when files are absent. Logs a WARNING
        (with copy-in hint) and returns False on any failure (fail-safe).
        """
        if self._open_attempted:
            return self._city_reader is not None and self._asn_reader is not None
        self._open_attempted = True

        # Attempt first-run download if either file is absent
        if not self._city_db_path.exists() or not self._asn_db_path.exists():
            self._try_first_run_fetch()

        # Now try to open whatever is present
        return self._try_open_readers()

    def _try_first_run_fetch(self) -> None:
        """Attempt to download the DB-IP Lite files. Logs and continues on failure."""
        try:
            from firewatch_core.adapters.geo_mmdb_fetch import ensure_dbs

            ensure_dbs(
                city_db_path=self._city_db_path,
                asn_db_path=self._asn_db_path,
            )
        except Exception as exc:
            logger.warning(
                "geo_mmdb: first-run DB download failed (%s). "
                "Geo enrichment will be skipped. %s",
                exc,
                _COPY_IN_HINT,
            )

    def _try_open_readers(self) -> bool:
        """Open both readers from disk. Returns True on success; logs WARNING on failure."""
        from maxminddb.errors import InvalidDatabaseError

        try:
            city_reader = maxminddb.open_database(str(self._city_db_path))
            self._city_reader = city_reader
        except (OSError, InvalidDatabaseError, Exception) as exc:
            logger.warning(
                "geo_mmdb: cannot open City DB at %s (%s). "
                "Geo enrichment will be skipped. %s",
                self._city_db_path,
                exc,
                _COPY_IN_HINT,
            )
            return False

        try:
            asn_reader = maxminddb.open_database(str(self._asn_db_path))
            self._asn_reader = asn_reader
        except (OSError, InvalidDatabaseError, Exception) as exc:
            logger.warning(
                "geo_mmdb: cannot open ASN DB at %s (%s). "
                "Geo enrichment will be skipped. %s",
                self._asn_db_path,
                exc,
                _COPY_IN_HINT,
            )
            return False

        return True

    # ------------------------------------------------------------------
    # Lookup helpers
    # ------------------------------------------------------------------

    def _lookup_ip(self, ip: str) -> dict[str, Any] | None:
        """Look up a single IP in both DBs and return a merged geo dict, or None.

        Returns None when either reader is unavailable. Fields missing in a DB
        record are stored as None (never fabricated per EARS criterion).
        """
        if self._city_reader is None or self._asn_reader is None:
            return None

        try:
            city_record = self._city_reader.get(ip)
            city_data = (
                _extract_city_record(city_record)  # type: ignore[arg-type]
                if isinstance(city_record, dict)
                else {"country": None, "city": None, "lat": None, "lon": None}
            )
        except Exception as exc:
            logger.debug("geo_mmdb: city lookup error for %s: %s", ip, exc)
            city_data = {"country": None, "city": None, "lat": None, "lon": None}

        try:
            asn_record = self._asn_reader.get(ip)
            asn_data = (
                _extract_asn_record(asn_record)  # type: ignore[arg-type]
                if isinstance(asn_record, dict)
                else {"asn": None, "as_name": None}
            )
        except Exception as exc:
            logger.debug("geo_mmdb: asn lookup error for %s: %s", ip, exc)
            asn_data = {"asn": None, "as_name": None}

        return {"ip": ip, **city_data, **asn_data}

    # ------------------------------------------------------------------
    # Enricher protocol
    # ------------------------------------------------------------------

    async def enrich(self, events: list[SecurityEvent]) -> list[SecurityEvent]:
        """Look up geo data for any IPs that lack it and persist the results.

        Steps:
        1. Open MMDB readers (lazy; triggers first-run fetch when absent).
        2. Ask the store which IPs have no geo data yet.
        3. Filter out private/reserved/multicast IPs (same guard as GeoEnricher).
        4. Look up each IP in City + ASN DBs.
        5. Persist resolved data via ``store.upsert_ip_geo()``.
        6. Return the original ``events`` list unmodified.

        Fail-safe: any DB error, reader failure, or unexpected exception is
        caught and logged at WARNING; events are returned unchanged. Never raises.
        """
        if not events:
            return events

        await self._resolve_and_persist()
        return events

    async def backfill_geo(self) -> None:
        """Resolve geo for all IPs in get_ips_without_geo(), decoupled from event flow.

        Called once at startup (via Pipeline.startup_backfill) to backfill
        historical IPs that were ingested before the MMDB files were available.
        Unlike enrich(), this method has no event list — it resolves outstanding
        IPs regardless of new event flow (issue #637).

        Fail-safe: any error (readers unavailable, store error) is caught and
        logged at WARNING; never raises (ADR-0003).
        """
        await self._resolve_and_persist()

    async def _resolve_and_persist(self) -> None:
        """Core geo resolution logic shared by enrich() and backfill_geo().

        Opens MMDB readers (lazy, triggers first-run fetch when absent), queries
        the store for IPs lacking geo, filters private IPs, looks each one up in
        the City + ASN DBs, and persists results via store.upsert_ip_geo().

        Fail-safe: returns silently on any error without raising.
        """
        # Open or check readers (triggers first-run fetch if needed)
        if not self._open_readers():
            return

        try:
            ips_needing_geo = await self._store.get_ips_without_geo()
        except Exception as exc:  # pragma: no cover
            logger.warning("geo_mmdb: could not query ips_without_geo: %s", exc)
            return

        public_ips = [ip for ip in ips_needing_geo if not is_non_public(ip)]
        if not public_ips:
            return

        resolved: list[dict[str, Any]] = []
        for ip in public_ips:
            row = self._lookup_ip(ip)
            if row is not None:
                resolved.append(row)

        if resolved:
            try:
                await self._store.upsert_ip_geo(resolved)
                logger.info(
                    "geo_mmdb: resolved %d/%d IPs (offline MMDB)",
                    len(resolved),
                    len(public_ips),
                )
            except Exception as exc:  # pragma: no cover
                logger.warning("geo_mmdb: upsert_ip_geo failed: %s", exc)
