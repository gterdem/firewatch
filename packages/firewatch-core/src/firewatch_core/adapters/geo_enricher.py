"""GeoEnricher — concrete Enricher that geo-locates IPs via ip-api.com.

Implements the ``firewatch_sdk.Enricher`` protocol (``name`` + ``enrich``).
Ported from ``legacy/app/sync.py:geo_lookup_ips`` (reference only; never imported).

Design decisions
----------------
* Provider: ip-api.com batch endpoint (free tier, no API key required for <45 req/min).
  Same provider as v1. An optional ``api_key`` (``SecretStr``) enables the pro plan.
  When a key is set the pro base URL (``_GEO_PRO_URL``) is used and the key is passed
  via ``params={"key": ...}`` — never interpolated into the URL string.
* Private/reserved IP guard: ``ipaddress.ip_address(...).is_global`` plus an explicit
  multicast check.  IPs that are not globally routable — or that are multicast — are
  skipped without calling the API (SSRF guard).  ``0.0.0.0`` is treated as non-routable.
  Multicast (224.0.0.0/4) is blocked explicitly because Python's ``is_global`` returns
  True for multicast addresses (CPython ≥3.11 behaviour; RFC 5771 §4).
* Response-query validation (NB-3): only results whose ``query`` field matches one of
  the IPs we actually sent are persisted.  This removes the store-poisoning vector a
  MITM could exploit over the plain-HTTP free tier.
* Fail-safe posture (ADR-0003): any HTTP error, timeout, or unexpected exception is
  caught per-batch; events are returned unmodified. Never raises to the caller.
* Batch size: 100 IPs per request (ip-api.com hard limit for the batch endpoint).
"""
from __future__ import annotations

import logging
from typing import Any

import httpx
from pydantic import SecretStr

from firewatch_core.adapters.geo_ip_utils import is_non_public
from firewatch_sdk.models import SecurityEvent
from firewatch_sdk.ports import EventStore

logger = logging.getLogger("firewatch.geo_enricher")

# Backward-compatible alias: existing tests patch ``geo_enricher._is_non_public``.
# Keep this shim so those tests continue to work unchanged.
_is_non_public = is_non_public

# ip-api.com free-tier batch endpoint; fields we need.
# 'as' and 'asname' are available on both free and pro tiers (issue #211).
# ip-api.com field reference: https://ip-api.com/docs/api:batch
#
# NB-3 (security): The free tier does NOT support HTTPS — ip-api.com free plan
# is HTTP-only (documented at https://ip-api.com/docs). Because no API key is
# sent on the free path, the only attack surface is response tampering (MITM).
# That vector is already mitigated by the response-query validation in enrich()
# (NB-3 guard: only accept entries whose ``query`` is in the sent chunk).
_GEO_FREE_URL = (
    "http://ip-api.com/batch?fields=status,query,country,city,lat,lon,as,asname"
)

# ip-api.com Pro batch endpoint (used when api_key is set).
# The Pro plan supports HTTPS — use it so the API key is NOT sent in cleartext.
# Reference: https://pro.ip-api.com/docs (HTTPS required for Pro tier).
# The key is passed via params=, never interpolated into the URL string.
_GEO_PRO_URL = (
    "https://pro.ip-api.com/batch?fields=status,query,country,city,lat,lon,as,asname"
)

# ip-api.com hard limit per batch request
_BATCH_SIZE = 100

# HTTP timeout for the geo API (seconds)
_TIMEOUT = 15.0


def _parse_asn(as_field: str | None) -> int | None:
    """Parse the integer AS number from an ip-api.com 'as' field string.

    ip-api.com returns the 'as' field as e.g. ``"AS4837 CHINA UNICOM China169 Backbone"``.
    This function extracts the numeric suffix of the ``AS`` prefix token and returns it
    as an integer.  Returns ``None`` when the field is absent, empty, or not parseable
    (tolerate absence per EARS-2 fail-safe posture).

    Examples::

        _parse_asn("AS4837 CHINA UNICOM")  -> 4837
        _parse_asn("AS15169 GOOGLE")       -> 15169
        _parse_asn(None)                   -> None
        _parse_asn("")                     -> None
        _parse_asn("unknown")              -> None
    """
    if not as_field:
        return None
    first_token = as_field.split()[0] if as_field.strip() else ""
    if first_token.upper().startswith("AS"):
        numeric = first_token[2:]
        if numeric.isdigit():
            return int(numeric)
    return None


class GeoEnricher:
    """Geo-locates IPs stored in the EventStore by calling ip-api.com.

    Implements ``firewatch_sdk.Enricher``:
    - ``name: str`` — always ``"geo"``
    - ``async enrich(events) -> list[SecurityEvent]``

    Usage (pipeline / scheduler calls this after a pull cycle):

        enricher = GeoEnricher(store=my_store)
        events = await enricher.enrich(events)

    The enricher reads ``store.get_ips_without_geo()``, looks them up, and calls
    ``store.upsert_ip_geo()``. This fills the ``ip_geo`` table so that
    ``store.get_analytics_geo()`` and ``store.get_analytics_summary()`` return rows.
    """

    name: str = "geo"

    def __init__(
        self,
        store: EventStore,
        api_key: SecretStr | None = None,
    ) -> None:
        """
        Parameters
        ----------
        store:
            The ``EventStore`` used to query IPs needing geo and to persist results.
        api_key:
            Optional ip-api.com Pro API key (``SecretStr``). When supplied the pro
            endpoint (``_GEO_PRO_URL``) is used, which removes the rate limit, and the
            key is passed via ``params={"key": ...}``.  Never pass a plain ``str``.
            Calling ``.get_secret_value()`` happens only at the request site — the
            secret is never logged or stored in the URL string.
        """
        self._store = store
        self._api_key = api_key

    def _geo_url(self) -> tuple[str, dict[str, str] | None]:
        """Return (url, params) for the current tier.

        Free tier: (``_GEO_FREE_URL``, None)
        Pro tier:  (``_GEO_PRO_URL``, {"key": <secret>})

        ``.get_secret_value()`` is called only here, at the request site.
        """
        if self._api_key is not None:
            return _GEO_PRO_URL, {"key": self._api_key.get_secret_value()}
        return _GEO_FREE_URL, None

    async def enrich(self, events: list[SecurityEvent]) -> list[SecurityEvent]:
        """Look up geo data for any IPs that lack it and persist the results.

        Steps:
        1. Ask the store which IPs have no geo data yet.
        2. Filter out private/reserved/multicast IPs (SSRF guard).
        3. Batch-request geo data from ip-api.com (≤100 IPs per call).
        4. Validate each response entry: only persist if ``response["query"]`` was
           in the batch we sent (store-poisoning / MITM guard).
        5. Persist resolved data via ``store.upsert_ip_geo()``.
        6. Return the original ``events`` list unmodified (enrichment is store-side).

        Fail-safe: any HTTP or unexpected error is caught per-batch, logged at WARNING,
        and the enricher returns events unchanged. Never raises.
        """
        if not events:
            return events

        await self._resolve_and_persist()
        return events

    async def backfill_geo(self) -> None:
        """Resolve geo for all IPs in get_ips_without_geo(), decoupled from event flow.

        Called once at startup (via Pipeline.startup_backfill) to backfill
        historical IPs that were ingested before geo was working or before the
        ip-api.com provider was reachable (issue #637).

        Unlike enrich(), this method has no event list — it resolves outstanding
        IPs regardless of new event flow.

        Fail-safe: any HTTP or store error is caught and logged at WARNING; never
        raises (ADR-0003).
        """
        await self._resolve_and_persist()

    async def _resolve_and_persist(self) -> None:
        """Core geo resolution logic shared by enrich() and backfill_geo().

        Queries the store for IPs lacking geo, filters private/reserved/multicast
        IPs (SSRF guard), batch-requests ip-api.com (NB-3 query validation), and
        persists results via store.upsert_ip_geo().

        Fail-safe: returns silently on any error without raising.
        """
        try:
            ips_needing_geo = await self._store.get_ips_without_geo()
        except Exception as exc:  # pragma: no cover
            logger.warning("geo_enricher: could not query ips_without_geo: %s", exc)
            return

        # Filter to only globally-routable, non-multicast IPs
        public_ips = [ip for ip in ips_needing_geo if not _is_non_public(ip)]

        if not public_ips:
            return

        url, params = self._geo_url()
        resolved: list[dict[str, Any]] = []

        async with httpx.AsyncClient(timeout=_TIMEOUT) as client:
            for i in range(0, len(public_ips), _BATCH_SIZE):
                chunk = public_ips[i : i + _BATCH_SIZE]
                chunk_set = set(chunk)  # NB-3: only accept responses for IPs we sent
                try:
                    resp = await client.post(
                        url,
                        params=params,
                        json=[{"query": ip} for ip in chunk],
                    )
                    resp.raise_for_status()
                    data: list[dict[str, Any]] = resp.json()
                    for d in data:
                        # NB-3: reject entries whose query is not in the sent chunk
                        if d.get("status") == "success" and d.get("query") in chunk_set:
                            # ASN fields (issue #211): 'as' and 'asname' are present
                            # on both free and pro tiers. Absent fields are tolerated
                            # per EARS-2 fail-safe posture — store None, not a default.
                            as_raw: str | None = d.get("as") or None
                            resolved.append(
                                {
                                    "ip": d["query"],
                                    "country": d.get("country", ""),
                                    "city": d.get("city", ""),
                                    "lat": float(d.get("lat", 0.0)),
                                    "lon": float(d.get("lon", 0.0)),
                                    "asn": _parse_asn(as_raw),
                                    "as_name": d.get("asname") or None,
                                }
                            )
                except Exception as exc:
                    logger.warning(
                        "geo_enricher: batch lookup failed for chunk starting at %s: %s",
                        chunk[0],
                        exc,
                    )
                    # Fail-safe: continue with next batch / return what we have so far

        if resolved:
            try:
                await self._store.upsert_ip_geo(resolved)
                logger.info(
                    "geo_enricher: resolved %d/%d IPs",
                    len(resolved),
                    len(public_ips),
                )
            except Exception as exc:  # pragma: no cover
                logger.warning("geo_enricher: upsert_ip_geo failed: %s", exc)
