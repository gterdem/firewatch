"""Shared IP-address utility for geo enrichers.

Extracted from ``geo_enricher.py`` so both the online and offline enrichers
reuse the same guard without duplication.
"""
from __future__ import annotations

import ipaddress
import logging

logger = logging.getLogger("firewatch.geo_ip_utils")


def is_non_public(ip_str: str) -> bool:
    """Return True if the IP must NOT be sent to a public geo API or looked up.

    Covers:
    - Private ranges: RFC 1918 (10/8, 172.16/12, 192.168/16)
    - Loopback: 127/8, ::1
    - Link-local: 169.254/16 (RFC 3927), fe80::/10 (RFC 4291)
    - Unique local (IPv6 ULA): fc00::/7
    - Unspecified: 0.0.0.0, ::
    - Multicast: 224.0.0.0/4 (RFC 5771) — ``is_global`` returns True for multicast
      in CPython, so we check ``is_multicast`` explicitly.
    - Any other address that is not globally-reachable

    Returns True also for addresses that cannot be parsed (fail-safe).
    """
    try:
        addr = ipaddress.ip_address(ip_str)
        # is_global covers private, loopback, link-local, unspecified, and reserved.
        # Multicast (224/4) has is_global=True in CPython, so block it explicitly.
        return not addr.is_global or addr.is_multicast
    except ValueError:
        # Unparseable IP — treat as non-public to be safe
        logger.debug("Unparseable IP %r — skipping geo lookup", ip_str)
        return True
