"""Queryable FilterSpec vocabulary — enumerated from store schema at runtime.

ADR-0049 Decision 1: the NL vocabulary is the set of columns that
``get_paginated``/aggregates can actually filter on, NOT the full SecurityEvent
field list.  A field that exists on the model but is not yet persisted/queryable
(the historical ``destination_ip`` trap) is NEVER advertised to the LLM.

This module declares ``QUERYABLE_FIELDS`` — the authoritative list of fields
that are:
  (a) present in the ``logs`` table with a real WHERE clause in
      ``SQLiteEventStore.get_paginated``, AND
  (b) safe to expose to the NL→FilterSpec pipeline as queryable vocabulary.

Any future column that gains a WHERE clause in ``get_paginated`` must also be
added here; any field removed from ``get_paginated`` must be removed here.
The test suite (test_nl_vocabulary.py) enforces that every key here corresponds
to a real FilterSpec field — acting as a structural gate against drift.

Excluded from vocabulary on purpose:
  - ``cursor``           — internal pagination token, not a meaningful NL filter.
  - ``q``               — free-text fallback, not a discrete vocabulary term.
  - ``category_name``   — deprecated synonym; ``category`` covers it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


MatchType = Literal["exact", "substring", "enum"]


@dataclass(frozen=True)
class FilterField:
    """Descriptor for one queryable FilterSpec field.

    Attributes
    ----------
    key:
        The FilterSpec field name (e.g. ``"ip"``, ``"action"``).
    label:
        Human-readable name shown in the prompt (e.g. ``"source IP"``).
    match_type:
        ``"exact"``     — value must match the stored value exactly (e.g. protocol).
        ``"substring"`` — value is used as a LIKE substring (e.g. source IP prefix).
        ``"enum"``      — value must be one of the ``examples`` (e.g. action).
    description:
        One-line description of what filtering on this field does.
    examples:
        Representative allowed values.  For ``enum`` fields this is the exhaustive
        set; for ``substring`` / ``exact`` fields these are illustrative samples.
    """

    key: str
    label: str
    match_type: MatchType
    description: str
    examples: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Authoritative queryable field list (ADR-0049 Decision 1).
#
# Ordering: most-useful NL filters first (source IP, action, severity).
# Adding a new field here requires a matching WHERE clause in get_paginated.
# ---------------------------------------------------------------------------

QUERYABLE_FIELDS: tuple[FilterField, ...] = (
    FilterField(
        key="ip",
        label="source IP",
        match_type="substring",
        description=(
            "Filter by the attacker/client source IP address. "
            "Accepts a prefix or full IP (IPv4 or IPv6)."
        ),
        examples=["192.0.2", "198.51.100.1", "203.0.113"],
    ),
    FilterField(
        key="action",
        label="action",
        match_type="enum",
        description=(
            "Filter by the event disposition action. "
            "Use 'blocked' as shorthand for BLOCK+DROP."
        ),
        examples=["BLOCK", "DROP", "ALERT", "ALLOW", "LOG", "blocked"],
    ),
    FilterField(
        key="severity",
        label="severity",
        match_type="enum",
        description="Filter by event severity level.",
        examples=["critical", "high", "medium", "low"],
    ),
    FilterField(
        key="category",
        label="category",
        match_type="exact",
        description=(
            "Filter by the stored event category (e.g. attack type). "
            "Use the exact value as stored by the source."
        ),
        examples=["SQL Injection", "XSS", "Brute Force", "Port Scan"],
    ),
    FilterField(
        key="source_type",
        label="source type",
        match_type="exact",
        description=(
            "Filter by the telemetry source plugin type "
            "(e.g. suricata, azure_waf, syslog)."
        ),
        examples=["suricata", "azure_waf", "syslog"],
    ),
    FilterField(
        key="source_id",
        label="source instance",
        match_type="exact",
        description=(
            "Filter by the named source instance (e.g. pi-home, azure-juiceshop). "
            "Use source_type= unless you need a specific sensor."
        ),
        examples=["pi-home", "vm-target"],
    ),
    FilterField(
        key="rule",
        label="rule ID",
        match_type="substring",
        description="Filter by rule identifier substring (rule_id column).",
        examples=["2100498", "942", "ET SCAN"],
    ),
    FilterField(
        key="destination_ip",
        label="destination IP",
        match_type="substring",
        description=(
            "Filter by destination IP address substring (ADR-0048 / ML-1). "
            "Only rows where the sensor populated destination_ip participate."
        ),
        examples=["10.0.0", "192.168.1"],
    ),
    FilterField(
        key="protocol",
        label="protocol",
        match_type="exact",
        description=(
            "Filter by network protocol. "
            "Sources that do not populate protocol (e.g. Azure WAF) will not match."
        ),
        examples=["TCP", "UDP", "ICMP"],
    ),
    FilterField(
        key="tls_ja4",
        label="JA4 TLS fingerprint",
        match_type="exact",
        description=(
            "Filter by JA4 TLS client fingerprint (ML-13 / ADR-0048). "
            "Only rows where the sensor emitted a JA4 value participate."
        ),
        examples=["t13d1517h2_8daaf6152771_b0da82dd1658"],
    ),
)


def get_vocabulary() -> list[FilterField]:
    """Return the current queryable vocabulary as a list.

    ADR-0049 Decision 1: the vocabulary is enumerated from the store-queryable
    column set at runtime.  ``QUERYABLE_FIELDS`` is the authoritative source;
    this function is the public accessor (allows future dynamic augmentation
    without changing call sites).

    Returns
    -------
    list[FilterField]
        Ordered list of queryable fields.  The order matches the declaration
        order above (most-useful NL filters first).
    """
    return list(QUERYABLE_FIELDS)
