"""Constants, shared exception, and row-conversion helper for the sqlite subpackage.

Nothing in this module opens a DB connection.  It is imported by every mixin
so that constants are defined in one place and the mixins reference them without
circular imports.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Final

from firewatch_sdk.models import SecurityEvent

logger = logging.getLogger("firewatch.sqlite")

# ---------------------------------------------------------------------------
# Public exception (ADR-0025)
# ---------------------------------------------------------------------------


class SourceKVCapExceededError(RuntimeError):
    """Raised when a source_kv_put would exceed the per-(source_type, namespace) row cap.

    Security note: the cap prevents a runaway or malicious plugin from bloating
    the shared database.  The caller's message includes source_type and namespace
    for diagnostics but never the value (which may be sensitive).
    """


# ---------------------------------------------------------------------------
# Default DB path — callers may override via __init__(db_path=…)
# ---------------------------------------------------------------------------

_DEFAULT_DB = Path("firewatch.db")

# ---------------------------------------------------------------------------
# source_kv constants (ADR-0025)
# ---------------------------------------------------------------------------

# Internal source_type token used by the rule_descriptions facade so it always
# resolves to a stable, globally-shared namespace regardless of which plugin is
# calling.  Starting with '_' ensures it cannot collide with a plugin type_key
# (those are constrained to ^[a-z][a-z0-9_]*$ — '_global' is not a valid plugin
# key because it starts with an underscore, ADR-0025 addendum BLOCKING-2).
_KV_GLOBAL_SOURCE_TYPE: str = "_global"
_KV_RULE_DESC_NAMESPACE: str = "rule_descriptions"

# Per-(source_type, namespace) row caps for source_kv (ADR-0025).
#
# SOURCE_KV_CAP — default cap for all namespaces except rule_descriptions.
#   Conservative by design: prevents a runaway or malicious plugin from bloating
#   the DB.  10 000 rows is sufficient for cursors, small lookup maps, and similar
#   auxiliary state.
#
# RULE_DESC_KV_CAP — elevated cap applied whenever namespace == _KV_RULE_DESC_NAMESPACE,
#   regardless of which source_type is writing.  This covers BOTH the plugin path
#   (source_type='suricata' writing via ScopedKV → source_kv_put) AND the core
#   facade path (upsert_rule_descriptions writing under source_type='_global').
#
#   Why namespace-aware cap routing here (not only in upsert_rule_descriptions)?
#   The live collect path is:
#     plugin → ctx.kv.put("rule_descriptions", sid, msg)
#       → _CoreScopedKV.put
#       → store.source_kv_put(source_type='suricata', namespace='rule_descriptions', ...)
#   If source_kv_put enforced SOURCE_KV_CAP for all namespaces, a 50k ET Open
#   ruleset would hit the 10k cap after 10k entries, bail with a single warning,
#   never store the fingerprint, and re-parse the 43MB file on every 30s cycle.
#   The cap must be elevated for the rule_descriptions namespace at this layer —
#   the only place where the raw namespace string is visible to the routing logic.
#   (issue #165, seam-gap fix post-PR-#186 review.)
#
#   The real-world ET Open ruleset ships ~50 000 rules; ET Pro is larger.
#   150 000 gives headroom for both without unbounded growth.
#
# Both are module-level Finals so they cannot be overridden on an instance
# (an instance-level override would be a mutable attribute anyone could patch).
SOURCE_KV_CAP: Final[int] = 10_000
RULE_DESC_KV_CAP: Final[int] = 150_000

# Private alias used to bootstrap the class attribute below without triggering
# a name-shadowing issue in the class body.
_SOURCE_KV_CAP_VALUE: int = SOURCE_KV_CAP

# ---------------------------------------------------------------------------
# Score history constants (issue #250)
# ---------------------------------------------------------------------------

# SCORE_HISTORY_DELTA_WINDOW_HOURS — default look-back window for computing
#   score_delta on the /threats list.  1 hour matches the Splunk ES precedent
#   for "recent risk score changes" and is documented in the API response.
#   The window is documented here so callers can reference this constant
#   rather than hard-coding the value.
#
# SCORE_HISTORY_RETENTION_DAYS — snapshots older than 7 days are pruned.
#   7 days gives the Risk Movers sparkline a week of trajectory while bounding
#   storage growth (bounded to ~days × distinct IPs × sample rate rows).
SCORE_HISTORY_DELTA_WINDOW_HOURS: Final[int] = 1
SCORE_HISTORY_RETENTION_DAYS: Final[int] = 7

# ---------------------------------------------------------------------------
# Canonical "blocked" action set (issue #252)
# ---------------------------------------------------------------------------

# The ONE definition of what "blocked" means in the store layer.  Every query
# that filters on blocked events references this frozenset so that adding or
# removing an action only requires a single change here.  Exposed as a
# module-level constant so the API route description and tests can cite it
# without duplicating the values.
BLOCKED_ACTIONS: frozenset[str] = frozenset({"BLOCK", "DROP"})

# NB-2: Guard the _BLOCKED_SQL_FRAG literal-interpolation at module load time.
# All values in BLOCKED_ACTIONS must match ^[A-Z]+$ — uppercase ASCII letters only.
# This assertion is cheap (frozenset is tiny) and prevents a future bad value
# (e.g. a quote or semicolon) from being silently interpolated into a SQL string.
_bad_actions = [a for a in BLOCKED_ACTIONS if not a.isalpha() or not a.isupper()]
assert not _bad_actions, (
    f"BLOCKED_ACTIONS contains invalid values {_bad_actions!r}; "
    "each action must match ^[A-Z]+$"
)

# SQL IN-clause fragment derived from BLOCKED_ACTIONS.  Sorted for determinism;
# all values are hard-coded string literals — never interpolated from user input.
_BLOCKED_SQL_FRAG: str = (
    "action IN ("
    + ", ".join(f"'{a}'" for a in sorted(BLOCKED_ACTIONS))
    + ")"
)

# ---------------------------------------------------------------------------
# Rule-id shorthand for get_paginated category filter (legacy compat)
# ---------------------------------------------------------------------------

_PAGINATED_PREFIX_MAP: dict[str, str] = {
    "sqli": "942",
    "xss": "941",
    "lfi": "930",
    "cmdi": "932",
    "proto": "920",
    "anomaly": "949",
    "bot": "300",
}
_PAGINATED_CONTAINS_MAP: dict[str, str] = {
    "ratelimit": "RateLimit",
    "geo": "GeoBlock",
}

# ---------------------------------------------------------------------------
# Row converter
# ---------------------------------------------------------------------------


def _row_to_security_event(d: dict[str, Any]) -> SecurityEvent:
    """Convert a raw logs-table row dict to a SecurityEvent.

    Only the columns that SecurityEvent declares are mapped; extra DB columns
    are silently dropped so new schema columns don't break deserialization.
    """
    raw_ts = d.get("timestamp", "")
    try:
        ts = datetime.fromisoformat(raw_ts)
    except (ValueError, TypeError):
        ts = datetime.now(timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)

    return SecurityEvent(
        source_type=d.get("source_type") or "unknown",
        source_id=d.get("source_id") or "default",
        source_ip=d.get("source_ip", ""),
        destination_port=d.get("destination_port") or None,
        destination_ip=d.get("destination_ip") or None,
        protocol=d.get("protocol") or None,
        action=d.get("action", "ALLOW"),  # type: ignore[arg-type]
        rule_id=d.get("rule_id") or None,
        rule_name=d.get("rule_name") or None,
        payload_snippet=d.get("payload_snippet") or None,
        timestamp=ts,
        severity=d.get("severity") or None,  # type: ignore[arg-type]
        category=d.get("category") or None,
        # ADR-0048 network-depth fields (ML-1): NULL in DB → None in model.
        bytes_in=d.get("bytes_in"),
        bytes_out=d.get("bytes_out"),
        packets_in=d.get("packets_in"),
        packets_out=d.get("packets_out"),
        flow_duration_ms=d.get("flow_duration_ms"),
        dns_query=d.get("dns_query") or None,
        dns_rcode=d.get("dns_rcode") or None,
        tls_ja4=d.get("tls_ja4") or None,
        tls_ja4s=d.get("tls_ja4s") or None,
        tls_sni=d.get("tls_sni") or None,
        tls_version=d.get("tls_version") or None,
        http_method=d.get("http_method") or None,
        http_host=d.get("http_host") or None,
        http_url=d.get("http_url") or None,
        http_user_agent=d.get("http_user_agent") or None,
        # ADR-0055 file-IOC / DNS-answer / JA3 fields (issue #602): NULL → None.
        # OCSF sources: File.hashes[] (algorithm_id 1/2/3), DNS Activity answers[].rdata,
        # ECS sources: file.hash.*, file.name, file.mime_type, dns.answers, tls.client.ja3
        file_sha256=d.get("file_sha256") or None,
        file_md5=d.get("file_md5") or None,
        file_sha1=d.get("file_sha1") or None,
        file_name=d.get("file_name") or None,
        file_mime_type=d.get("file_mime_type") or None,
        dns_answer=d.get("dns_answer") or None,
        tls_ja3=d.get("tls_ja3") or None,
    )
