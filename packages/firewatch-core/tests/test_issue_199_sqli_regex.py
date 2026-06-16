"""Regression tests for issue #199 — SQLi regex false-positive / false-negative audit.

EARS spec (from issue #199):
  WHEN events contain URIs like /.env.orig or /.ssh/authorized_keys and no SQL syntax,
    THEN attack_types SHALL NOT include sql_injection.
  WHEN a payload contains ' OR 1=1 or UNION SELECT,
    THEN attack_types SHALL include sql_injection.

Additional sibling-pattern audit per issue scope:
  UNION SELECT and DROP TABLE must be word-boundary anchored.
  XSS patterns are audited for over-broad zero-width matches.

ADR-0024: classification pins to canonical standards, never legacy —
the r"\\s*OR" pattern was ported verbatim from v1 and is broken; these
tests encode the correct standard-aligned behaviour.
"""
from __future__ import annotations

import pytest

from firewatch_core.scoring import run_rules
from _fakes import make_event


# ---------------------------------------------------------------------------
# EARS: false-positive regression — filenames containing "or" MUST NOT fire
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "uri",
    [
        "/.env.orig",
        "/.ssh/authorized_keys",
        "/wp-config.php.orig",
        "/robots.txt.bak.orig",
        "/store/products",           # "or" inside word "store"/"products"
        "/vendor/autoload.php",      # "or" inside "vendor"/"autoload"
        "/wordpress/wp-login.php",   # "or" inside "wordpress"
    ],
)
def test_uri_with_or_substring_does_not_fire_sqli(uri: str) -> None:
    """URIs that contain the letters 'or' but carry no SQL syntax must not trigger
    sql_injection.  The broken r'\\s*OR' pattern matched zero whitespace so any
    occurrence of the substring was a hit — this test pins the fix."""
    events = [make_event(action="BLOCK", payload_snippet=uri)]
    _, attack_types = run_rules(events)
    assert "sql_injection" not in attack_types, (
        f"False positive: payload {uri!r} incorrectly classified as sql_injection. "
        "r'\\s*OR' with zero-width \\s* must be replaced with a context-anchored pattern."
    )


# ---------------------------------------------------------------------------
# EARS: true-positive — real SQL injection payloads MUST fire
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        "' OR 1=1",
        "' OR 1=1--",
        "' OR '1'='1",
        "1' OR '1'='1",
        "admin'  OR  '1'='1",          # multiple spaces (\s+)
        "x' OR(1=1)--",                # OR immediately followed by '('
    ],
)
def test_boolean_or_sqli_fires(payload: str) -> None:
    """Classic boolean OR injection patterns (quote + OR + space/paren) must be detected."""
    events = [make_event(action="BLOCK", payload_snippet=payload)]
    _, attack_types = run_rules(events)
    assert "sql_injection" in attack_types, (
        f"False negative: payload {payload!r} not classified as sql_injection."
    )


# ---------------------------------------------------------------------------
# Security-review follow-up: numeric-context OR payloads (no leading quote)
# These FAILED the previous r"'\\s*OR\\b" pattern (3/10 OWASP §4.7.5 coverage).
# The two-alternative _BOOL_OR pattern achieves 10/10.
# Ref: OWASP Testing Guide v4.2 §4.7.5; sqlmap default payload set.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        "1 OR 1=1",            # sqlmap default numeric-context boolean injection
        "1 OR 1=1--",          # with SQL comment terminator
        ") OR (1=1",           # paren-context (closing a subquery)
        "1 OR 2>1",            # alternative numeric comparison (sqlmap variant)
    ],
)
def test_numeric_context_boolean_or_sqli_fires(payload: str) -> None:
    """Numeric-context boolean OR payloads (no leading quote) must be detected.

    These all FAILED the previous r"'\\s*OR\\b" pattern because they do not
    start with a single-quote.  The two-alternative _BOOL_OR pattern covers them.
    Failing this test means the OR pattern has regressed to quote-only coverage.
    """
    events = [make_event(action="BLOCK", payload_snippet=payload)]
    _, attack_types = run_rules(events)
    assert "sql_injection" in attack_types, (
        f"False negative: numeric-context OR payload {payload!r} not classified as "
        "sql_injection.  The boolean-OR pattern must cover non-quote-led payloads."
    )


@pytest.mark.parametrize(
    "payload",
    [
        "UNION SELECT 1,2,3",
        "UNION SELECT username,password FROM users",
        "1 UNION SELECT null--",
        "union select 1",                        # case-insensitive
        "' UNION  SELECT  1 --",                 # multiple spaces
    ],
)
def test_union_select_sqli_fires(payload: str) -> None:
    """UNION SELECT injection must be detected, case-insensitively."""
    events = [make_event(action="BLOCK", payload_snippet=payload)]
    _, attack_types = run_rules(events)
    assert "sql_injection" in attack_types, (
        f"False negative: payload {payload!r} not classified as sql_injection."
    )


@pytest.mark.parametrize(
    "payload",
    [
        "DROP TABLE users",
        "DROP TABLE IF EXISTS sessions",
        "drop table logs",                        # case-insensitive
        "'; DROP TABLE users --",
    ],
)
def test_drop_table_sqli_fires(payload: str) -> None:
    """DROP TABLE injection must be detected, case-insensitively."""
    events = [make_event(action="BLOCK", payload_snippet=payload)]
    _, attack_types = run_rules(events)
    assert "sql_injection" in attack_types, (
        f"False negative: payload {payload!r} not classified as sql_injection."
    )


# ---------------------------------------------------------------------------
# Sibling pattern audit — word-boundary anchoring prevents over-matching
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        "UNIONSELECTFOO",               # no whitespace between keywords
        "DROPTABLEFOO",                 # concatenated, no whitespace
    ],
)
def test_concatenated_keywords_do_not_fire(payload: str) -> None:
    """Keyword patterns must use word boundaries (\\b) so that concatenated strings
    that happen to contain the keyword sequence are not matched."""
    events = [make_event(action="BLOCK", payload_snippet=payload)]
    _, attack_types = run_rules(events)
    assert "sql_injection" not in attack_types, (
        f"Over-broad match: payload {payload!r} incorrectly classified as sql_injection. "
        "Patterns must require word boundaries around SQL keywords."
    )


# ---------------------------------------------------------------------------
# Sibling audit — XSS patterns must remain sound (no regression)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload",
    [
        "<script>alert(1)</script>",
        "<SCRIPT SRC=evil.js>",
        'img onerror=alert(1)',
        "javascript:alert(1)",
    ],
)
def test_xss_patterns_still_fire(payload: str) -> None:
    """XSS detection must be unaffected by the SQLi pattern audit."""
    events = [make_event(action="BLOCK", payload_snippet=payload)]
    _, attack_types = run_rules(events)
    assert "xss" in attack_types, (
        f"XSS regression: payload {payload!r} not classified as xss after SQLi fix."
    )


def test_xss_not_triggered_by_plain_html_text() -> None:
    """A plain URI path should not fire XSS (guard against zero-width XSS regression)."""
    events = [make_event(action="BLOCK", payload_snippet="/index.html?q=hello")]
    _, attack_types = run_rules(events)
    assert "xss" not in attack_types


# ---------------------------------------------------------------------------
# Scored-once invariant must hold after fix
# ---------------------------------------------------------------------------


def test_sqli_scored_only_once_across_multiple_events() -> None:
    """Even with 5 SQLi events, sql_injection appears exactly once in attack_types."""
    events = [
        make_event(action="BLOCK", payload_snippet="' OR 1=1")
        for _ in range(5)
    ]
    _, attack_types = run_rules(events)
    assert attack_types.count("sql_injection") == 1
