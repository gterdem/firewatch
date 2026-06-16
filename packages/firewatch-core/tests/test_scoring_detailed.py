"""Tests for scoring.build_detailed_samples — issue #19 (M2.4).

Each test maps 1:1 to an EARS acceptance criterion.

EARS-1 (Event-driven): build_detailed_samples includes ALL triggered rules (no 15-cap).
EARS-2 (Event-driven): 300-char payload truncation.
EARS-3 (Event-driven): per-rule first/last timestamps in each sample.
EARS-4 (Event-driven): rule description from rule_descs dict; blank string if absent.
EARS-5 (Ubiquitous): BLOCK/DROP events only; ALLOW/ALERT events excluded from samples.
EARS-6 (Ubiquitous): samples sorted by count descending (parity with build_samples).
"""
from __future__ import annotations

from datetime import datetime, timezone

from firewatch_core.scoring import build_detailed_samples
from _fakes import make_event

_T0 = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
_T1 = datetime(2026, 1, 15, 11, 0, 0, tzinfo=timezone.utc)
_T2 = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# EARS-1: all rules, no cap
# ---------------------------------------------------------------------------


def test_build_detailed_samples_no_cap() -> None:
    """EARS-1: all triggered rules included — no 15-rule cap."""
    events = [
        make_event(action="BLOCK", rule_id=f"9{i:05d}", payload_snippet="x")
        for i in range(20)
    ]
    samples = build_detailed_samples(events, {})
    assert len(samples) == 20, (
        f"Expected 20 rules (no cap), got {len(samples)}. "
        "build_detailed_samples must NOT cap at MAX_SAMPLES."
    )


def test_build_detailed_samples_more_than_15_rules() -> None:
    """EARS-1: 16 rules all appear (verifies no off-by-one at the cap boundary)."""
    events = [
        make_event(action="BLOCK", rule_id=f"94{i:04d}", payload_snippet="payload")
        for i in range(16)
    ]
    samples = build_detailed_samples(events, {})
    assert len(samples) == 16


# ---------------------------------------------------------------------------
# EARS-2: 300-char payload truncation
# ---------------------------------------------------------------------------


def test_build_detailed_samples_truncates_at_300() -> None:
    """EARS-2: payloads longer than 300 chars are truncated to exactly 300."""
    long_payload = "A" * 600
    events = [make_event(action="BLOCK", rule_id="942100", payload_snippet=long_payload)]
    samples = build_detailed_samples(events, {})
    assert len(samples) == 1
    assert len(samples[0]["payload"]) == 300


def test_build_detailed_samples_short_payload_unchanged() -> None:
    """EARS-2: payloads <= 300 chars are not padded or truncated."""
    short_payload = "SELECT * FROM users"
    events = [make_event(action="BLOCK", rule_id="942100", payload_snippet=short_payload)]
    samples = build_detailed_samples(events, {})
    assert samples[0]["payload"] == short_payload


def test_build_detailed_samples_exactly_300_unchanged() -> None:
    """EARS-2: payload of exactly 300 chars passes through unchanged."""
    exact_payload = "B" * 300
    events = [make_event(action="BLOCK", rule_id="942100", payload_snippet=exact_payload)]
    samples = build_detailed_samples(events, {})
    assert samples[0]["payload"] == exact_payload


# ---------------------------------------------------------------------------
# EARS-3: per-rule first/last timestamps
# ---------------------------------------------------------------------------


def test_build_detailed_samples_per_rule_timestamps() -> None:
    """EARS-3: each sample carries first_triggered and last_triggered."""
    events = [
        make_event(action="BLOCK", rule_id="942100", timestamp=_T0),
        make_event(action="BLOCK", rule_id="942100", timestamp=_T2),
        make_event(action="BLOCK", rule_id="942100", timestamp=_T1),
    ]
    samples = build_detailed_samples(events, {})
    assert len(samples) == 1
    s = samples[0]
    assert "first_triggered" in s
    assert "last_triggered" in s
    assert s["first_triggered"] == str(_T0)
    assert s["last_triggered"] == str(_T2)


def test_build_detailed_samples_timestamps_per_rule_independent() -> None:
    """EARS-3: each rule's timestamps are independent — not across all events."""
    events = [
        make_event(action="BLOCK", rule_id="942100", timestamp=_T0),
        make_event(action="BLOCK", rule_id="941100", timestamp=_T2),
    ]
    samples = build_detailed_samples(events, {})
    by_rule = {s["rule_id"]: s for s in samples}

    assert by_rule["942100"]["first_triggered"] == str(_T0)
    assert by_rule["942100"]["last_triggered"] == str(_T0)
    assert by_rule["941100"]["first_triggered"] == str(_T2)
    assert by_rule["941100"]["last_triggered"] == str(_T2)


# ---------------------------------------------------------------------------
# EARS-4: rule description from rule_descs
# ---------------------------------------------------------------------------


def test_build_detailed_samples_description_from_rule_descs() -> None:
    """EARS-4: rule description comes from the rule_descs mapping."""
    rule_descs = {"942100": "SQL injection via numeric parameter"}
    events = [make_event(action="BLOCK", rule_id="942100")]
    samples = build_detailed_samples(events, rule_descs)
    assert samples[0]["description"] == "SQL injection via numeric parameter"


def test_build_detailed_samples_missing_description_is_blank() -> None:
    """EARS-4: missing rule description becomes an empty string (graceful)."""
    events = [make_event(action="BLOCK", rule_id="942100")]
    samples = build_detailed_samples(events, {})
    assert samples[0]["description"] == ""


def test_build_detailed_samples_partial_rule_descs() -> None:
    """EARS-4: partial rule_descs — some have descriptions, some blank."""
    rule_descs = {"942100": "SQLi rule"}
    events = [
        make_event(action="BLOCK", rule_id="942100"),
        make_event(action="BLOCK", rule_id="941100"),
    ]
    samples = build_detailed_samples(events, rule_descs)
    by_rule = {s["rule_id"]: s for s in samples}
    assert by_rule["942100"]["description"] == "SQLi rule"
    assert by_rule["941100"]["description"] == ""


# ---------------------------------------------------------------------------
# EARS-5: BLOCK/DROP only; ALLOW/ALERT excluded
# ---------------------------------------------------------------------------


def test_build_detailed_samples_excludes_allow_and_alert() -> None:
    """EARS-5: ALLOW and ALERT events do not appear in detailed samples."""
    events = [
        make_event(action="ALLOW", rule_id="942100"),
        make_event(action="ALERT", rule_id="941100"),
        make_event(action="BLOCK", rule_id="930100"),
    ]
    samples = build_detailed_samples(events, {})
    rule_ids = [s["rule_id"] for s in samples]
    assert "942100" not in rule_ids
    assert "941100" not in rule_ids
    assert "930100" in rule_ids


def test_build_detailed_samples_includes_drop() -> None:
    """EARS-5: DROP events are included (same as build_samples behavior)."""
    events = [make_event(action="DROP", rule_id="942100")]
    samples = build_detailed_samples(events, {})
    assert len(samples) == 1
    assert samples[0]["rule_id"] == "942100"


def test_build_detailed_samples_empty_if_no_blocked() -> None:
    """EARS-5: returns empty list when no BLOCK/DROP events."""
    events = [make_event(action="ALERT"), make_event(action="ALLOW")]
    samples = build_detailed_samples(events, {})
    assert samples == []


# ---------------------------------------------------------------------------
# EARS-6: sorted by count descending
# ---------------------------------------------------------------------------


def test_build_detailed_samples_sorted_by_count_desc() -> None:
    """EARS-6: samples sorted by frequency descending."""
    events = (
        [make_event(action="BLOCK", rule_id="942100")] * 3
        + [make_event(action="BLOCK", rule_id="941100")] * 7
        + [make_event(action="BLOCK", rule_id="930100")] * 1
    )
    samples = build_detailed_samples(events, {})
    counts = [s["count"] for s in samples]
    assert counts == sorted(counts, reverse=True)
    assert samples[0]["rule_id"] == "941100"  # highest count first


# ---------------------------------------------------------------------------
# EARS-7 (Ubiquitous): output dict contains required keys
# ---------------------------------------------------------------------------


def test_build_detailed_samples_required_keys() -> None:
    """EARS-7: each sample dict contains all required keys."""
    required = {"rule_id", "category", "description", "payload", "count",
                "first_triggered", "last_triggered"}
    events = [make_event(action="BLOCK", rule_id="942100", payload_snippet="test")]
    samples = build_detailed_samples(events, {"942100": "desc"})
    assert len(samples) == 1
    missing = required - set(samples[0].keys())
    assert not missing, f"Sample missing keys: {missing}"


# ---------------------------------------------------------------------------
# EARS-8: no payload event → uses "(no payload)" sentinel
# ---------------------------------------------------------------------------


def test_build_detailed_samples_no_payload_sentinel() -> None:
    """EARS-8: events with no payload_snippet use the '(no payload)' sentinel."""
    events = [make_event(action="BLOCK", rule_id="942100", payload_snippet=None)]
    samples = build_detailed_samples(events, {})
    assert samples[0]["payload"] == "(no payload)"
