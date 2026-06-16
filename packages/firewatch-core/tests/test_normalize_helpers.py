"""Shared normalize-helper tests (EARS-3 — helpers ported verbatim)."""
import pytest

from firewatch_core.normalize_helpers import categorize_rule, ocsf_for_category


@pytest.mark.parametrize(
    "rule_id, expected",
    [
        ("942100", "SQL Injection"),
        ("941110", "XSS"),
        ("930120", "Local File Inclusion"),
        ("932150", "Command Injection"),
        ("920270", "Protocol Violation"),
        ("949110", "Anomaly Score Exceeded"),
        ("300013", "Bot Activity"),
        ("RateLimitRule", "Rate Limited"),
        ("GeoBlockUS", "Geo-Blocked"),
        ("IPReputationDeny", "IP Reputation"),
        ("999999", "Other"),
        (None, "Other"),
        ("", "Other"),
    ],
)
def test_categorize_rule(rule_id, expected):
    assert categorize_rule(rule_id) == expected


@pytest.mark.parametrize(
    "category, expected",
    [
        ("SQL Injection", (6004, 6)),
        ("XSS", (6004, 6)),
        ("Bot Activity", (4001, 4)),
        ("IP Reputation", (4001, 4)),
        ("Other", (6004, 6)),
        ("not-a-category", (None, None)),
    ],
)
def test_ocsf_for_category(category, expected):
    assert ocsf_for_category(category) == expected
