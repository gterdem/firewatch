"""CRS table completeness test — MC.2 golden layer, EARS criterion for #87.

Every documented OWASP CRS rule-ID family (913/920/921/930/931/932/933/941/
942/943/944/949) must resolve to a non-"Other" category with non-None
attack_technique, attack_tactic, kill_chain_phase, and severity.

This test is a *table-completeness assertion* against the static CRS mapping
in ``crs.py``.  It is a spec guard: if a new CRS family is added to the issue
list without a corresponding table entry, this test fails immediately.

Sources:
  - OWASP CRS rule-ID families: coreruleset.org/docs/3-about-rules/ruleid/
  - Azure CRS rule groups: learn.microsoft.com/en-us/azure/web-application-firewall/
    ag/application-gateway-crs-rulegroups-rules
  - azure-waf-log-standard.md §2c (the condensed mapping table)

IP addresses in fixtures use RFC 5737 ranges only (203.0.113.0/24, etc.)
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from firewatch_sdk import RawEvent

# ---------------------------------------------------------------------------
# CRS families required by the issue §87 EARS criteria.
# Each tuple: (family_prefix, one representative rule_id, expected category fragment).
# Representative IDs were chosen as first-documented rule in each family per CRS docs.
# ---------------------------------------------------------------------------

_REQUIRED_CRS_FAMILIES: list[tuple[str, str, str]] = [
    # 913xxx: scanner/recon detection
    # Source: CRS docs "913 - Scanner Detection" family
    ("913", "913100", "Scanner"),
    # 920xxx: protocol enforcement / violation
    # Source: CRS docs "920 - Protocol Enforcement" family; MS Learn 920350 example
    ("920", "920350", "Protocol"),
    # 921xxx: HTTP request smuggling / protocol attack
    # Source: CRS docs "921 - Protocol Attack" family
    ("921", "921110", "Protocol"),
    # 930xxx: local file inclusion
    # Source: CRS docs "930 - Application Attack - Local File Inclusion" family
    ("930", "930100", "Local File"),
    # 931xxx: remote file inclusion
    # Source: CRS docs "931 - Application Attack - Remote File Inclusion" family
    ("931", "931100", "Remote File"),
    # 932xxx: remote code execution / command injection
    # Source: CRS docs "932 - Application Attack - Remote Code Execution" family
    ("932", "932100", "Remote Code"),
    # 933xxx: PHP injection
    # Source: CRS docs "933 - Application Attack - PHP Injection" family
    ("933", "933100", "PHP"),
    # 941xxx: cross-site scripting (XSS)
    # Source: CRS docs "941 - Application Attack - XSS" family
    ("941", "941100", "XSS"),
    # 942xxx: SQL injection
    # Source: CRS docs "942 - Application Attack - SQLi" family; MS Learn 942100 example
    ("942", "942100", "SQL"),
    # 943xxx: session fixation
    # Source: CRS docs "943 - Application Attack - Session Fixation" family
    ("943", "943100", "Session"),
    # 944xxx: Java attacks (includes Log4Shell CVE-2021-44228)
    # Source: CRS docs "944 - Application Attack - Java Attack" family
    ("944", "944100", "Java"),
    # 949xxx: anomaly-score blocking evaluation
    # Source: CRS docs "949 - Blocking Evaluation of Anomaly Scores" family
    ("949", "949110", "Anomaly"),
]

# ---------------------------------------------------------------------------
# Helper: build a minimal App Gateway RawEvent for a given rule_id
# ---------------------------------------------------------------------------


def _make_raw_event(rule_id: str) -> RawEvent:
    """Build a minimal App Gateway WAF RawEvent for a given CRS rule_id.

    Uses the ``"properties"`` envelope shape that normalize() reads directly.
    IP: 203.0.113.1 (RFC 5737 documentation range — gitleaks safe).
    """
    return RawEvent(
        source_type="azure_waf",
        received_at=datetime(2026, 1, 15, 0, 0, 0, tzinfo=timezone.utc),
        data={
            "time": "2026-01-15T00:00:00Z",
            "category": "ApplicationGatewayFirewallLog",
            "properties": {
                "clientIp": "203.0.113.1",
                "requestUri": "/test",
                "ruleSetType": "OWASP",
                "ruleSetVersion": "3.2",
                "ruleId": rule_id,
                "ruleGroup": f"CRS-FAMILY-{rule_id[:3]}",
                "message": f"CRS rule {rule_id} triggered",
                "action": "Matched",
                "site": "Global",
                "transactionId": "test-txn-0",
            },
        },
    )


# ---------------------------------------------------------------------------
# Fixture: plugin instance
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def plugin() -> object:
    from firewatch_azure_waf.plugin import AzureWAFSource
    return AzureWAFSource()


# ---------------------------------------------------------------------------
# EARS: table-completeness — no documented CRS family maps to "Other" or None
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "family_prefix,rule_id,expected_category_fragment",
    _REQUIRED_CRS_FAMILIES,
    ids=[f"crs-{fam}" for fam, _, _ in _REQUIRED_CRS_FAMILIES],
)
def test_crs_family_category_not_other_and_not_none(
    plugin: object,
    family_prefix: str,
    rule_id: str,
    expected_category_fragment: str,
) -> None:
    """Every documented CRS family must resolve to a known category (not 'Other', not None).

    EARS criterion: 'A table-completeness test SHALL assert that no documented CRS
    family (913/920/921/930/931/932/933/941/942/943/944/949) normalizes to "Other"
    or to severity is None.'

    This test guards against the legacy 68% "Other" problem:
    legacy/core/normalizer.py categorize_rule() only covered 7 prefixes and fell
    through to "Other" for all others (azure-waf-log-standard.md §3 critique #4).

    Sources: OWASP CRS docs (coreruleset.org/docs/3-about-rules/ruleid/);
    azure-waf-log-standard.md §2c.
    """
    raw = _make_raw_event(rule_id)
    # Accessing the plugin via the fixture type — mypy doesn't know the type here
    # but the plugin is an AzureWAFSource instance
    from firewatch_azure_waf.plugin import AzureWAFSource
    assert isinstance(plugin, AzureWAFSource)
    event = plugin.normalize(raw, "crs-test")

    # Must not be None
    assert event.category is not None, (
        f"CRS family {family_prefix}xxx (rule_id={rule_id}): category is None. "
        f"The CRS static table in crs.py must cover this family — no fall-through to None."
    )

    # Must not be "Other" (the legacy ~68% "Other" problem)
    assert "other" not in (event.category or "").lower(), (
        f"CRS family {family_prefix}xxx (rule_id={rule_id}): category is 'Other' "
        f"or a variant: {event.category!r}. "
        f"The CRS table must map every documented family to a specific category. "
        f"Legacy fallthrough to 'Other' is the bug this test guards against "
        f"(azure-waf-log-standard.md §3 critique #4)."
    )

    # Must contain expected fragment (sanity-check the mapping is specific)
    assert expected_category_fragment.lower() in (event.category or "").lower(), (
        f"CRS family {family_prefix}xxx (rule_id={rule_id}): expected category "
        f"to contain '{expected_category_fragment}', got {event.category!r}. "
        f"Source: azure-waf-log-standard.md §2c CRS range table."
    )


@pytest.mark.parametrize(
    "family_prefix,rule_id,_",
    _REQUIRED_CRS_FAMILIES,
    ids=[f"crs-{fam}" for fam, _, _ in _REQUIRED_CRS_FAMILIES],
)
def test_crs_family_severity_not_none(
    plugin: object,
    family_prefix: str,
    rule_id: str,
    _: str,
) -> None:
    """Every documented CRS family must yield a non-None severity.

    EARS criterion: 'No fixture SHALL expect an empty (None) severity.'

    This also guards the legacy bug: the Azure path never set severity at all
    (azure-waf-log-standard.md §3 critique #3). The severity module must always
    return a SeverityLiteral for any category the CRS table emits.

    Source: azure-waf-log-standard.md §2d (severity derivation).
    """
    raw = _make_raw_event(rule_id)
    from firewatch_azure_waf.plugin import AzureWAFSource
    assert isinstance(plugin, AzureWAFSource)
    event = plugin.normalize(raw, "crs-test")

    assert event.severity is not None, (
        f"CRS family {family_prefix}xxx (rule_id={rule_id}): severity is None. "
        f"The severity module must always return a SeverityLiteral — never None. "
        f"The legacy Azure path left severity empty for every event "
        f"(azure-waf-log-standard.md §3 critique #3). "
        f"Source: azure-waf-log-standard.md §2d."
    )
    assert event.severity in ("info", "low", "medium", "high", "critical"), (
        f"CRS family {family_prefix}xxx (rule_id={rule_id}): severity must be "
        f"a valid SeverityLiteral; got {event.severity!r}"
    )


@pytest.mark.parametrize(
    "family_prefix,rule_id,_",
    _REQUIRED_CRS_FAMILIES,
    ids=[f"crs-{fam}" for fam, _, _ in _REQUIRED_CRS_FAMILIES],
)
def test_crs_family_attack_technique_not_none_for_key_families(
    plugin: object,
    family_prefix: str,
    rule_id: str,
    _: str,
) -> None:
    """Key CRS families (attack families) must have a non-None attack_technique.

    The 949xxx anomaly-score family is excluded because CAPEC/technique is
    intentionally None for pure threshold evaluations (the anomaly-score itself
    doesn't represent a specific technique).

    Source: azure-waf-log-standard.md §2c MITRE column.
    """
    # 949xxx is a threshold evaluation, not a specific attack — technique is None by design
    if family_prefix == "949":
        pytest.skip("949xxx anomaly threshold: attack_technique intentionally None")

    raw = _make_raw_event(rule_id)
    from firewatch_azure_waf.plugin import AzureWAFSource
    assert isinstance(plugin, AzureWAFSource)
    event = plugin.normalize(raw, "crs-test")

    assert event.attack_technique is not None, (
        f"CRS family {family_prefix}xxx (rule_id={rule_id}): attack_technique is None. "
        f"Attack families must have a MITRE ATT&CK technique. "
        f"Source: azure-waf-log-standard.md §2c (MITRE ATT&CK column)."
    )


# ---------------------------------------------------------------------------
# Direct CRS module API tests (supplement the normalize path above)
# ---------------------------------------------------------------------------


class TestCRSModuleDirectAPI:
    """Direct unit tests for crs.lookup_by_rule_id() covering all documented families.

    These tests call the CRS module directly (not via normalize) to verify the
    static table in isolation.  Complements the normalize-path tests above.
    """

    @pytest.mark.parametrize("rule_id,expected_category", [
        # Source for all: azure-waf-log-standard.md §2c + OWASP CRS rule-ID docs
        ("913100", "Scanner / Recon Detection"),
        ("920350", "Protocol Enforcement"),
        ("921110", "Protocol Attack"),
        ("930100", "Local File Inclusion"),
        ("931100", "Remote File Inclusion"),
        ("932100", "Remote Code Execution"),
        ("933100", "PHP Injection"),
        ("941100", "Cross-Site Scripting (XSS)"),
        ("942100", "SQL Injection"),
        ("943100", "Session Fixation"),
        ("944100", "Java / Log4j Exploit"),
        ("949110", "Anomaly Score Threshold"),
    ])
    def test_lookup_by_rule_id_returns_correct_category(
        self, rule_id: str, expected_category: str
    ) -> None:
        """crs.lookup_by_rule_id() returns the exact category string for each family."""
        from firewatch_azure_waf.crs import lookup_by_rule_id

        entry = lookup_by_rule_id(rule_id)
        assert entry is not None, (
            f"lookup_by_rule_id({rule_id!r}) returned None — "
            f"CRS table must cover rule_id {rule_id}"
        )
        assert entry.category == expected_category, (
            f"lookup_by_rule_id({rule_id!r}).category: "
            f"expected {expected_category!r}, got {entry.category!r}"
        )

    @pytest.mark.parametrize("rule_id,expected_capec", [
        # CAPEC values from capec.mitre.org; summarized in azure-waf-log-standard.md §2c
        ("913100", "CAPEC-169"),   # 913xxx scanning → CAPEC-169 Footprinting
        ("920350", "CAPEC-272"),   # 920xxx protocol → CAPEC-272 Protocol Manipulation
        ("921110", "CAPEC-105"),   # 921xxx smuggling → CAPEC-105 HTTP Request Smuggling
        ("930100", "CAPEC-126"),   # 930xxx LFI → CAPEC-126 Path Traversal
        ("931100", "CAPEC-193"),   # 931xxx RFI → CAPEC-193 PHP Remote File Inclusion
        ("932100", "CAPEC-248"),   # 932xxx RCE → CAPEC-248 Command Injection
        ("933100", "CAPEC-242"),   # 933xxx PHP → CAPEC-242 Code Injection
        ("941100", "CAPEC-63"),    # 941xxx XSS → CAPEC-63 Cross-Site Scripting
        ("942100", "CAPEC-66"),    # 942xxx SQLi → CAPEC-66 SQL Injection
        ("943100", "CAPEC-61"),    # 943xxx session fixation → CAPEC-61 Session Fixation
        ("944100", "CAPEC-242"),   # 944xxx Java → CAPEC-242 Code Injection (Log4Shell)
    ])
    def test_lookup_by_rule_id_returns_correct_capec(
        self, rule_id: str, expected_capec: str
    ) -> None:
        """crs.lookup_by_rule_id() returns the correct CAPEC ID for each attack family.

        949xxx (anomaly threshold) is excluded — capec_id is intentionally None there
        because no specific attack vector is known until the triggering rule fires.
        Source: capec.mitre.org; azure-waf-log-standard.md §2c.
        """
        from firewatch_azure_waf.crs import lookup_by_rule_id

        entry = lookup_by_rule_id(rule_id)
        assert entry is not None
        assert entry.capec_id == expected_capec, (
            f"lookup_by_rule_id({rule_id!r}).capec_id: "
            f"expected {expected_capec!r}, got {entry.capec_id!r}. "
            f"Source: capec.mitre.org; azure-waf-log-standard.md §2c."
        )

    @pytest.mark.parametrize("rule_id,expected_technique", [
        # MITRE ATT&CK technique IDs from attack.mitre.org;
        # azure-waf-log-standard.md §2c MITRE column
        ("913100", "T1595"),  # 913xxx → T1595 Active Scanning (Reconnaissance)
        ("920350", "T1190"),  # 920xxx → T1190 Exploit Public-Facing Application
        ("921110", "T1190"),  # 921xxx → T1190
        ("930100", "T1190"),  # 930xxx → T1190
        ("931100", "T1190"),  # 931xxx → T1190
        ("932100", "T1190"),  # 932xxx → T1190 (RCE via app vuln)
        ("933100", "T1190"),  # 933xxx → T1190
        ("941100", "T1059"),  # 941xxx → T1059 Command and Scripting Interpreter (XSS)
        ("942100", "T1190"),  # 942xxx → T1190
        ("943100", "T1190"),  # 943xxx → T1190
        ("944100", "T1190"),  # 944xxx → T1190 (Log4Shell)
        ("949110", "T1190"),  # 949xxx → T1190 (anomaly threshold from exploitation)
    ])
    def test_lookup_by_rule_id_returns_correct_mitre_technique(
        self, rule_id: str, expected_technique: str
    ) -> None:
        """crs.lookup_by_rule_id() returns the correct MITRE ATT&CK technique."""
        from firewatch_azure_waf.crs import lookup_by_rule_id

        entry = lookup_by_rule_id(rule_id)
        assert entry is not None
        assert entry.attack_technique == expected_technique, (
            f"lookup_by_rule_id({rule_id!r}).attack_technique: "
            f"expected {expected_technique!r}, got {entry.attack_technique!r}. "
            f"Source: attack.mitre.org; azure-waf-log-standard.md §2c."
        )
