"""Golden normalize() tests — standards-pinned, built from MS Learn log shapes.

Each fixture is the RAW MS-Learn-shaped JSON (with ``"properties"`` envelope) as
documented in azure-waf-log-standard.md §4 and §1a/§1b.  Fixtures are fed directly
to ``normalize()`` without any canonicalization step, which is correct: the
``"properties"`` key is already present in the MS Learn envelope shape, so
``normalize()``'s first line (``props = d.get("properties") or d``) resolves it
immediately.  This matches the production path for JSON-blob (Storage Account)
and direct Event Hub payloads; for Log Analytics KQL results the canonicalize step
(``_columns.canonicalize_row()``) runs first and produces the same shape.

EARS criteria covered (mapped 1:1 to the issue §87 acceptance criteria):
  EARS-A1  source_type="azure_waf" on every fixture.
  EARS-A2  action dispositions: Block→BLOCK, Detected→ALERT, Matched→ALERT,
           AnomalyScoring→ALERT, Allowed→ALLOW, Log→LOG.
           Explicitly asserts Detected/Matched/AnomalyScoring ≠ BLOCK (the legacy bug).
  EARS-A3  App Gateway fixture: category/MITRE/CAPEC from discrete ruleId.
  EARS-A4  Front Door fixture: ruleName parsed → SAME (category, technique, capec)
           tuple as equivalent App Gateway ruleId (cross-shape consistency).
  EARS-A5  severity is non-None for every fixture.
  EARS-A6  ocsf_class==4002, ocsf_category==4 on every fixture.
  EARS-A7  No fabricated transport fields (destination_port, protocol are None).
  EARS-A8  Unmapped fields land in raw_log (not invented in the SecurityEvent).
  EARS-A9  Full (category, severity, attack_technique, capec_id) tuple asserted for
           SQLi 942, XSS 941, and Scanner 913 families.

IP addresses in fixtures are RFC 5737 documentation ranges only:
  192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
(gitleaks public-ipv4 rule enforced by CI; real/routable IPs are forbidden.)

GUIDs in fixtures use the allowlisted placeholder set from docs/lessons.md /
.gitleaks.toml: 00000000-0000-0000-0000-000000000000.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from firewatch_sdk import RawEvent

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _load_fixture(filename: str) -> dict[str, Any]:
    """Load a fixture JSON file from tests/fixtures/ as a dict."""
    path = _FIXTURES_DIR / filename
    return json.loads(path.read_text())


def _raw_event_from_fixture(filename: str) -> RawEvent:
    """Build a RawEvent directly from a fixture JSON file.

    The fixture is the raw MS-Learn-shaped JSON (with ``"properties"`` envelope).
    This is the shape that ``normalize()`` consumes in production: the
    ``"properties"`` key is present, so ``normalize()``'s
    ``props = d.get("properties") or d`` resolves to the inner dict directly.

    For Log Analytics KQL results the canonicalize step
    (``_columns.canonicalize_row()``) runs first and produces the same shape —
    the ``"properties"`` envelope is always present by the time ``normalize()``
    is called.
    """
    data = _load_fixture(filename)
    return RawEvent(
        source_type="azure_waf",
        received_at=datetime(2026, 1, 15, 0, 0, 0, tzinfo=timezone.utc),
        data=data,
    )


# ---------------------------------------------------------------------------
# Module-level: load the plugin once for all tests
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def plugin() -> Any:
    """AzureWAFSource plugin instance (module-scoped for performance)."""
    from firewatch_azure_waf.plugin import AzureWAFSource
    return AzureWAFSource()


# ---------------------------------------------------------------------------
# EARS-A1 / EARS-A6: source_type and OCSF constants hold on every fixture
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fixture_file", [
    "app_gateway_920350_matched.json",
    "app_gateway_941100_xss_detected.json",
    "app_gateway_932100_rce_block.json",
    "app_gateway_913100_scanner_allowed.json",
    "app_gateway_942100_sqli_log.json",
    "front_door_942100_sqli_block.json",
    "front_door_941100_xss_anomalyscoring.json",
    "front_door_913110_scanner_log.json",
])
def test_source_type_and_ocsf_constants(plugin: Any, fixture_file: str) -> None:
    """Every fixture yields source_type='azure_waf', ocsf_class=4002, ocsf_category=4.

    EARS-A1: source_type constant.
    EARS-A6: OCSF HTTP Activity (4002) / Network Activity category (4) —
             azure-waf-log-standard.md §2a; schema.ocsf.io/classes/http_activity.
    """
    raw = _raw_event_from_fixture(fixture_file)
    event = plugin.normalize(raw, "test-instance")

    # EARS-A1
    assert event.source_type == "azure_waf", (
        f"{fixture_file}: source_type must be 'azure_waf' (Flag B — constant, never "
        f"branches on source_id); got {event.source_type!r}"
    )
    # EARS-A6: OCSF HTTP Activity (4002) — azure-waf-log-standard.md §2a
    assert event.ocsf_class == 4002, (
        f"{fixture_file}: ocsf_class must be 4002 (OCSF HTTP Activity, "
        "schema.ocsf.io/classes/http_activity — corrects stale legacy 6004); "
        f"got {event.ocsf_class!r}"
    )
    # EARS-A6: OCSF Network Activity category (4) — schema.ocsf.io
    assert event.ocsf_category == 4, (
        f"{fixture_file}: ocsf_category must be 4 (OCSF Network Activity); "
        f"got {event.ocsf_category!r}"
    )


# ---------------------------------------------------------------------------
# EARS-A5: severity is non-None for every fixture
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fixture_file", [
    "app_gateway_920350_matched.json",
    "app_gateway_941100_xss_detected.json",
    "app_gateway_932100_rce_block.json",
    "app_gateway_913100_scanner_allowed.json",
    "app_gateway_942100_sqli_log.json",
    "front_door_942100_sqli_block.json",
    "front_door_941100_xss_anomalyscoring.json",
    "front_door_913110_scanner_log.json",
])
def test_severity_never_none(plugin: Any, fixture_file: str) -> None:
    """severity is always a SeverityLiteral — never None.

    EARS-A5: azure-waf-log-standard.md §2d — severity always derivable from
    CRS category; the legacy Azure path left severity=None (§3 critique #3).
    """
    raw = _raw_event_from_fixture(fixture_file)
    event = plugin.normalize(raw, "test-instance")

    assert event.severity is not None, (
        f"{fixture_file}: severity must never be None — the legacy Azure path left "
        "severity empty for every event (§3 critique #3). CRS category provides the "
        "primary signal; azure-waf-log-standard.md §2d."
    )
    assert event.severity in ("info", "low", "medium", "high", "critical"), (
        f"{fixture_file}: severity must be a valid SeverityLiteral; "
        f"got {event.severity!r}"
    )


# ---------------------------------------------------------------------------
# EARS-A7: no fabricated transport fields
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fixture_file", [
    "app_gateway_920350_matched.json",
    "app_gateway_941100_xss_detected.json",
    "app_gateway_932100_rce_block.json",
    "app_gateway_913100_scanner_allowed.json",
    "app_gateway_942100_sqli_log.json",
    "front_door_942100_sqli_block.json",
    "front_door_941100_xss_anomalyscoring.json",
    "front_door_913110_scanner_log.json",
])
def test_no_fabricated_transport_fields(plugin: Any, fixture_file: str) -> None:
    """destination_port and protocol are NOT fabricated.

    EARS-A7: azure-waf-log-standard.md §3 critique #5 — Azure WAF logs do not
    carry destination_port or protocol; fabricating them (e.g. port=80, 'TCP')
    is the explicit legacy anti-pattern this milestone corrects.
    """
    raw = _raw_event_from_fixture(fixture_file)
    event = plugin.normalize(raw, "test-instance")

    assert event.destination_port is None, (
        f"{fixture_file}: destination_port must be None — Azure WAF logs do not "
        "carry it. Fabricating '80' is the legacy anti-pattern (§3 critique #5)."
    )
    assert event.protocol is None, (
        f"{fixture_file}: protocol must be None — Azure WAF logs do not carry it. "
        "Fabricating 'TCP' is the legacy anti-pattern (§3 critique #5)."
    )


# ---------------------------------------------------------------------------
# EARS-A8: raw_log preserved (unmapped fields land in raw_log, not invented)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fixture_file", [
    "app_gateway_920350_matched.json",
    "app_gateway_941100_xss_detected.json",
    "front_door_942100_sqli_block.json",
    "front_door_941100_xss_anomalyscoring.json",
])
def test_raw_log_preserves_original_data(plugin: Any, fixture_file: str) -> None:
    """raw_log holds the full original event data (no forensic data dropped).

    EARS-A8: PLUGIN_CONTRACT.md requires unmapped fields in raw_log;
    azure-waf-log-standard.md §3 critique #7 (geo-lookup baked into sync) is
    the legacy anti-pattern — here we verify unmapped Azure fields survive.
    """
    data = _load_fixture(fixture_file)
    raw = RawEvent(
        source_type="azure_waf",
        received_at=datetime(2026, 1, 15, 0, 0, 0, tzinfo=timezone.utc),
        data=data,
    )
    event = plugin.normalize(raw, "test-instance")

    assert event.raw_log is not None, (
        f"{fixture_file}: raw_log must not be None — all original event data "
        "must be preserved for forensic drill-down (PLUGIN_CONTRACT.md)."
    )
    # The full original dict should survive in raw_log
    assert event.raw_log == data, (
        f"{fixture_file}: raw_log must equal the original RawEvent.data dict "
        "(full forensic preservation)."
    )


# ---------------------------------------------------------------------------
# EARS-A2 + EARS-A3: Action dispositions — App Gateway fixtures
# ---------------------------------------------------------------------------


class TestAppGatewayActionDispositions:
    """EARS-A2 + EARS-A3: action disposition correctness on App Gateway fixtures.

    Covers every documented disposition category:
      Block→BLOCK, Detected→ALERT, Matched→ALERT, Allowed→ALLOW, Log→LOG.
    Explicitly asserts Detected/Matched ≠ BLOCK (the legacy bug, §3 critique #2).
    Source: azure-waf-log-standard.md §1c / §2b; MS Learn App Gateway WAF docs.
    """

    def test_matched_maps_to_alert_not_block(self, plugin: Any) -> None:
        """920350 with action=Matched → ALERT (non-terminating CRS contribution).

        The MS Learn example (azure-waf-log-standard.md §4) uses action=Matched.
        Legacy bug (sync.py:90): Matched was mapped to BLOCK — this asserts the
        correct ALERT mapping. azure-waf-log-standard.md §2b / §3 critique #2.
        """
        raw = _raw_event_from_fixture("app_gateway_920350_matched.json")
        event = plugin.normalize(raw, "test-instance")

        assert event.action == "ALERT", (
            "action=Matched must map to ALERT (non-terminating CRS anomaly-score "
            "contribution — NOT a block). Legacy bug: sync.py:90 mapped this to BLOCK. "
            "Source: azure-waf-log-standard.md §2b / MS Learn App Gateway WAF docs."
        )
        assert event.action != "BLOCK", (
            "action=Matched must NOT map to BLOCK — this is the explicit legacy bug "
            "(azure-waf-log-standard.md §3 critique #2) that MC milestone corrects."
        )

    def test_detected_maps_to_alert_not_block(self, plugin: Any) -> None:
        """941100 with action=Detected → ALERT (detection-mode, request passed).

        Detected = detection-mode match; the request is logged and passed to backend,
        NOT blocked. Legacy bug: sync.py:90 collapsed Detected into BLOCK.
        Source: azure-waf-log-standard.md §1c / §2b.
        """
        raw = _raw_event_from_fixture("app_gateway_941100_xss_detected.json")
        event = plugin.normalize(raw, "test-instance")

        assert event.action == "ALERT", (
            "action=Detected must map to ALERT — detection-mode match; logged and "
            "passed (NOT blocked). azure-waf-log-standard.md §1c / §2b."
        )
        assert event.action != "BLOCK", (
            "action=Detected must NOT map to BLOCK — this is the explicit legacy bug "
            "this milestone corrects (azure-waf-log-standard.md §3 critique #2)."
        )

    def test_block_maps_to_block(self, plugin: Any) -> None:
        """932100 with action=Block → BLOCK (terminating block).

        Source: azure-waf-log-standard.md §2b — Block/Blocked = terminating,
        OCSF disposition_id=2 Blocked.
        """
        raw = _raw_event_from_fixture("app_gateway_932100_rce_block.json")
        event = plugin.normalize(raw, "test-instance")

        assert event.action == "BLOCK", (
            "action=Block must map to BLOCK (terminating block, OCSF disposition_id=2). "
            "Source: azure-waf-log-standard.md §2b."
        )

    def test_allowed_maps_to_allow(self, plugin: Any) -> None:
        """913100 with action=Allowed → ALLOW (rule matched, request passed).

        Source: azure-waf-log-standard.md §2b — Allowed/Allow = OCSF disposition_id=1.
        """
        raw = _raw_event_from_fixture("app_gateway_913100_scanner_allowed.json")
        event = plugin.normalize(raw, "test-instance")

        assert event.action == "ALLOW", (
            "action=Allowed must map to ALLOW (rule matched, request passed through). "
            "Source: azure-waf-log-standard.md §2b, OCSF disposition_id=1."
        )

    def test_log_maps_to_log(self, plugin: Any) -> None:
        """942100 with action=Log → LOG (informational, non-terminating).

        Source: azure-waf-log-standard.md §2b — Log = OCSF disposition_id=17 Logged.
        """
        raw = _raw_event_from_fixture("app_gateway_942100_sqli_log.json")
        event = plugin.normalize(raw, "test-instance")

        assert event.action == "LOG", (
            "action=Log must map to LOG (informational). "
            "Source: azure-waf-log-standard.md §2b, OCSF disposition_id=17."
        )


# ---------------------------------------------------------------------------
# EARS-A3: Full (category, severity, attack_technique, capec_id) tuples
#          for App Gateway discrete ruleId
# ---------------------------------------------------------------------------


class TestAppGatewayFullTuples:
    """EARS-A3 + EARS-A9: full OCSF/MITRE/CAPEC tuples for App Gateway fixtures.

    Verifies that the static CRS range table (crs.py) maps ruleId correctly
    to the full (category, severity, attack_technique, attack_tactic, capec_id)
    tuple for 3 required CRS families: SQLi 942, XSS 941, Scanner 913.

    All expected values are derived from the published standard:
      - CRS rule-ID ranges: coreruleset.org/docs/3-about-rules/ruleid/
      - MITRE ATT&CK: attack.mitre.org (T1595, T1059, T1190)
      - CAPEC: capec.mitre.org (CAPEC-66 SQLi, CAPEC-63 XSS, CAPEC-169 scanning)
      - azure-waf-log-standard.md §2c (the condensed mapping table)
    """

    def test_app_gateway_920350_protocol_enforcement_tuple(self, plugin: Any) -> None:
        """920350 (Protocol Enforcement) → full tuple per CRS §2c.

        Rule 920350: Host header is a numeric IP — falls in 920xxx Protocol Enforcement.
        Source: MS Learn App Gateway WAF log example (azure-waf-log-standard.md §4).
        MITRE T1190 Exploit Public-Facing Application (TA0001 Initial Access).
        CAPEC-272 Protocol Manipulation — azure-waf-log-standard.md §2c.
        """
        raw = _raw_event_from_fixture("app_gateway_920350_matched.json")
        event = plugin.normalize(raw, "test-instance")

        # Category: 920xxx → Protocol Enforcement (CRS rule-ID range table, §2c)
        assert event.category == "Protocol Enforcement", (
            f"920350 must map to 'Protocol Enforcement' (920xxx range per CRS docs); "
            f"got {event.category!r}"
        )
        # MITRE ATT&CK T1190 Exploit Public-Facing Application (attack.mitre.org)
        assert event.attack_technique == "T1190", (
            f"920xxx → T1190 Exploit Public-Facing Application (MITRE ATT&CK, "
            f"attack.mitre.org); got {event.attack_technique!r}"
        )
        # MITRE tactic TA0001 Initial Access
        assert event.attack_tactic == "TA0001", (
            f"920xxx → TA0001 Initial Access (MITRE ATT&CK); got {event.attack_tactic!r}"
        )
        # CAPEC-272 Protocol Manipulation (capec.mitre.org)
        assert event.capec_id == "CAPEC-272", (
            f"920xxx → CAPEC-272 Protocol Manipulation; got {event.capec_id!r}"
        )
        # Severity: low (Protocol Enforcement — azure-waf-log-standard.md §2c)
        assert event.severity == "low", (
            f"Protocol Enforcement → severity 'low' (azure-waf-log-standard.md §2c); "
            f"got {event.severity!r}"
        )
        # ocsf_class=4002 (OCSF HTTP Activity, §2a)
        assert event.ocsf_class == 4002
        assert event.ocsf_category == 4

    def test_app_gateway_941100_xss_tuple(self, plugin: Any) -> None:
        """941100 (XSS) → full tuple per CRS §2c.

        Rule 941100: XSS Attack Detected via libinjection — 941xxx XSS family.
        Source: OWASP CRS docs (coreruleset.org/docs/3-about-rules/ruleid/).
        MITRE T1059 Command and Scripting Interpreter (execution, XSS delivers scripts).
        CAPEC-63 Cross-Site Scripting (capec.mitre.org).
        Severity: high (azure-waf-log-standard.md §2c).
        """
        raw = _raw_event_from_fixture("app_gateway_941100_xss_detected.json")
        event = plugin.normalize(raw, "test-instance")

        # Category: 941xxx → Cross-Site Scripting (XSS) (CRS range table, §2c)
        assert event.category == "Cross-Site Scripting (XSS)", (
            f"941100 must map to 'Cross-Site Scripting (XSS)' (941xxx range); "
            f"got {event.category!r}"
        )
        # MITRE T1059 (XSS delivers a script — T1059 Command and Scripting Interpreter,
        # attack.mitre.org)
        assert event.attack_technique == "T1059", (
            f"941xxx → T1059 Command and Scripting Interpreter (MITRE ATT&CK, "
            f"attack.mitre.org); got {event.attack_technique!r}"
        )
        # CAPEC-63 Cross-Site Scripting (capec.mitre.org)
        assert event.capec_id == "CAPEC-63", (
            f"941xxx → CAPEC-63 Cross-Site Scripting (capec.mitre.org); "
            f"got {event.capec_id!r}"
        )
        # Severity: high (azure-waf-log-standard.md §2c XSS)
        assert event.severity == "high", (
            f"XSS → severity 'high' (azure-waf-log-standard.md §2c); "
            f"got {event.severity!r}"
        )
        assert event.ocsf_class == 4002
        assert event.ocsf_category == 4

    def test_app_gateway_932100_rce_tuple(self, plugin: Any) -> None:
        """932100 (RCE) → full tuple per CRS §2c.

        Rule 932100: Remote Command Execution — 932xxx RCE family.
        Source: OWASP CRS docs; azure-waf-log-standard.md §2c.
        MITRE T1190 (Initial Access via public-facing app), severity critical.
        CAPEC-248 Command Injection (capec.mitre.org).
        """
        raw = _raw_event_from_fixture("app_gateway_932100_rce_block.json")
        event = plugin.normalize(raw, "test-instance")

        # Category: 932xxx → Remote Code Execution (CRS range table, §2c)
        assert event.category == "Remote Code Execution", (
            f"932100 must map to 'Remote Code Execution' (932xxx RCE range); "
            f"got {event.category!r}"
        )
        # CAPEC-248 Command Injection (capec.mitre.org)
        assert event.capec_id == "CAPEC-248", (
            f"932xxx → CAPEC-248 Command Injection (capec.mitre.org); "
            f"got {event.capec_id!r}"
        )
        # Severity: critical (azure-waf-log-standard.md §2c — RCE is highest severity)
        assert event.severity == "critical", (
            f"RCE → severity 'critical' (azure-waf-log-standard.md §2c); "
            f"got {event.severity!r}"
        )
        assert event.ocsf_class == 4002
        assert event.ocsf_category == 4

    def test_app_gateway_913100_scanner_tuple(self, plugin: Any) -> None:
        """913100 (Scanner/Recon) → full tuple per CRS §2c.

        Rule 913100: security scanner User-Agent detection — 913xxx scanner family.
        Source: OWASP CRS docs; azure-waf-log-standard.md §2c.
        MITRE T1595 Active Scanning (TA0043 Reconnaissance) — attack.mitre.org.
        CAPEC-169 Footprinting / CAPEC-118 Scanning for Vulnerable Software.
        Severity: low.
        """
        raw = _raw_event_from_fixture("app_gateway_913100_scanner_allowed.json")
        event = plugin.normalize(raw, "test-instance")

        # Category: 913xxx → Scanner / Recon Detection (CRS range table, §2c)
        assert event.category == "Scanner / Recon Detection", (
            f"913100 must map to 'Scanner / Recon Detection' (913xxx range); "
            f"got {event.category!r}"
        )
        # MITRE T1595 Active Scanning (TA0043 Reconnaissance — attack.mitre.org)
        assert event.attack_technique == "T1595", (
            f"913xxx → T1595 Active Scanning (MITRE ATT&CK, attack.mitre.org, "
            f"TA0043 Reconnaissance); got {event.attack_technique!r}"
        )
        assert event.attack_tactic == "TA0043", (
            f"913xxx → TA0043 Reconnaissance (MITRE ATT&CK); got {event.attack_tactic!r}"
        )
        # CAPEC-169 Footprinting (capec.mitre.org)
        assert event.capec_id == "CAPEC-169", (
            f"913xxx → CAPEC-169 Footprinting (capec.mitre.org); got {event.capec_id!r}"
        )
        # Severity: low (azure-waf-log-standard.md §2c — scanner/recon = low)
        assert event.severity == "low", (
            f"Scanner/Recon → severity 'low' (azure-waf-log-standard.md §2c); "
            f"got {event.severity!r}"
        )
        assert event.ocsf_class == 4002
        assert event.ocsf_category == 4

    def test_app_gateway_942100_sqli_tuple(self, plugin: Any) -> None:
        """942100 (SQLi) → full tuple per CRS §2c.

        Rule 942100: SQL Injection via libinjection — 942xxx SQLi family.
        Source: MS Learn Front Door example (azure-waf-log-standard.md §4).
        MITRE T1190 Exploit Public-Facing Application (TA0001), severity high.
        CAPEC-66 SQL Injection (capec.mitre.org).
        """
        raw = _raw_event_from_fixture("app_gateway_942100_sqli_log.json")
        event = plugin.normalize(raw, "test-instance")

        # Category: 942xxx → SQL Injection (CRS range table, §2c)
        assert event.category == "SQL Injection", (
            f"942100 must map to 'SQL Injection' (942xxx range); got {event.category!r}"
        )
        # MITRE T1190 Exploit Public-Facing Application (attack.mitre.org)
        assert event.attack_technique == "T1190", (
            f"942xxx → T1190 Exploit Public-Facing Application (MITRE ATT&CK); "
            f"got {event.attack_technique!r}"
        )
        # CAPEC-66 SQL Injection (capec.mitre.org)
        assert event.capec_id == "CAPEC-66", (
            f"942xxx → CAPEC-66 SQL Injection (capec.mitre.org); got {event.capec_id!r}"
        )
        # Severity: high (azure-waf-log-standard.md §2c — SQLi)
        assert event.severity == "high", (
            f"SQL Injection → severity 'high' (azure-waf-log-standard.md §2c); "
            f"got {event.severity!r}"
        )
        assert event.ocsf_class == 4002
        assert event.ocsf_category == 4


# ---------------------------------------------------------------------------
# EARS-A2: Front Door action dispositions
# ---------------------------------------------------------------------------


class TestFrontDoorActionDispositions:
    """EARS-A2: Front Door action dispositions are correctly mapped.

    Front Door uses different casing conventions from App Gateway (e.g. 'Block'
    not 'Blocked', 'AnomalyScoring' not 'Matched') — the plugin normalizes case
    before lookup (azure-waf-log-standard.md §1c).
    """

    def test_front_door_block_maps_to_block(self, plugin: Any) -> None:
        """Front Door action=Block → BLOCK.

        MS Learn Front Door example (azure-waf-log-standard.md §4) uses 'Block'.
        Source: azure-waf-log-standard.md §2b.
        """
        raw = _raw_event_from_fixture("front_door_942100_sqli_block.json")
        event = plugin.normalize(raw, "test-instance")

        assert event.action == "BLOCK", (
            "Front Door action=Block must map to BLOCK (terminating). "
            "Source: azure-waf-log-standard.md §2b."
        )

    def test_front_door_anomalyscoring_maps_to_alert_not_block(self, plugin: Any) -> None:
        """Front Door action=AnomalyScoring → ALERT (NOT BLOCK).

        AnomalyScoring = Front Door equivalent of App Gateway 'Matched' —
        non-terminating; the anomaly score was incremented but no block occurred yet.
        Source: azure-waf-log-standard.md §1c / §2b.
        Legacy bug (sync.py:90): AnomalyScoring would have fallen under the
        {Blocked/Detected/Matched}→BLOCK umbrella — this fixture guards against it.
        """
        raw = _raw_event_from_fixture("front_door_941100_xss_anomalyscoring.json")
        event = plugin.normalize(raw, "test-instance")

        assert event.action == "ALERT", (
            "Front Door action=AnomalyScoring must map to ALERT — non-terminating "
            "anomaly-score contribution (equivalent to App Gateway Matched). "
            "Source: azure-waf-log-standard.md §1c / §2b."
        )
        assert event.action != "BLOCK", (
            "Front Door action=AnomalyScoring must NOT be BLOCK — "
            "this guards the legacy bug where non-terminating events were mislabeled."
        )

    def test_front_door_log_maps_to_log(self, plugin: Any) -> None:
        """Front Door action=Log → LOG (informational).

        Source: azure-waf-log-standard.md §2b, OCSF disposition_id=17.
        """
        raw = _raw_event_from_fixture("front_door_913110_scanner_log.json")
        event = plugin.normalize(raw, "test-instance")

        assert event.action == "LOG", (
            "Front Door action=Log must map to LOG (informational). "
            "Source: azure-waf-log-standard.md §2b, OCSF disposition_id=17."
        )


# ---------------------------------------------------------------------------
# EARS-A4: Cross-shape consistency — Front Door ruleName parsed → same tuple
# ---------------------------------------------------------------------------


class TestCrossShapeConsistency:
    """EARS-A4: Front Door ruleName parsing produces the SAME tuple as App Gateway ruleId.

    Front Door packs CRS metadata into a single dotted ruleName string
    (``{ruleset}-{version}-{group}-{ruleId}``); the rule ID is parsed from the
    trailing numeric segment.  The normalized SecurityEvent must carry the SAME
    (category, attack_technique, capec_id) tuple regardless of which product shape
    the log came from.

    Source: azure-waf-log-standard.md §1b (Front Door field shape) + §2c (CRS table).
    """

    def test_sqli_942100_cross_shape_consistency(self, plugin: Any) -> None:
        """Front Door 'Microsoft_DefaultRuleSet-1.1-SQLI-942100' and App Gateway
        ruleId='942100' produce the SAME (category, technique, capec) tuple.

        The trailing '942100' in the Front Door ruleName must be parsed out and
        produce the same CRS lookup result as the discrete ruleId field.
        Source: azure-waf-log-standard.md §1b (ruleName parsing) / §2c (CRS table).
        """
        agw_raw = _raw_event_from_fixture("app_gateway_942100_sqli_log.json")
        fd_raw = _raw_event_from_fixture("front_door_942100_sqli_block.json")

        agw_event = plugin.normalize(agw_raw, "agw-test")
        fd_event = plugin.normalize(fd_raw, "fd-test")

        assert fd_event.rule_id == "942100", (
            f"Front Door: rule_id must be parsed from ruleName trailing segment "
            f"'...SQLI-942100' → '942100'; got {fd_event.rule_id!r}"
        )
        assert agw_event.category == fd_event.category, (
            f"Cross-shape consistency: App Gateway ruleId=942100 and Front Door "
            f"ruleName ending in -942100 must produce the same category. "
            f"AGW: {agw_event.category!r}, FD: {fd_event.category!r}"
        )
        assert agw_event.attack_technique == fd_event.attack_technique, (
            f"Cross-shape consistency: attack_technique must match. "
            f"AGW: {agw_event.attack_technique!r}, FD: {fd_event.attack_technique!r}"
        )
        assert agw_event.capec_id == fd_event.capec_id, (
            f"Cross-shape consistency: capec_id must match. "
            f"AGW: {agw_event.capec_id!r}, FD: {fd_event.capec_id!r}"
        )

    def test_xss_941100_cross_shape_consistency(self, plugin: Any) -> None:
        """Front Door 'Microsoft_DefaultRuleSet-2.1-XSS-941100' → same tuple as App Gateway 941100.

        The XSS family (941xxx) cross-shape check: Front Door dotted ruleName
        vs App Gateway discrete ruleId — both must yield XSS category + T1059 + CAPEC-63.
        Source: azure-waf-log-standard.md §1b / §2c; OWASP CRS docs.
        """
        agw_raw = _raw_event_from_fixture("app_gateway_941100_xss_detected.json")
        fd_raw = _raw_event_from_fixture("front_door_941100_xss_anomalyscoring.json")

        agw_event = plugin.normalize(agw_raw, "agw-test")
        fd_event = plugin.normalize(fd_raw, "fd-test")

        assert fd_event.rule_id == "941100", (
            f"Front Door: rule_id from 'Microsoft_DefaultRuleSet-2.1-XSS-941100' "
            f"must be '941100'; got {fd_event.rule_id!r}"
        )
        assert agw_event.category == fd_event.category, (
            f"XSS cross-shape: category must match. "
            f"AGW: {agw_event.category!r}, FD: {fd_event.category!r}"
        )
        assert agw_event.attack_technique == fd_event.attack_technique, (
            f"XSS cross-shape: attack_technique must match. "
            f"AGW: {agw_event.attack_technique!r}, FD: {fd_event.attack_technique!r}"
        )
        assert agw_event.capec_id == fd_event.capec_id, (
            f"XSS cross-shape: capec_id must match. "
            f"AGW: {agw_event.capec_id!r}, FD: {fd_event.capec_id!r}"
        )

    def test_scanner_913110_cross_shape_consistency(self, plugin: Any) -> None:
        """Front Door 'Microsoft_DefaultRuleSet-2.1-SCANNER-913110' → same as App Gateway 913100.

        Scanner family (913xxx): both fixtures should resolve to 'Scanner / Recon Detection'.
        Note: 913110 and 913100 are both in the 913xxx range, so same CRS table entry.
        Source: OWASP CRS docs; azure-waf-log-standard.md §2c.
        """
        agw_raw = _raw_event_from_fixture("app_gateway_913100_scanner_allowed.json")
        fd_raw = _raw_event_from_fixture("front_door_913110_scanner_log.json")

        agw_event = plugin.normalize(agw_raw, "agw-test")
        fd_event = plugin.normalize(fd_raw, "fd-test")

        assert fd_event.rule_id == "913110", (
            f"Front Door: rule_id from '...SCANNER-913110' must be '913110'; "
            f"got {fd_event.rule_id!r}"
        )
        assert agw_event.category == fd_event.category, (
            f"Scanner cross-shape: category must match. "
            f"AGW: {agw_event.category!r}, FD: {fd_event.category!r}"
        )
        assert agw_event.attack_technique == fd_event.attack_technique, (
            f"Scanner cross-shape: attack_technique must match. "
            f"AGW: {agw_event.attack_technique!r}, FD: {fd_event.attack_technique!r}"
        )
        assert agw_event.capec_id == fd_event.capec_id, (
            f"Scanner cross-shape: capec_id must match. "
            f"AGW: {agw_event.capec_id!r}, FD: {fd_event.capec_id!r}"
        )


# ---------------------------------------------------------------------------
# EARS-A4 (Front Door specific): ruleName parsing mechanics
# ---------------------------------------------------------------------------


class TestFrontDoorRuleNameParsing:
    """EARS-A4 supplement: Front Door ruleName produces the correct parsed rule_id
    and preserves the full dotted string in rule_name for forensic drill-down.

    Source: azure-waf-log-standard.md §1b.
    """

    def test_sqli_rule_name_full_string_preserved(self, plugin: Any) -> None:
        """The full dotted ruleName is stored in rule_name (provenance for drill-down).

        azure-waf-log-standard.md §1b: ruleName = {ruleset}-{version}-{group}-{ruleId}.
        Preserving the full string allows an operator to reconstruct the exact policy rule.
        """
        raw = _raw_event_from_fixture("front_door_942100_sqli_block.json")
        event = plugin.normalize(raw, "test-instance")

        assert event.rule_name == "Microsoft_DefaultRuleSet-1.1-SQLI-942100", (
            f"Front Door rule_name must preserve the full dotted ruleName string; "
            f"got {event.rule_name!r}"
        )

    def test_sqli_source_ip_from_client_ip_pascal(self, plugin: Any) -> None:
        """Front Door uses 'clientIP' (capital P) — differs from App Gateway 'clientIp'.

        azure-waf-log-standard.md §1b: Front Door field is clientIP.
        Source: MS Learn Front Door WAF monitoring docs.
        """
        raw = _raw_event_from_fixture("front_door_942100_sqli_block.json")
        event = plugin.normalize(raw, "test-instance")

        assert event.source_ip == "203.0.113.10", (
            f"Front Door source_ip must come from clientIP field (capital P); "
            f"got {event.source_ip!r}"
        )

    def test_sqli_source_port_from_client_port(self, plugin: Any) -> None:
        """Front Door carries clientPort (App Gateway does not) — must populate source_port.

        azure-waf-log-standard.md §1b: clientPort field present on Front Door.
        """
        raw = _raw_event_from_fixture("front_door_942100_sqli_block.json")
        event = plugin.normalize(raw, "test-instance")

        assert event.source_port == 52097, (
            f"Front Door source_port must be parsed from clientPort='52097'; "
            f"got {event.source_port!r}"
        )

    def test_sqli_tracking_reference_as_source_event_id(self, plugin: Any) -> None:
        """Front Door uses trackingReference as source_event_id.

        azure-waf-log-standard.md §1b: trackingReference = unique request ID.
        """
        raw = _raw_event_from_fixture("front_door_942100_sqli_block.json")
        event = plugin.normalize(raw, "test-instance")

        assert event.source_event_id == "08Q3gXgAAAAA_DEMO_REF_0000000000", (
            f"Front Door source_event_id must come from trackingReference; "
            f"got {event.source_event_id!r}"
        )

    def test_xss_payload_snippet_from_matches(self, plugin: Any) -> None:
        """Front Door details.matches[].matchVariableValue populates payload_snippet.

        azure-waf-log-standard.md §1b: matches[] holds the triggering value.
        """
        raw = _raw_event_from_fixture("front_door_941100_xss_anomalyscoring.json")
        event = plugin.normalize(raw, "test-instance")

        assert event.payload_snippet is not None, (
            "payload_snippet must be populated from Front Door details.matches[]"
        )
        assert "script" in (event.payload_snippet or "").lower(), (
            f"payload_snippet should contain XSS script fragment; "
            f"got {event.payload_snippet!r}"
        )
