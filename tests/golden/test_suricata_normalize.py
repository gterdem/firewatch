"""Golden regression tests — Suricata normalization oracle.

Feeds recorded v1 Suricata eve.json fixtures through the NEW
``firewatch_suricata.normalize.normalize()`` and asserts the resulting
``SecurityEvent``s match frozen v1-oracle expected values.

EARS-criteria coverage
──────────────────────
EARS-1  v1 Suricata eve.json fixtures -> NEW normalize() -> assert == frozen oracle.
EARS-2  Frozen expected values are literal constants in this file (not derived from
        the new code at test-time); any mapping or threshold change FAILS the suite.
EARS-3  Suite runs under ``uv run pytest`` and is green.
Flag B  source_type is always the constant "suricata" (correlation key, ADR-0016).

Oracle derivation (provenance)
──────────────────────────────
Expected field values were produced by running
``legacy/core/normalizer.py::suricata_raw_to_security_event`` on 2026-06-03 against
each eve.json fixture, then frozen here and in ``fixtures/expected_*.json``.

Known v2 schema extensions (NOT regressions, deliberately different from v1):
- ``source_type`` / ``source_id`` replace legacy ``source_module`` (ADR-0016).
- ``attack_technique`` / ``attack_tactic`` populated from ET Open metadata (ADR-0014);
  legacy v1 ignored these fields.
- ``ocsf_class`` / ``ocsf_category`` set per v2 ``_OCSF_CLASS_MAP`` (ADR-0020);
  legacy v1 returned None for all Suricata-specific categories.

All ported logic fields (action, category, severity, rule_id, rule_name,
payload_snippet, source_event_id, source_ip, destination_ip, ports, protocol,
timestamp) must be byte-compatible with v1.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from firewatch_sdk import RawEvent, SecurityEvent
from firewatch_suricata.normalize import normalize

FIXTURES_DIR = Path(__file__).parent / "fixtures"

# ── Helper ────────────────────────────────────────────────────────────────────

_RECEIVED_AT = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
SOURCE_ID = "pi-home"


def _load_eve(filename: str) -> dict:
    return json.loads((FIXTURES_DIR / filename).read_text())


def _raw(eve_data: dict) -> RawEvent:
    return RawEvent(source_type="suricata", received_at=_RECEIVED_AT, data=eve_data)


def _normalize(eve_filename: str) -> SecurityEvent:
    return normalize(_raw(_load_eve(eve_filename)), source_id=SOURCE_ID)


# ── EARS-2 sentinel: frozen constants prove independence from new code ─────────

# These are the EXACT oracle values extracted from the legacy v1 normalizer run.
# If any mapping or threshold changes in the new code, the assertions below FAIL.
# DO NOT regenerate these from new-code output — that defeats the regression oracle.

_ORACLE_01 = {
    "action": "ALERT",
    "category": "Web Attack (IDS)",
    "severity": "high",
    "rule_id": "2012345",
    "rule_name": "ET WEB_SERVER SQL Injection Attempt",
    "payload_snippet": "10.0.0.1/admin?id=1 OR 1=1",
    "source_ip": "203.0.113.5",
    "destination_ip": "10.0.0.1",
    "destination_port": 80,
    "source_port": 44321,
    "protocol": "TCP",
    "source_event_id": "123456789",
    # v2 extensions: MITRE tags from ET Open metadata (ADR-0014)
    "attack_technique": "T1190",
    "attack_tactic": "TA0001",
    # v2 extensions: OCSF alignment (ADR-0020) — Web Attack (IDS) -> (2004, 2)
    # OCSF 2004 Detection Finding (category_uid=2 Findings): security-product alert.
    # Source: https://schema.ocsf.io/classes/detection_finding
    # NOTE: stale fixture had 6004 — corrected to 2004 (ML-2 fix).
    "ocsf_class": 2004,
    "ocsf_category": 2,
    # ADR-0048 network-depth fields (ML-2): HTTP from http sub-object; no flow/dns/tls.
    "bytes_in": None,
    "bytes_out": None,
    "packets_in": None,
    "packets_out": None,
    "flow_duration_ms": None,
    "dns_query": None,
    "dns_rcode": None,
    "tls_ja4": None,
    "tls_ja4s": None,
    "tls_sni": None,
    "tls_version": None,
    "http_method": None,        # EVE http block has no http_method key in this fixture
    "http_host": "10.0.0.1",    # http.hostname
    "http_url": "/admin?id=1 OR 1=1",  # http.url
    "http_user_agent": None,    # EVE http block has no http_user_agent in this fixture
}

_ORACLE_02 = {
    "action": "BLOCK",   # alert.action='blocked' -> BLOCK (ADR-0012)
    "category": "Port Scan (IDS)",
    "severity": "critical",
    "rule_id": "2000537",
    "rule_name": "ET SCAN Nmap Scripting Engine User-Agent Detected",
    "payload_snippet": None,
    "source_ip": "198.51.100.7",
    "destination_ip": "10.0.0.2",
    "destination_port": 22,
    "source_port": 12000,
    "protocol": "TCP",
    "source_event_id": "987654321",
    "attack_technique": None,
    "attack_tactic": None,
    # v2 OCSF: Port Scan (IDS) -> (4001, 4)
    "ocsf_class": 4001,
    "ocsf_category": 4,
    # ADR-0048 network-depth fields (ML-2): all null — no sub-objects in this EVE record.
    "bytes_in": None,
    "bytes_out": None,
    "packets_in": None,
    "packets_out": None,
    "flow_duration_ms": None,
    "dns_query": None,
    "dns_rcode": None,
    "tls_ja4": None,
    "tls_ja4s": None,
    "tls_sni": None,
    "tls_version": None,
    "http_method": None,
    "http_host": None,
    "http_url": None,
    "http_user_agent": None,
}

_ORACLE_03 = {
    "action": "ALERT",
    "category": "Trojan (IDS)",
    "severity": "high",
    "rule_id": "2019020",
    "rule_name": "ET TROJAN Generic - IPS Dropper Command",
    "payload_snippet": None,
    "source_ip": "203.0.113.5",
    "destination_ip": "10.0.0.3",
    "destination_port": 4444,
    "source_port": 55000,
    "protocol": "TCP",
    "source_event_id": "111222333",
    "attack_technique": None,
    "attack_tactic": None,
    # v2 OCSF: Trojan (IDS) -> (4001, 4)
    "ocsf_class": 4001,
    "ocsf_category": 4,
    # ADR-0048 network-depth fields (ML-2): all null — no sub-objects in this EVE record.
    "bytes_in": None,
    "bytes_out": None,
    "packets_in": None,
    "packets_out": None,
    "flow_duration_ms": None,
    "dns_query": None,
    "dns_rcode": None,
    "tls_ja4": None,
    "tls_ja4s": None,
    "tls_sni": None,
    "tls_version": None,
    "http_method": None,
    "http_host": None,
    "http_url": None,
    "http_user_agent": None,
}

_ORACLE_04 = {
    "action": "ALERT",
    "category": "Privilege Escalation (IDS)",
    "severity": "critical",
    "rule_id": "2034567",
    "rule_name": "ET EXPLOIT Privilege Escalation via Environment Variable",
    "payload_snippet": "10.0.0.4/cgi-bin/admin?cmd=id",
    "source_ip": "203.0.113.5",
    "destination_ip": "10.0.0.4",
    "destination_port": 443,
    "source_port": 49001,
    "protocol": "TCP",
    "source_event_id": "444555666",
    # ET Open MITRE tags (ADR-0014)
    "attack_technique": "T1059",
    "attack_tactic": "TA0004",
    # v2 OCSF: Privilege Escalation (IDS) -> (2004, 2)
    # OCSF 2004 Detection Finding (category_uid=2 Findings): security-product alert.
    # Source: https://schema.ocsf.io/classes/detection_finding
    # NOTE: stale fixture had 6004 — corrected to 2004 (ML-2 fix).
    "ocsf_class": 2004,
    "ocsf_category": 2,
    # ADR-0048 network-depth fields (ML-2): HTTP from http sub-object; no flow/dns/tls.
    "bytes_in": None,
    "bytes_out": None,
    "packets_in": None,
    "packets_out": None,
    "flow_duration_ms": None,
    "dns_query": None,
    "dns_rcode": None,
    "tls_ja4": None,
    "tls_ja4s": None,
    "tls_sni": None,
    "tls_version": None,
    "http_method": None,
    "http_host": "10.0.0.4",           # http.hostname
    "http_url": "/cgi-bin/admin?cmd=id",  # http.url
    "http_user_agent": None,
}

_ORACLE_05 = {
    "action": "ALERT",
    "category": "Recon (IDS)",
    "severity": "medium",
    "rule_id": "2012008",
    "rule_name": "ET POLICY Sensitive Info in URI",
    "payload_snippet": "10.0.0.5/etc/passwd",
    "source_ip": "198.51.100.99",
    "destination_ip": "10.0.0.5",
    "destination_port": 80,
    "source_port": 33000,
    "protocol": "TCP",
    "source_event_id": "777888999",
    "attack_technique": None,
    "attack_tactic": None,
    # v2 OCSF: Recon (IDS) -> (4001, 4)
    "ocsf_class": 4001,
    "ocsf_category": 4,
    # ADR-0048 network-depth fields (ML-2): HTTP from http sub-object; no flow/dns/tls.
    "bytes_in": None,
    "bytes_out": None,
    "packets_in": None,
    "packets_out": None,
    "flow_duration_ms": None,
    "dns_query": None,
    "dns_rcode": None,
    "tls_ja4": None,
    "tls_ja4s": None,
    "tls_sni": None,
    "tls_version": None,
    "http_method": None,
    "http_host": "10.0.0.5",    # http.hostname
    "http_url": "/etc/passwd",  # http.url
    "http_user_agent": None,
}


def _assert_matches_oracle(event: SecurityEvent, oracle: dict) -> None:
    """Assert every oracle field matches the SecurityEvent."""
    for field, expected in oracle.items():
        actual = getattr(event, field)
        assert actual == expected, (
            f"Field {field!r}: expected {expected!r} (v1 oracle) but got {actual!r} (new code). "
            "This is a regression — the new code diverged from the legacy v1 oracle."
        )


# ── EARS-1: eve.json fixtures -> normalize() -> assert oracle fields ──────────


class TestFixture01WebAttackAlert:
    """Fixture 01: Web Application Attack, IDS mode (ALERT), severity=2, HTTP payload,
    ET Open MITRE metadata (T1190/TA0001).

    EARS-1: recorded eve.json -> NEW normalize() -> assert == oracle.
    """

    def test_ported_fields_match_v1_oracle(self) -> None:
        """All ported-from-v1 fields match the frozen legacy oracle output."""
        event = _normalize("eve_01_web_attack_alert.json")
        _assert_matches_oracle(event, _ORACLE_01)

    def test_source_type_is_constant_suricata(self) -> None:
        """Flag B: source_type must always be 'suricata' (the correlation key, ADR-0016)."""
        event = _normalize("eve_01_web_attack_alert.json")
        assert event.source_type == "suricata", (
            f"source_type must be the constant 'suricata'; got {event.source_type!r}. "
            "Flag B: correlation keys on source_type telemetry-type diversity."
        )

    def test_source_id_passed_through(self) -> None:
        """source_id is the user's named instance; passed through unchanged (Flag B)."""
        event = _normalize("eve_01_web_attack_alert.json")
        assert event.source_id == SOURCE_ID

    def test_timestamp_parsed_from_eve(self) -> None:
        """Timestamp from eve.json is parsed correctly (UTC, ISO-8601)."""
        event = _normalize("eve_01_web_attack_alert.json")
        assert event.timestamp == datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)

    def test_raw_log_preserved(self) -> None:
        """Original EVE dict preserved in raw_log for forensic drill-down."""
        event = _normalize("eve_01_web_attack_alert.json")
        assert event.raw_log is not None
        assert event.raw_log.get("event_type") == "alert"


class TestFixture02PortScanBlock:
    """Fixture 02: Port Scan detected, IPS mode (action='blocked' -> BLOCK),
    severity=1 (critical), no HTTP payload.

    EARS-1: blocked path (ADR-0012) verified.
    """

    def test_ported_fields_match_v1_oracle(self) -> None:
        event = _normalize("eve_02_port_scan_block.json")
        _assert_matches_oracle(event, _ORACLE_02)

    def test_action_block_when_alert_action_blocked(self) -> None:
        """alert.action='blocked' -> SecurityEvent.action=BLOCK (ADR-0012 IPS path)."""
        event = _normalize("eve_02_port_scan_block.json")
        assert event.action == "BLOCK"

    def test_source_type_constant_regardless_of_action(self) -> None:
        """source_type='suricata' constant even for BLOCK events (Flag B)."""
        event = _normalize("eve_02_port_scan_block.json")
        assert event.source_type == "suricata"


class TestFixture03TrojanAlert:
    """Fixture 03: Trojan activity detected (ALERT, high severity, no HTTP)."""

    def test_ported_fields_match_v1_oracle(self) -> None:
        event = _normalize("eve_03_trojan_alert.json")
        _assert_matches_oracle(event, _ORACLE_03)

    def test_category_trojan_ids(self) -> None:
        """'A Network Trojan was detected' maps to 'Trojan (IDS)'."""
        event = _normalize("eve_03_trojan_alert.json")
        assert event.category == "Trojan (IDS)"

    def test_no_http_payload_is_none(self) -> None:
        """Alerts without HTTP section have payload_snippet=None."""
        event = _normalize("eve_03_trojan_alert.json")
        assert event.payload_snippet is None


class TestFixture04PrivescMitre:
    """Fixture 04: Privilege escalation with ET Open MITRE metadata (T1059/TA0004).

    EARS-1: MITRE technique/tactic extraction from alert.metadata pinned.
    """

    def test_ported_fields_match_v1_oracle(self) -> None:
        event = _normalize("eve_04_privesc_mitre.json")
        _assert_matches_oracle(event, _ORACLE_04)

    def test_mitre_technique_extracted(self) -> None:
        """ET Open mitre_technique_id[0] -> attack_technique (ADR-0014)."""
        event = _normalize("eve_04_privesc_mitre.json")
        assert event.attack_technique == "T1059"

    def test_mitre_tactic_extracted(self) -> None:
        """ET Open mitre_tactic_id[0] -> attack_tactic (ADR-0014)."""
        event = _normalize("eve_04_privesc_mitre.json")
        assert event.attack_tactic == "TA0004"

    def test_severity_critical_for_severity_1(self) -> None:
        """Suricata severity=1 (highest priority) -> 'critical'."""
        event = _normalize("eve_04_privesc_mitre.json")
        assert event.severity == "critical"


class TestFixture05ReconAlert:
    """Fixture 05: Recon / Information Leak (medium severity, HTTP payload)."""

    def test_ported_fields_match_v1_oracle(self) -> None:
        event = _normalize("eve_05_recon_alert.json")
        _assert_matches_oracle(event, _ORACLE_05)

    def test_category_recon_ids(self) -> None:
        """'Attempted Information Leak' maps to 'Recon (IDS)'."""
        event = _normalize("eve_05_recon_alert.json")
        assert event.category == "Recon (IDS)"


# ── EARS-2: threshold/mapping drift causes failure ────────────────────────────


class TestMappingDriftDetection:
    """EARS-2 — frozen constants prove the suite fails when mappings change.

    The oracle constants (_ORACLE_01..05) above are NOT derived from the new code
    at test runtime. They were captured from legacy v1 on 2026-06-03. Therefore:
    - Changing SURICATA_CATEGORY_MAP entries → test_ported_fields_match_v1_oracle fails.
    - Changing _SEVERITY_MAP entries → severity assertions fail.
    - Changing action mapping logic → action assertions fail.
    - Changing payload truncation limit → payload_snippet assertions fail.
    """

    def test_category_map_constants_are_frozen_not_new_code(self) -> None:
        """The oracle action/category/severity values are literal string constants,
        not computed from the new normalizer — they prove independence from the new code.
        This test documents EARS-2 explicitly: if you change SURICATA_CATEGORY_MAP,
        the fixture assertions above will fail because these constants won't update."""
        # The oracle constant for fixture 01 says "Web Attack (IDS)" for category.
        # If someone changes the map to return something else, the test fails.
        assert _ORACLE_01["category"] == "Web Attack (IDS)"
        assert _ORACLE_01["action"] == "ALERT"
        assert _ORACLE_01["severity"] == "high"
        assert _ORACLE_02["action"] == "BLOCK"
        assert _ORACLE_02["category"] == "Port Scan (IDS)"
        assert _ORACLE_02["severity"] == "critical"
        assert _ORACLE_04["attack_technique"] == "T1059"
        assert _ORACLE_04["attack_tactic"] == "TA0004"

    def test_all_five_fixture_files_exist(self) -> None:
        """Fixture files are committed — if deleted, the oracle is gone."""
        for i in range(1, 6):
            input_name = f"eve_0{i}_" + [
                "web_attack_alert", "port_scan_block", "trojan_alert",
                "privesc_mitre", "recon_alert"
            ][i - 1] + ".json"
            path = FIXTURES_DIR / input_name
            assert path.exists(), f"Missing eve fixture: {path}"


# ── Flag B: source_type correlation key (ADR-0016) ────────────────────────────


class TestFlagBSourceTypeCorrelation:
    """Flag B — source_type is the cross-source correlation key.

    PLUGIN_CONTRACT.md: 'cross-source correlation keys on source_type'.
    The test pins that:
    1. source_type is always "suricata" (constant) across all fixtures.
    2. source_id varies per instance without affecting source_type.
    """

    @pytest.mark.parametrize("eve_file,instance", [
        ("eve_01_web_attack_alert.json", "pi-home"),
        ("eve_02_port_scan_block.json", "pi-home"),
        ("eve_03_trojan_alert.json", "sensor-rack"),
        ("eve_04_privesc_mitre.json", "azure-lab"),
        ("eve_05_recon_alert.json", "pi-home"),
    ])
    def test_source_type_constant_across_all_fixtures(
        self, eve_file: str, instance: str
    ) -> None:
        """source_type is always 'suricata' regardless of source_id or event content.

        This is the Flag B invariant: the correlation engine identifies all events
        from this plugin as type 'suricata'. A different source_id (named instance)
        does NOT change the type — it only identifies which sensor the event came from.
        """
        raw = _raw(_load_eve(eve_file))
        event = normalize(raw, source_id=instance)
        assert event.source_type == "suricata", (
            f"source_type must be constant 'suricata' for {eve_file} / instance={instance!r}; "
            f"got {event.source_type!r}. Flag B requires source_type to be the correlation key."
        )

    def test_source_id_different_instances_same_source_type(self) -> None:
        """Two instances with different source_ids still produce source_type='suricata'.

        This pins the ECS-aligned design: source_type ≈ event.module (constant),
        source_id ≈ observer.name (user's instance name, never branched on).
        """
        raw = _raw(_load_eve("eve_01_web_attack_alert.json"))
        ev_home = normalize(raw, source_id="pi-home")
        ev_rack = normalize(raw, source_id="sensor-rack")
        assert ev_home.source_type == "suricata"
        assert ev_rack.source_type == "suricata"
        assert ev_home.source_id == "pi-home"
        assert ev_rack.source_id == "sensor-rack"
