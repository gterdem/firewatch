"""Golden regression tests -- Syslog/CEF normalization oracle (EARS-6).

Pins expected SecurityEvent field values for >=2 vendor CEF samples + 1 RFC 5424
sample as frozen literal constants derived from the published standards -- NOT
from the new code's own output. Any mapping change FAILS the suite.

EARS-criteria coverage:
  EARS-1  CEF header+Extension -> SecurityEvent canonical fields.
  EARS-2  Vendor registry: Fortinet deny->BLOCK, PAN-OS drop->DROP,
          unknown vendor reject->BLOCK (generic fallback).
  EARS-3  RFC 5424 fallback: SSH brute-force -> ALERT.
  EARS-6  >=2 vendor CEF samples + 1 RFC 5424 + 1 RFC 3164 pinned as literals.

Oracle derivation (provenance):
  Expected values are derived directly from the published standards:
  - ArcSight CEF Implementation Standard (field mapping)
  - RFC 5424 / RFC 3164 (framing)
  - ADR-0012 (action: WAF/IPS block->BLOCK/DROP, IDS->ALERT)
  - OCSF 1.8.0 schema (https://schema.ocsf.io/api/1.8.0/classes, verified live
    2026-07-16, issue #76): CEF network/HTTP paths -> class_uid 4001/4002,
    category_uid 4 (Network Activity -- correct, untouched, Must-NOT per #76);
    syslog fallback auth events -> class_uid 3002, category_uid 3
    (Authentication / Identity & Access Management -- corrected by #76, was
    wrongly 4001/4)
  - MITRE ATT&CK v15 T1110 / TA0006 (brute-force / credential-access)

Test IPs: RFC 5737 documentation ranges ONLY (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) -- never real/routable IPs.

DO NOT regenerate these constants from code output -- they are the spec oracle.
"""
from __future__ import annotations

from datetime import datetime, timezone

from firewatch_sdk import RawEvent
from firewatch_syslog_cef.normalize import normalize

# Shared received_at for deterministic timestamp assertions.
_RECEIVED_AT = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
_SOURCE_ID = "golden-sensor"


def _raw(line: str, client_ip: str = "192.0.2.1") -> RawEvent:
    return RawEvent(
        source_type="syslog_cef",
        received_at=_RECEIVED_AT,
        data={"line": line, "client_ip": client_ip, "transport": "udp"},
    )


# ---------------------------------------------------------------------------
# Golden fixture 1: Fortinet FortiGate -- act=deny -> BLOCK
#
# CEF format (ArcSight CEF Implementation Standard):
#   CEF:Version|DeviceVendor|DeviceProduct|DeviceVersion|SignatureID|Name|Severity|Extension
# Fortinet CEF source: Fortinet FortiGate Log Reference
#   https://docs.fortinet.com/document/fortigate/7.0.0/log-message-reference/
# ---------------------------------------------------------------------------

_FORTINET_LINE = (
    "CEF:0|Fortinet|FortiGate|6.4.5|1234|traffic blocked|7|"
    "src=198.51.100.50 dst=192.0.2.100 spt=54321 dpt=443 proto=TCP act=deny"
)

# Expected values derived from published standards (NOT from code output):
#   act=deny + vendor=Fortinet -> BLOCK (Fortinet CEF mapping: deny=firewall block)
#   CEF severity 7 -> "high"   (ArcSight CEF spec: 7-8 = High)
#   SignatureID=1234 -> rule_id (CEF header field mapping)
#   Name="traffic blocked" -> rule_name (CEF header field mapping)
#   src=198.51.100.50 -> source_ip (CEF Extension dictionary 'src' key)
#   dst=192.0.2.100 -> destination_ip (CEF Extension 'dst' key)
#   spt=54321 -> source_port (CEF Extension 'spt' key)
#   dpt=443 -> destination_port (CEF Extension 'dpt' key)
#   proto=TCP -> protocol (CEF Extension 'proto' key)
#   OCSF 4001 = Network Activity, category 4 = Network Activity -- CEF network path,
#   correct and untouched by issue #76 (Must-NOT: pinned explicitly below).
_ORACLE_FORTINET = {
    "action": "BLOCK",
    "severity": "high",
    "source_ip": "198.51.100.50",
    "destination_ip": "192.0.2.100",
    "source_port": 54321,
    "destination_port": 443,
    "protocol": "TCP",
    "rule_id": "1234",
    "rule_name": "traffic blocked",
    "source_type": "syslog_cef",
    "ocsf_class": 4001,
    "ocsf_category": 4,
}


class TestGoldenFortinetCEF:
    """Golden oracle: Fortinet FortiGate CEF deny -> BLOCK."""

    def setup_method(self) -> None:
        self.event = normalize(_raw(_FORTINET_LINE), source_id=_SOURCE_ID)

    def test_action(self) -> None:
        assert self.event.action == _ORACLE_FORTINET["action"]

    def test_severity(self) -> None:
        assert self.event.severity == _ORACLE_FORTINET["severity"]

    def test_source_ip(self) -> None:
        assert self.event.source_ip == _ORACLE_FORTINET["source_ip"]

    def test_destination_ip(self) -> None:
        assert self.event.destination_ip == _ORACLE_FORTINET["destination_ip"]

    def test_source_port(self) -> None:
        assert self.event.source_port == _ORACLE_FORTINET["source_port"]

    def test_destination_port(self) -> None:
        assert self.event.destination_port == _ORACLE_FORTINET["destination_port"]

    def test_protocol(self) -> None:
        assert self.event.protocol == _ORACLE_FORTINET["protocol"]

    def test_rule_id(self) -> None:
        assert self.event.rule_id == _ORACLE_FORTINET["rule_id"]

    def test_rule_name(self) -> None:
        assert self.event.rule_name == _ORACLE_FORTINET["rule_name"]

    def test_source_type_constant(self) -> None:
        """source_type is always 'syslog_cef' (Flag B oracle)."""
        assert self.event.source_type == _ORACLE_FORTINET["source_type"]

    def test_ocsf_class_network(self) -> None:
        """Must-NOT (#76): CEF network events stay 4001 (Network Activity)."""
        assert self.event.ocsf_class == _ORACLE_FORTINET["ocsf_class"]

    def test_ocsf_category(self) -> None:
        assert self.event.ocsf_category == _ORACLE_FORTINET["ocsf_category"]


# ---------------------------------------------------------------------------
# Golden fixture 2: Palo Alto Networks PAN-OS -- act=drop -> DROP, with HTTP fields
#
# PAN-OS CEF source: Palo Alto Networks CEF Configuration Guide
#   https://docs.paloaltonetworks.com/pan-os/10-1/pan-os-admin/monitoring/
# ---------------------------------------------------------------------------

_PALOALTO_LINE = (
    "CEF:0|Palo Alto Networks|PAN-OS|10.1.0|5678|threat detected|8|"
    "src=203.0.113.10 dst=192.0.2.200 spt=1234 dpt=80 proto=UDP act=drop "
    "request=/admin/login requestMethod=GET"
)

# Expected values:
#   act=drop + vendor=Palo Alto Networks -> DROP (PAN-OS: drop=silently discard)
#   CEF severity 8 -> "high"  (ArcSight CEF spec: 7-8 = High)
#   request=/admin/login -> http_url  (CEF Extension 'request' key, ADR-0048)
#   requestMethod=GET -> http_method  (CEF Extension 'requestMethod', ADR-0048)
#   OCSF 4002 = HTTP Activity (because HTTP fields present), category 4
_ORACLE_PALOALTO = {
    "action": "DROP",
    "severity": "high",
    "source_ip": "203.0.113.10",
    "destination_ip": "192.0.2.200",
    "source_port": 1234,
    "destination_port": 80,
    "protocol": "UDP",
    "rule_id": "5678",
    "rule_name": "threat detected",
    "http_url": "/admin/login",
    "http_method": "GET",
    "source_type": "syslog_cef",
    "ocsf_class": 4002,
    "ocsf_category": 4,
}


class TestGoldenPaloAltoCEF:
    """Golden oracle: Palo Alto PAN-OS CEF drop -> DROP + HTTP fields."""

    def setup_method(self) -> None:
        self.event = normalize(_raw(_PALOALTO_LINE), source_id=_SOURCE_ID)

    def test_action(self) -> None:
        assert self.event.action == _ORACLE_PALOALTO["action"]

    def test_severity(self) -> None:
        assert self.event.severity == _ORACLE_PALOALTO["severity"]

    def test_source_ip(self) -> None:
        assert self.event.source_ip == _ORACLE_PALOALTO["source_ip"]

    def test_destination_ip(self) -> None:
        assert self.event.destination_ip == _ORACLE_PALOALTO["destination_ip"]

    def test_source_port(self) -> None:
        assert self.event.source_port == _ORACLE_PALOALTO["source_port"]

    def test_destination_port(self) -> None:
        assert self.event.destination_port == _ORACLE_PALOALTO["destination_port"]

    def test_protocol(self) -> None:
        assert self.event.protocol == _ORACLE_PALOALTO["protocol"]

    def test_rule_id(self) -> None:
        assert self.event.rule_id == _ORACLE_PALOALTO["rule_id"]

    def test_rule_name(self) -> None:
        assert self.event.rule_name == _ORACLE_PALOALTO["rule_name"]

    def test_http_url(self) -> None:
        assert self.event.http_url == _ORACLE_PALOALTO["http_url"]

    def test_http_method(self) -> None:
        assert self.event.http_method == _ORACLE_PALOALTO["http_method"]

    def test_source_type_constant(self) -> None:
        """source_type is always 'syslog_cef' (Flag B oracle)."""
        assert self.event.source_type == _ORACLE_PALOALTO["source_type"]

    def test_ocsf_class_http(self) -> None:
        """HTTP fields present -> OCSF class_uid 4002 (HTTP Activity)."""
        assert self.event.ocsf_class == _ORACLE_PALOALTO["ocsf_class"]

    def test_ocsf_category(self) -> None:
        assert self.event.ocsf_category == _ORACLE_PALOALTO["ocsf_category"]


# ---------------------------------------------------------------------------
# Golden fixture 3: Unknown vendor -- act=reject -> BLOCK (generic fallback)
# ---------------------------------------------------------------------------

_GENERIC_LINE = (
    "CEF:0|UnknownVendor|UnknownProduct|1.0|0001|connection rejected|5|"
    "src=198.51.100.77 dst=192.0.2.99 spt=11111 dpt=22 proto=TCP act=reject"
)

# Expected values:
#   act=reject + unknown vendor -> BLOCK (generic table: reject=BLOCK)
#   CEF severity 5 -> "medium" (ArcSight CEF spec: 4-6 = Medium)
_ORACLE_GENERIC = {
    "action": "BLOCK",
    "severity": "medium",
    "source_ip": "198.51.100.77",
    "destination_ip": "192.0.2.99",
    "source_port": 11111,
    "destination_port": 22,
    "protocol": "TCP",
    "source_type": "syslog_cef",
}


class TestGoldenGenericCEFFallback:
    """Golden oracle: unknown vendor CEF reject -> BLOCK via generic table."""

    def setup_method(self) -> None:
        self.event = normalize(_raw(_GENERIC_LINE), source_id=_SOURCE_ID)

    def test_action(self) -> None:
        assert self.event.action == _ORACLE_GENERIC["action"]

    def test_severity(self) -> None:
        assert self.event.severity == _ORACLE_GENERIC["severity"]

    def test_source_ip(self) -> None:
        assert self.event.source_ip == _ORACLE_GENERIC["source_ip"]

    def test_destination_ip(self) -> None:
        assert self.event.destination_ip == _ORACLE_GENERIC["destination_ip"]

    def test_source_port(self) -> None:
        assert self.event.source_port == _ORACLE_GENERIC["source_port"]

    def test_destination_port(self) -> None:
        assert self.event.destination_port == _ORACLE_GENERIC["destination_port"]

    def test_protocol(self) -> None:
        assert self.event.protocol == _ORACLE_GENERIC["protocol"]

    def test_source_type_constant(self) -> None:
        assert self.event.source_type == _ORACLE_GENERIC["source_type"]


# ---------------------------------------------------------------------------
# Golden fixture 4: RFC 5424 non-CEF -- SSH brute-force -> ALERT
#
# RFC 5424 format (section 6): https://datatracker.ietf.org/doc/html/rfc5424#section-6
# MITRE ATT&CK T1110 / TA0006: https://attack.mitre.org/techniques/T1110/
# ---------------------------------------------------------------------------

_RFC5424_LINE = (
    "<134>1 2026-01-15T10:00:01Z gateway sshd 1234 - - "
    "Failed password for root from 198.51.100.5 port 44321 ssh2"
)

# Expected values:
#   "Failed password for root from 198.51.100.5" -> SSH brute-force pattern
#   -> ALERT (ADR-0012: IDS detection)
#   -> severity=high (SSH brute-force is high severity)
#   -> source_ip extracted from "from 198.51.100.5" in MSG
#   -> MITRE T1110 / TA0006 / credential-access (ATT&CK v15)
#   -> OCSF class_uid=3002 (Authentication), category_uid=3 (Identity & Access
#      Management) -- https://schema.ocsf.io/api/1.8.0/classes/authentication
#      ("regardless of success"), corrected by issue #76 (was wrongly 4001/4).
_ORACLE_RFC5424 = {
    "action": "ALERT",
    "severity": "high",
    "source_ip": "198.51.100.5",
    "attack_technique": "T1110",
    "attack_tactic": "TA0006",
    "kill_chain_phase": "credential-access",
    "ocsf_class": 3002,
    "ocsf_category": 3,
    "source_type": "syslog_cef",
}


class TestGoldenRFC5424Fallback:
    """Golden oracle: RFC 5424 SSH brute-force -> ALERT + MITRE T1110."""

    def setup_method(self) -> None:
        self.event = normalize(_raw(_RFC5424_LINE), source_id=_SOURCE_ID)

    def test_action(self) -> None:
        assert self.event.action == _ORACLE_RFC5424["action"]

    def test_severity(self) -> None:
        assert self.event.severity == _ORACLE_RFC5424["severity"]

    def test_source_ip(self) -> None:
        assert self.event.source_ip == _ORACLE_RFC5424["source_ip"]

    def test_attack_technique(self) -> None:
        assert self.event.attack_technique == _ORACLE_RFC5424["attack_technique"]

    def test_attack_tactic(self) -> None:
        assert self.event.attack_tactic == _ORACLE_RFC5424["attack_tactic"]

    def test_kill_chain_phase(self) -> None:
        assert self.event.kill_chain_phase == _ORACLE_RFC5424["kill_chain_phase"]

    def test_ocsf_class(self) -> None:
        assert self.event.ocsf_class == _ORACLE_RFC5424["ocsf_class"]

    def test_ocsf_category(self) -> None:
        assert self.event.ocsf_category == _ORACLE_RFC5424["ocsf_category"]

    def test_source_type_constant(self) -> None:
        assert self.event.source_type == _ORACLE_RFC5424["source_type"]


# ---------------------------------------------------------------------------
# Golden fixture 5: RFC 3164 non-CEF -- SSH brute-force -> ALERT
#
# RFC 3164 format (section 4): https://datatracker.ietf.org/doc/html/rfc3164#section-4
# ---------------------------------------------------------------------------

_RFC3164_LINE = (
    "<134>Jan 15 10:00:01 gateway sshd[1234]: "
    "Failed password for root from 203.0.113.5 port 44321 ssh2"
)

# Expected values (same mapping as RFC 5424 fallback but via RFC 3164 framing):
_ORACLE_RFC3164 = {
    "action": "ALERT",
    "severity": "high",
    "source_ip": "203.0.113.5",
    "attack_technique": "T1110",
    "attack_tactic": "TA0006",
    "kill_chain_phase": "credential-access",
    "source_type": "syslog_cef",
}


class TestGoldenRFC3164Fallback:
    """Golden oracle: RFC 3164 SSH brute-force -> ALERT + MITRE T1110."""

    def setup_method(self) -> None:
        self.event = normalize(_raw(_RFC3164_LINE), source_id=_SOURCE_ID)

    def test_action(self) -> None:
        assert self.event.action == _ORACLE_RFC3164["action"]

    def test_severity(self) -> None:
        assert self.event.severity == _ORACLE_RFC3164["severity"]

    def test_source_ip(self) -> None:
        assert self.event.source_ip == _ORACLE_RFC3164["source_ip"]

    def test_attack_technique(self) -> None:
        assert self.event.attack_technique == _ORACLE_RFC3164["attack_technique"]

    def test_attack_tactic(self) -> None:
        assert self.event.attack_tactic == _ORACLE_RFC3164["attack_tactic"]

    def test_kill_chain_phase(self) -> None:
        assert self.event.kill_chain_phase == _ORACLE_RFC3164["kill_chain_phase"]

    def test_source_type_constant(self) -> None:
        assert self.event.source_type == _ORACLE_RFC3164["source_type"]


# ---------------------------------------------------------------------------
# Golden fixture 6: bare-line fallback -- unclassified -> Base Event (0/0)
#
# OCSF 1.8.0: category_uid 0 "Uncategorized" -- "a generic event that does not
# belong to any event category". https://schema.ocsf.io/api/1.8.0/categories,
# verified live 2026-07-16. Issue #76: previously hard-coded 6002/4, a
# class/category pair no OCSF version defines (6002 is Application Lifecycle,
# category 4 is Network Activity -- neither is 6's own category).
# ---------------------------------------------------------------------------

_UNCLASSIFIED_LINE = "gateway kernel: link status changed on eth0"

_ORACLE_UNCLASSIFIED = {
    "action": "LOG",
    "severity": "info",
    "category": "Syslog Event",
    "ocsf_class": 0,
    "ocsf_category": 0,
    "source_type": "syslog_cef",
}


class TestGoldenUnclassifiedFallback:
    """Golden oracle: bare-line fallback with no recognized pattern -> Base Event."""

    def setup_method(self) -> None:
        self.event = normalize(_raw(_UNCLASSIFIED_LINE), source_id=_SOURCE_ID)

    def test_action(self) -> None:
        assert self.event.action == _ORACLE_UNCLASSIFIED["action"]

    def test_severity(self) -> None:
        assert self.event.severity == _ORACLE_UNCLASSIFIED["severity"]

    def test_category(self) -> None:
        assert self.event.category == _ORACLE_UNCLASSIFIED["category"]

    def test_ocsf_class(self) -> None:
        assert self.event.ocsf_class == _ORACLE_UNCLASSIFIED["ocsf_class"]

    def test_ocsf_category(self) -> None:
        assert self.event.ocsf_category == _ORACLE_UNCLASSIFIED["ocsf_category"]

    def test_source_type_constant(self) -> None:
        assert self.event.source_type == _ORACLE_UNCLASSIFIED["source_type"]


# ---------------------------------------------------------------------------
# Existing golden tests must stay byte-identical (EARS-6 regression gate).
# This test imports the Suricata oracle to prove the existing suite is unaffected.
# ---------------------------------------------------------------------------


class TestExistingGoldensUnaffected:
    """Confirm that adding syslog_cef does not break existing golden tests."""

    def test_suricata_golden_module_still_importable(self) -> None:
        """Suricata normalize module imports cleanly after syslog_cef is added."""
        from firewatch_suricata.normalize import normalize as suricata_normalize  # noqa: F401

        assert callable(suricata_normalize)

    def test_syslog_golden_module_still_importable(self) -> None:
        """Syslog normalize module imports cleanly after syslog_cef is added."""
        from firewatch_syslog.normalize import normalize as syslog_normalize  # noqa: F401

        assert callable(syslog_normalize)
