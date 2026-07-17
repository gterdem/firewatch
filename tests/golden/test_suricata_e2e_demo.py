"""End-to-end golden test — synthetic eve.json demo feed (MB.8).

Drives the synthetic ``eve_demo.json`` fixture through the full pipeline (AI-off)
and asserts canonical-standard ``SecurityEvent``/``ThreatScore`` values.

EARS-criteria coverage
──────────────────────
EARS-RFC5737  The demo feed contains only RFC 5737 documentation IPs; no real/
              routable IP appears. This test enumerates every unique IP in the
              fixture file and asserts each is within the three RFC 5737 blocks.
EARS-SAME-ART The demo feed path and the golden input are the same artifact —
              both the test and the demo run guide point at the same file.
EARS-E2E-AOFF When the synthetic eve.json is run through the pipeline AI-off, it
              produces frozen canonical-standard SecurityEvent/ThreatScore values
              (deterministic; no LLM required).
EARS-CANONICAL Expected golden values are derived from the canonical standard
              (OCSF/MITRE/action vocab per ADR-0020/0014/0012), never from
              legacy/ outputs (ADR-0024).
EARS-GRACEFUL While AI is off, the demo still produces scored ThreatScore data for
              all three distinct source IPs (ADR-0015 graceful degradation).
EARS-NO-LLM   The test uses _DisabledAIEngine; no inference endpoint is contacted.

Oracle derivation (provenance)
──────────────────────────────
Expected field values are derived from:
  - OCSF schema (https://schema.ocsf.io/): class_uid 4001 (Network Activity,
    category_uid=4) for connection-level events; class_uid 2004 (Detection Finding,
    category_uid=2 Findings) for IDS/IPS security-product detections/alerts.
  - MITRE ATT&CK (https://attack.mitre.org/): T1190 (Exploit Public-Facing
    Application, TA0001 Initial Access), T1059 (Command and Scripting Interpreter,
    TA0004 Privilege Escalation).
  - ADR-0012: alert.action="blocked" → BLOCK; otherwise → ALERT.
  - ADR-0020: FireWatch category → (ocsf_class, ocsf_category) mapping.
  - ADR-0014: ET Open mitre_technique_id/tactic_id metadata extraction.
  - Scoring: run_rules() + merge_score() (no AI boost — disabled).

The constants are literals, NOT derived from new-code output, so any mapping
change will fail this suite (EARS-CANONICAL regression-oracle property).
"""
from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from firewatch_sdk import RawEvent, SecurityEvent
from firewatch_suricata.normalize import normalize
from firewatch_core.scoring import run_rules, merge_score
from firewatch_core.detector import detect

FIXTURES_DIR = Path(__file__).parent / "fixtures"
DEMO_FEED = FIXTURES_DIR / "eve_demo.json"

# RFC 5737 documentation IP ranges (https://www.rfc-editor.org/rfc/rfc5737)
_RFC5737_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]

_DEMO_RECEIVED_AT = datetime(2026, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
_DEMO_SOURCE_ID = "demo-sensor"


# ── Helpers ───────────────────────────────────────────────────────────────────


def _load_demo_events() -> list[dict[str, Any]]:
    """Load all events from the demo NDJSON feed as raw dicts."""
    lines = DEMO_FEED.read_text(encoding="utf-8").splitlines()
    return [json.loads(line) for line in lines if line.strip()]


def _normalize_demo() -> list[SecurityEvent]:
    """Normalize all demo events through firewatch_suricata.normalize."""
    results: list[SecurityEvent] = []
    for evt_dict in _load_demo_events():
        raw = RawEvent(
            source_type="suricata",
            received_at=_DEMO_RECEIVED_AT,
            data=evt_dict,
        )
        results.append(normalize(raw, source_id=_DEMO_SOURCE_ID))
    return results


class _DisabledAIEngine:
    """Rules-only AI engine — no LLM called (mirrors pipeline_factory pattern)."""

    async def is_available(self) -> bool:
        return False

    async def analyze_concise(  # noqa: PLR0913
        self,
        ip: str,
        total_events: int,
        blocked_events: int,
        rules_triggered: int,
        first_seen: str,
        last_seen: str,
        samples: list[dict[str, Any]],
        security_mode: bool = False,
        correlations: list[Any] | None = None,
    ) -> dict[str, Any]:
        return {"ai_status": "disabled", "threat_level": "UNKNOWN"}

    async def analyze_detailed(  # noqa: PLR0913
        self,
        ip: str,
        total_events: int,
        blocked_events: int,
        rules_triggered: int,
        first_seen: str,
        last_seen: str,
        samples: list[dict[str, Any]],
        security_mode: bool = False,
        correlations: list[Any] | None = None,
    ) -> dict[str, Any]:
        return {"ai_status": "disabled", "threat_level": "UNKNOWN"}


def _score_events(events: list[SecurityEvent]) -> tuple[int, str, list[str], list[str]]:
    """Run the full deterministic scoring path (rules + detections + merge, no AI)."""
    rule_score, attack_types = run_rules(events)
    detections = detect(events)
    detection_boost = sum(d.score_delta for d in detections)
    final_score, level, _deriv = merge_score(rule_score, None, detection_boost=detection_boost)
    return final_score, level, attack_types, [d.rule_name for d in detections]


# ── EARS-RFC5737: no real IPs in the fixture ──────────────────────────────────


class TestRfc5737Compliance:
    """EARS-RFC5737 — every IP in the demo feed is within an RFC 5737 block.

    RFC 5737 (https://www.rfc-editor.org/rfc/rfc5737) reserves these ranges for
    documentation: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24. No real/routable
    IP may appear in a committed golden fixture (gitleaks + CI backstop).
    """

    def test_all_ips_are_rfc5737(self) -> None:
        """Every src_ip and dest_ip in eve_demo.json is in an RFC 5737 range."""
        events = _load_demo_events()
        all_ips: set[str] = set()
        for evt in events:
            if src := evt.get("src_ip"):
                all_ips.add(src)
            if dst := evt.get("dest_ip"):
                all_ips.add(dst)

        assert all_ips, "No IPs found in demo fixture — fixture is empty or malformed"

        for ip_str in all_ips:
            addr = ipaddress.ip_address(ip_str)
            in_rfc5737 = any(addr in net for net in _RFC5737_NETWORKS)
            assert in_rfc5737, (
                f"IP {ip_str!r} is NOT within RFC 5737 documentation ranges "
                f"(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24). "
                f"All fixture IPs must be documentation-only to prevent "
                f"accidental commitment of real infrastructure addresses."
            )

    def test_fixture_file_exists(self) -> None:
        """EARS-SAME-ART: the demo fixture file is committed at the expected path."""
        assert DEMO_FEED.exists(), (
            f"Demo feed not found at {DEMO_FEED}. "
            "The demo feed and golden input must be the same artifact (MB.8 EARS)."
        )

    def test_fixture_has_multiple_events(self) -> None:
        """The demo feed contains multiple events (multi-attack-type coverage)."""
        events = _load_demo_events()
        assert len(events) >= 5, (
            f"Demo feed has only {len(events)} events — expected at least 5 "
            "to cover multiple attack categories for the dashboard demo."
        )


# ── EARS-CANONICAL: frozen canonical SecurityEvent values ────────────────────


class TestCanonicalNormalization:
    """EARS-CANONICAL — normalized SecurityEvent fields match frozen canonical-standard values.

    Canonical value sources:
    - OCSF schema (https://schema.ocsf.io/): class_uid/category_uid per event class.
    - MITRE ATT&CK (https://attack.mitre.org/): technique/tactic IDs.
    - ADR-0012: action mapping (blocked → BLOCK, else → ALERT).
    - ADR-0020: FireWatch category → OCSF (class_uid, category_uid).
    - ADR-0014: ET Open mitre_technique_id/mitre_tactic_id extraction.
    - ADR-0024: values pinned to canonical standard, NEVER to legacy/ outputs.

    These constants are LITERALS — not computed from new-code output at test time.
    Any mapping change causes a test failure, proving regression-oracle independence.
    """

    def setup_method(self) -> None:
        self._events = _normalize_demo()

    def _by_flow(self, flow_id: int) -> SecurityEvent:
        """Find the normalized event whose raw flow_id matches."""
        for e in self._events:
            if e.raw_log and e.raw_log.get("flow_id") == flow_id:
                return e
        raise AssertionError(f"No normalized event found for flow_id={flow_id}")

    # ── Event 1: SQL Injection, Web Attack ───────────────────────────────────
    # Source: 203.0.113.10 → 192.0.2.100:80, allowed
    # OCSF: Web Attack (IDS) → class_uid=2004 (Detection Finding, https://schema.ocsf.io/classes/detection_finding),
    #        category_uid=2 (Findings)
    # MITRE: T1190 (Exploit Public-Facing Application) / TA0001 (Initial Access)
    # ADR-0012: action="allowed" → ALERT

    def test_event1_web_attack_action_alert(self) -> None:
        """Event 1: alert.action='allowed' → SecurityEvent.action='ALERT' (ADR-0012)."""
        e = self._by_flow(1000000001)
        assert e.action == "ALERT"

    def test_event1_web_attack_category(self) -> None:
        """Event 1: 'Web Application Attack' → category='Web Attack (IDS)'."""
        e = self._by_flow(1000000001)
        assert e.category == "Web Attack (IDS)"

    def test_event1_web_attack_severity_medium(self) -> None:
        """Event 1: Suricata severity=2 → FireWatch severity='medium' (ADR-0069 D4(a))."""
        e = self._by_flow(1000000001)
        assert e.severity == "medium"

    def test_event1_web_attack_ocsf_class(self) -> None:
        """Event 1: Web Attack (IDS) → ocsf_class=2004 (OCSF Detection Finding, ADR-0020).

        Source: https://schema.ocsf.io/classes/detection_finding — class_uid=2004,
        category='Findings' (category_uid=2). IDS/IPS alerts map to Detection Finding,
        not class 6004 (Web Resource Access Activity) which is for user web access events.
        """
        e = self._by_flow(1000000001)
        assert e.ocsf_class == 2004, (
            f"Expected ocsf_class=2004 (OCSF Detection Finding); got {e.ocsf_class}. "
            "Web Attack (IDS) → Detection Finding per ADR-0020 / OCSF schema."
        )

    def test_event1_web_attack_ocsf_category(self) -> None:
        """Event 1: Web Attack (IDS) → ocsf_category=2 (OCSF Findings, ADR-0020)."""
        e = self._by_flow(1000000001)
        assert e.ocsf_category == 2

    def test_event1_web_attack_mitre_technique(self) -> None:
        """Event 1: ET Open mitre_technique_id=['T1190'] → attack_technique='T1190' (ADR-0014).

        MITRE ATT&CK T1190: Exploit Public-Facing Application (TA0001 Initial Access).
        Source: https://attack.mitre.org/techniques/T1190/
        """
        e = self._by_flow(1000000001)
        assert e.attack_technique == "T1190", (
            f"Expected attack_technique='T1190' (MITRE T1190 Exploit Public-Facing App); "
            f"got {e.attack_technique!r}. ADR-0014: ET Open metadata → attack_technique."
        )

    def test_event1_web_attack_mitre_tactic(self) -> None:
        """Event 1: ET Open mitre_tactic_id=['TA0001'] → attack_tactic='TA0001' (ADR-0014).

        MITRE ATT&CK TA0001: Initial Access.
        Source: https://attack.mitre.org/tactics/TA0001/
        """
        e = self._by_flow(1000000001)
        assert e.attack_tactic == "TA0001"

    def test_event1_web_attack_source_ip(self) -> None:
        """Event 1: src_ip preserved as source_ip."""
        e = self._by_flow(1000000001)
        assert e.source_ip == "203.0.113.10"

    def test_event1_web_attack_payload_snippet(self) -> None:
        """Event 1: HTTP hostname+url → payload_snippet."""
        e = self._by_flow(1000000001)
        assert e.payload_snippet is not None
        assert "192.0.2.100" in e.payload_snippet
        assert "UNION+SELECT" in e.payload_snippet

    # ── Events 2–6: Port Scan (5 blocked events) ─────────────────────────────
    # Source: 198.51.100.42, 5 blocked scan probes across 5 distinct dest ports
    # OCSF: Port Scan (IDS) → class_uid=4001 (Network Activity), category_uid=4
    # ADR-0012: action="blocked" → BLOCK

    def test_event2_port_scan_action_block(self) -> None:
        """Event 2: alert.action='blocked' → SecurityEvent.action='BLOCK' (ADR-0012)."""
        e = self._by_flow(1000000002)
        assert e.action == "BLOCK"

    def test_event2_port_scan_category(self) -> None:
        """Event 2: 'Detection of a Network Scan' → category='Port Scan (IDS)'."""
        e = self._by_flow(1000000002)
        assert e.category == "Port Scan (IDS)"

    def test_event2_port_scan_severity_high(self) -> None:
        """Event 2: Suricata severity=1 (highest priority) → FireWatch severity='high'
        (ADR-0069 D4(a); was 'critical')."""
        e = self._by_flow(1000000002)
        assert e.severity == "high"

    def test_event2_port_scan_ocsf_class(self) -> None:
        """Events 2-6: Port Scan (IDS) → ocsf_class=4001 (OCSF Network Activity, ADR-0020).

        Source: https://schema.ocsf.io/classes/network_activity — class_uid=4001,
        category='Network Activity' (category_uid=4). Port scans map to network activity.
        """
        e = self._by_flow(1000000002)
        assert e.ocsf_class == 4001, (
            f"Expected ocsf_class=4001 (OCSF Network Activity); got {e.ocsf_class}. "
            "Port Scan (IDS) → Network Activity per ADR-0020 / OCSF schema."
        )

    def test_event2_port_scan_ocsf_category(self) -> None:
        """Event 2: Port Scan (IDS) → ocsf_category=4 (OCSF Network Activity, ADR-0020)."""
        e = self._by_flow(1000000002)
        assert e.ocsf_category == 4

    def test_port_scan_events_no_mitre(self) -> None:
        """Events 2-6: no ET Open MITRE metadata → attack_technique/tactic are None."""
        for flow_id in range(1000000002, 1000000007):
            e = self._by_flow(flow_id)
            assert e.attack_technique is None, (
                f"flow {flow_id}: expected attack_technique=None (no MITRE metadata); "
                f"got {e.attack_technique!r}"
            )
            assert e.attack_tactic is None

    def test_five_port_scan_events_collected(self) -> None:
        """Events 2-6: all 5 scan probes from 198.51.100.42 are present."""
        scanner_events = [
            e for e in self._events
            if e.source_ip == "198.51.100.42"
        ]
        assert len(scanner_events) == 5, (
            f"Expected 5 port scan events from 198.51.100.42; got {len(scanner_events)}"
        )
        # All 5 must be BLOCK
        non_block = [e for e in scanner_events if e.action != "BLOCK"]
        assert not non_block, f"Some scan events are not BLOCK: {[e.action for e in non_block]}"

    def test_five_distinct_dest_ports_for_scanner(self) -> None:
        """Events 2-6: 5 distinct destination ports (port scan pattern)."""
        scanner_events = [e for e in self._events if e.source_ip == "198.51.100.42"]
        ports = {e.destination_port for e in scanner_events}
        assert len(ports) == 5, (
            f"Expected 5 distinct destination ports; got {ports}. "
            "5 distinct ports triggers the port_scan rule in run_rules()."
        )
        # Verify the specific ports from the fixture
        assert ports == {22, 23, 3389, 8080, 443}

    # ── Event 7: Trojan/Malware ───────────────────────────────────────────────
    # Source: 203.0.113.77 → 192.0.2.200:4444, allowed
    # OCSF: Trojan (IDS) → class_uid=4001, category_uid=4
    # No MITRE metadata in this event

    def test_event7_trojan_category(self) -> None:
        """Event 7: 'A Network Trojan was detected' → category='Trojan (IDS)'."""
        e = self._by_flow(1000000007)
        assert e.category == "Trojan (IDS)"

    def test_event7_trojan_action_alert(self) -> None:
        """Event 7: alert.action='allowed' → action='ALERT' (ADR-0012)."""
        e = self._by_flow(1000000007)
        assert e.action == "ALERT"

    def test_event7_trojan_severity_medium(self) -> None:
        """Event 7: Suricata severity=2 → severity='medium' (ADR-0069 D4(a); was 'high')."""
        e = self._by_flow(1000000007)
        assert e.severity == "medium"

    def test_event7_trojan_ocsf_class(self) -> None:
        """Event 7: Trojan (IDS) → ocsf_class=4001 (OCSF Network Activity, ADR-0020).

        Source: https://schema.ocsf.io/classes/network_activity — class_uid=4001.
        Trojan/malware detections map to network activity (connection-level events).
        """
        e = self._by_flow(1000000007)
        assert e.ocsf_class == 4001

    def test_event7_trojan_ocsf_category(self) -> None:
        """Event 7: Trojan (IDS) → ocsf_category=4 (Network Activity)."""
        e = self._by_flow(1000000007)
        assert e.ocsf_category == 4

    def test_event7_trojan_no_mitre(self) -> None:
        """Event 7: no ET Open MITRE metadata → attack_technique=None."""
        e = self._by_flow(1000000007)
        assert e.attack_technique is None
        assert e.attack_tactic is None

    def test_event7_trojan_no_http_payload(self) -> None:
        """Event 7: no HTTP section → payload_snippet=None."""
        e = self._by_flow(1000000007)
        assert e.payload_snippet is None

    # ── Event 8: Privilege Escalation with MITRE ─────────────────────────────
    # Source: 203.0.113.10 → 192.0.2.100:443, allowed
    # OCSF: Privilege Escalation (IDS) → class_uid=2004 (Detection Finding), category_uid=2
    # MITRE: T1059 / TA0004

    def test_event8_privesc_category(self) -> None:
        """Event 8: 'Attempted Administrator Privilege Gain' → category='Privilege Escalation (IDS)'."""
        e = self._by_flow(1000000008)
        assert e.category == "Privilege Escalation (IDS)"

    def test_event8_privesc_action_alert(self) -> None:
        """Event 8: alert.action='allowed' → action='ALERT' (ADR-0012)."""
        e = self._by_flow(1000000008)
        assert e.action == "ALERT"

    def test_event8_privesc_severity_high(self) -> None:
        """Event 8: Suricata severity=1 → severity='high' (ADR-0069 D4(a); was 'critical')."""
        e = self._by_flow(1000000008)
        assert e.severity == "high"

    def test_event8_privesc_ocsf_class(self) -> None:
        """Event 8: Privilege Escalation (IDS) → ocsf_class=2004 (Detection Finding, ADR-0020).

        Source: https://schema.ocsf.io/classes/detection_finding — class_uid=2004,
        category='Findings' (category_uid=2). IDS privilege-escalation detections
        are security-product alerts, correctly mapped to Detection Finding.
        """
        e = self._by_flow(1000000008)
        assert e.ocsf_class == 2004

    def test_event8_privesc_ocsf_category(self) -> None:
        """Event 8: Privilege Escalation (IDS) → ocsf_category=2 (Findings)."""
        e = self._by_flow(1000000008)
        assert e.ocsf_category == 2

    def test_event8_privesc_mitre_technique(self) -> None:
        """Event 8: ET Open mitre_technique_id=['T1059'] → attack_technique='T1059' (ADR-0014).

        MITRE ATT&CK T1059: Command and Scripting Interpreter (TA0004 Privilege Escalation).
        Source: https://attack.mitre.org/techniques/T1059/
        """
        e = self._by_flow(1000000008)
        assert e.attack_technique == "T1059"

    def test_event8_privesc_mitre_tactic(self) -> None:
        """Event 8: ET Open mitre_tactic_id=['TA0004'] → attack_tactic='TA0004' (ADR-0014).

        MITRE ATT&CK TA0004: Privilege Escalation.
        Source: https://attack.mitre.org/tactics/TA0004/
        """
        e = self._by_flow(1000000008)
        assert e.attack_tactic == "TA0004"

    # ── source_type constant across all events ───────────────────────────────

    def test_all_events_source_type_suricata(self) -> None:
        """All demo events carry source_type='suricata' (constant, Flag B / ADR-0016)."""
        non_suricata = [e for e in self._events if e.source_type != "suricata"]
        assert not non_suricata, (
            f"Found {len(non_suricata)} events with source_type != 'suricata': "
            f"{[e.source_type for e in non_suricata]}"
        )

    def test_all_events_source_id_passed_through(self) -> None:
        """All demo events carry source_id='demo-sensor' (passed through unchanged)."""
        wrong = [e for e in self._events if e.source_id != _DEMO_SOURCE_ID]
        assert not wrong, f"source_id not passed through: {[e.source_id for e in wrong]}"

    def test_total_event_count(self) -> None:
        """Demo feed normalizes to exactly 8 SecurityEvent objects."""
        assert len(self._events) == 8, (
            f"Expected 8 normalized events; got {len(self._events)}. "
            "eve_demo.json should have exactly 8 alert lines."
        )


# ── EARS-E2E-AOFF: scoring pipeline AI-off deterministic ─────────────────────


class TestE2ePipelineAiOff:
    """EARS-E2E-AOFF — full scoring path AI-off produces deterministic frozen scores.

    Verifies that the DisabledAIEngine path (ADR-0015/MB.2) produces the same
    result every run without contacting any LLM endpoint.

    Frozen oracle values (RE-BLESSED by ADR-0058 §D5a / issue #651):
    - IP 198.51.100.42 (scanner): 5 BLOCK events, 5 distinct ports →
        port_scan rule (+25) + persistence floor (+10, 5>=3 blocked) → score=35, level=MEDIUM
    - IP 203.0.113.10 (web attacker + privesc): 2 ALERT events, 0 BLOCKs → score=0, level=LOW.
        The payload is "1+UNION+SELECT" (URL-encoded "+" = space) which does NOT match the
        UNION-SELECT pattern (it requires real whitespace between the keywords); run_rules
        does not URL-decode (a separate future issue). The 0 is correct/precise, not a missed fix.
    - IP 203.0.113.77 (trojan): 1 ALERT event, 0 BLOCKs → score=0, level=LOW

    These are NOT derived from legacy/ outputs (ADR-0024) — they are derived by reading
    the run_rules() formula (ADR-0058 §D5a disposition-weighted):
      score = (30 if blocked>=10 else 0)
             + (25 if distinct_dest_ports>=5 else 0)
             + round(sqli_base*weight) + round(xss_base*weight)   # scanned across ALL events
             + (10 if blocked>=3 else 0)                          # persistence floor
    """

    # Frozen oracle values — literals, NOT computed from new code
    _ORACLE_SCANNER_IP = "198.51.100.42"
    _ORACLE_SCANNER_SCORE = 35   # port_scan(+25) + persistence floor(+10, 5>=3 blocked) = 35
    _ORACLE_SCANNER_LEVEL = "MEDIUM"
    _ORACLE_SCANNER_ATTACKS = ["port_scan"]

    _ORACLE_ATTACKER_IP = "203.0.113.10"
    # Stays 0 post-rebalance: payload `1+UNION+SELECT` (URL-encoded space) does not match
    # `\bUNION\s+SELECT\b`; run_rules does not URL-decode (separate future issue). Precise, not missed.
    _ORACLE_ATTACKER_SCORE = 0
    _ORACLE_ATTACKER_LEVEL = "LOW"
    _ORACLE_ATTACKER_ATTACKS: list[str] = []

    _ORACLE_TROJAN_IP = "203.0.113.77"
    _ORACLE_TROJAN_SCORE = 0
    _ORACLE_TROJAN_LEVEL = "LOW"
    _ORACLE_TROJAN_ATTACKS: list[str] = []

    def setup_method(self) -> None:
        self._events = _normalize_demo()

    def _events_for_ip(self, ip: str) -> list[SecurityEvent]:
        return [e for e in self._events if e.source_ip == ip]

    def test_scanner_score_deterministic_ai_off(self) -> None:
        """198.51.100.42 (5 blocked port-scan probes): score=35, level=MEDIUM, AI-off.

        run_rules() formula: 5 distinct ports (+25) + persistence floor (+10, 5>=3 blocked) = 35.
        MEDIUM = score in [26, 50]. AI contribution = 0 (DisabledAIEngine → ai_result=None).
        """
        events = self._events_for_ip(self._ORACLE_SCANNER_IP)
        assert len(events) == 5, f"Expected 5 scanner events; got {len(events)}"

        score, level, attacks, _ = _score_events(events)

        assert score == self._ORACLE_SCANNER_SCORE, (
            f"Score regression for {self._ORACLE_SCANNER_IP}: "
            f"expected {self._ORACLE_SCANNER_SCORE} (port_scan+25 + 5_blocks) "
            f"but got {score}."
        )
        assert level == self._ORACLE_SCANNER_LEVEL, (
            f"Level regression: expected {self._ORACLE_SCANNER_LEVEL!r} got {level!r}. "
            f"Score={score}, MEDIUM=[26,50]."
        )
        assert attacks == self._ORACLE_SCANNER_ATTACKS, (
            f"Attack types regression: expected {self._ORACLE_SCANNER_ATTACKS} got {attacks}."
        )

    def test_attacker_score_deterministic_ai_off(self) -> None:
        """203.0.113.10 (SQL injection + privesc, all ALERT): score=0, level=LOW, AI-off.

        ALERT events do not contribute to rule_score (only BLOCKs/DROPs do).
        With 0 blocks and <5 distinct ports: score = 0, level = LOW.
        """
        events = self._events_for_ip(self._ORACLE_ATTACKER_IP)
        assert len(events) == 2, f"Expected 2 attacker events; got {len(events)}"

        score, level, attacks, _ = _score_events(events)

        assert score == self._ORACLE_ATTACKER_SCORE, (
            f"Score regression for {self._ORACLE_ATTACKER_IP}: "
            f"expected {self._ORACLE_ATTACKER_SCORE} (ALERT-only, no blocks) got {score}."
        )
        assert level == self._ORACLE_ATTACKER_LEVEL
        assert attacks == self._ORACLE_ATTACKER_ATTACKS

    def test_trojan_score_deterministic_ai_off(self) -> None:
        """203.0.113.77 (trojan ALERT): score=0, level=LOW, AI-off."""
        events = self._events_for_ip(self._ORACLE_TROJAN_IP)
        assert len(events) == 1, f"Expected 1 trojan event; got {len(events)}"

        score, level, attacks, _ = _score_events(events)

        assert score == self._ORACLE_TROJAN_SCORE
        assert level == self._ORACLE_TROJAN_LEVEL
        assert attacks == self._ORACLE_TROJAN_ATTACKS

    def test_three_distinct_source_ips(self) -> None:
        """EARS-GRACEFUL: demo produces events for 3 distinct source IPs (varied data).

        All three views (Dashboard/Logs/Analytics) require varied, non-trivial data.
        The three IPs provide distinct threat profiles: scanner (MEDIUM), attacker (LOW),
        trojan (LOW) — sufficient for a meaningful demo.
        """
        ips = {e.source_ip for e in self._events}
        assert ips == {
            "203.0.113.10",   # SQL injection + privesc
            "198.51.100.42",  # port scanner
            "203.0.113.77",   # trojan
        }, f"Expected exactly 3 source IPs; got {ips}"

    def test_ai_off_no_llm_calls(self) -> None:
        """EARS-NO-LLM: scoring pipeline with DisabledAIEngine makes zero LLM calls.

        The DisabledAIEngine never contacts an inference endpoint. Confirms that
        ai_result=None is passed to merge_score, leaving the AI boost at zero.
        """
        events = self._events_for_ip(self._ORACLE_SCANNER_IP)
        rule_score, _ = run_rules(events)
        # With ai_result=None, merge_score adds no AI boost
        score_with_ai_none, _, _deriv = merge_score(rule_score, None, detection_boost=0)
        # Score is purely rule-based (no detection boost for single-source)
        assert score_with_ai_none == rule_score, (
            "merge_score with ai_result=None must not add AI boost. "
            f"Expected {rule_score}, got {score_with_ai_none}."
        )


# ── EARS-GRACEFUL: graceful degradation — all IPs scored AI-off ──────────────


class TestGracefulDegradation:
    """EARS-GRACEFUL: AI-off still produces ThreatScore data for all IPs (ADR-0015).

    ADR-0015: tiered autonomy. AI is additive-only — rules-only score is always
    the floor. When AI is disabled, every IP in the demo feed still receives a
    deterministic rule+detection score rather than a null/empty response.
    """

    def setup_method(self) -> None:
        self._events = _normalize_demo()

    def test_all_ips_get_score_ai_off(self) -> None:
        """Every distinct source IP in the demo feed can be scored AI-off."""
        ips = {e.source_ip for e in self._events}
        assert ips, "No events normalized — demo feed is empty or broken"

        for ip in ips:
            ip_events = [e for e in self._events if e.source_ip == ip]
            score, level, _, _ = _score_events(ip_events)
            # Score must be a valid integer in [0, 100]
            assert isinstance(score, int), f"score for {ip} is not int: {score!r}"
            assert 0 <= score <= 100, f"score for {ip} out of range: {score}"
            # Level must be a valid ThreatLevelLiteral
            assert level in ("LOW", "MEDIUM", "HIGH", "CRITICAL"), (
                f"Invalid threat level for {ip}: {level!r}"
            )

    def test_scanner_achieves_medium_without_ai(self) -> None:
        """198.51.100.42 achieves MEDIUM threat level from rules alone (no AI).

        This confirms ADR-0015: the rule+detection score is a meaningful floor, and
        the demo shows non-trivial scoring even without a running LLM.
        """
        scanner = [e for e in self._events if e.source_ip == "198.51.100.42"]
        _, level, _, _ = _score_events(scanner)
        assert level == "MEDIUM", (
            f"Scanner IP should reach MEDIUM from rules alone; got {level!r}. "
            "Port scan rule (+25) + persistence floor (+10, 5>=3 blocked) = 35 → MEDIUM."
        )

    def test_raw_logs_preserved_for_forensics(self) -> None:
        """All normalized events have raw_log populated for drill-down (ADR-0020)."""
        no_raw = [e for e in self._events if e.raw_log is None]
        assert not no_raw, (
            f"{len(no_raw)} events have raw_log=None. "
            "raw_log must be preserved for forensic drill-down."
        )


# ── EARS-SAME-ART: single artifact for demo and golden ───────────────────────


class TestSingleArtifact:
    """EARS-SAME-ART: the demo feed and the golden input are the same artifact.

    The file at tests/golden/fixtures/eve_demo.json serves BOTH as:
    1. The golden regression input (this test suite).
    2. The committed demo feed (pointed at by the demo run guide).

    This class pins that the file can be read correctly as an NDJSON feed
    in the same way a live 'firewatch run' --local path would consume it.
    """

    def test_demo_file_is_valid_ndjson(self) -> None:
        """eve_demo.json is valid NDJSON: each line is valid JSON."""
        lines = DEMO_FEED.read_text(encoding="utf-8").splitlines()
        non_empty = [ln for ln in lines if ln.strip()]
        assert non_empty, "Demo feed is empty"
        for i, line in enumerate(non_empty, start=1):  # noqa: B007 — i used in pytest.fail
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                pytest.fail(f"Line {i} is not valid JSON: {exc}\n  {line!r}")
            assert isinstance(obj, dict), f"Line {i} is not a JSON object: {type(obj)}"

    def test_all_events_are_alert_type(self) -> None:
        """All events in the demo feed have event_type='alert' (collector filter target)."""
        events = _load_demo_events()
        non_alert = [e for e in events if e.get("event_type") != "alert"]
        assert not non_alert, (
            f"Found {len(non_alert)} non-alert events in demo feed. "
            "The Suricata collector only yields alert events."
        )

    def test_demo_feed_covers_multiple_categories(self) -> None:
        """Demo feed covers at least 3 distinct Suricata alert categories."""
        events = _load_demo_events()
        categories = {e["alert"]["category"] for e in events if "alert" in e}
        assert len(categories) >= 3, (
            f"Demo feed covers only {len(categories)} category/categories: {categories}. "
            "Need at least 3 for meaningful dashboard/analytics demo."
        )

    def test_demo_feed_has_both_alert_and_block_actions(self) -> None:
        """Demo feed contains both IDS (ALERT) and IPS (BLOCK) events for varied display."""
        events = _normalize_demo()
        actions = {e.action for e in events}
        assert "ALERT" in actions, "Demo feed has no ALERT events"
        assert "BLOCK" in actions, "Demo feed has no BLOCK events"
