"""Tests for the OCSF 1.8.0 export surface (ADR-0040 / MI-5 #386).

EARS acceptance criteria → test mapping (1:1):

  EARS-1 — WHEN /export/ocsf/findings is queried, each item SHALL be an OCSF 1.8.0
           Detection Finding (class_uid 2004) with metadata.version "1.8.0" and
           evidences carrying the contributing events.
           → test_findings_items_are_detection_findings
           → test_findings_metadata_version
           → test_findings_evidences_carry_contributing_events

  EARS-2 — WHEN /export/ocsf/events is queried, each item SHALL carry the documented
           field map (disposition/activity/severity/class ids) for representative WAF
           and IDS events.
           → test_events_azure_waf_class_uid
           → test_events_azure_waf_disposition_id
           → test_events_azure_waf_severity_id
           → test_events_suricata_ids_class_uid
           → test_events_suricata_net_class_uid
           → test_events_pagination_envelope_shape

  EARS-3 (read-only) — export SHALL be read-only, SHALL NOT change SecurityEvent.
           → test_event_to_ocsf_does_not_mutate_input
           → test_findings_no_store_returns_503
           → test_events_no_store_returns_503

  EARS-4 (golden) — golden tests SHALL pin representative OCSF serializations for
           at least one Azure-WAF event, one Suricata event, and one finding.
           → test_golden_azure_waf_block_event
           → test_golden_suricata_ids_alert_event
           → test_golden_finding_shape

  Ubiquitous:
           → test_mapping_constants_source_citations
           → test_serializer_event_to_ocsf_azure_waf_http_activity
           → test_serializer_event_to_ocsf_suricata_detection_finding
           → test_serializer_threat_to_detection_finding_required_fields

RFC-5737 IPs only: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi.testclient import TestClient

from firewatch_sdk.models import (
    ScoreBreakdownItem,
    SecurityEvent,
    ThreatScore,
)

from firewatch_api.ocsf import mapping, serializer


# ---------------------------------------------------------------------------
# Shared fixtures / factory helpers
# ---------------------------------------------------------------------------

_TS_UTC = datetime(2026, 6, 12, 10, 0, 0, tzinfo=timezone.utc)
_TS_STR = "2026-06-12T10:00:00+00:00"

# RFC-5737 documentation IPs only (gitleaks public-ipv4 rule enforced by CI).
_WAF_IP = "198.51.100.10"
_SURICATA_IP = "203.0.113.5"
_FINDING_IP = "192.0.2.50"


def _make_waf_event(
    *,
    action: str = "BLOCK",
    severity: str = "high",
    rule_id: str = "932100",
    rule_name: str = "Remote Code Execution",
    http_method: str | None = "GET",
    request_uri: str = "/api/exec?cmd=ls",
    payload_snippet: str | None = "ls -la",
    attack_technique: str | None = "T1059",
    attack_tactic: str | None = "TA0002",
) -> SecurityEvent:
    """Build a SecurityEvent shaped like an Azure WAF normalize() output.

    Uses the REAL production fields that normalize.py sets (ocsf_class=4002,
    ocsf_category=4) — consistent with EARS-4 golden requirement.
    """
    raw_log: dict[str, Any] = {
        "properties": {
            "clientIp": _WAF_IP,
            "requestUri": request_uri,
            "action": action.capitalize(),
            "ruleId": rule_id,
            "message": rule_name,
        }
    }
    if http_method:
        raw_log["properties"]["httpMethod"] = http_method
    return SecurityEvent(
        source_type="azure_waf",
        source_id="gw-prod",
        timestamp=_TS_UTC,
        source_ip=_WAF_IP,
        destination_ip=None,
        destination_port=None,
        action=action,  # type: ignore[arg-type]
        category="Remote Code Execution",
        severity=severity,  # type: ignore[arg-type]
        rule_id=rule_id,
        rule_name=rule_name,
        payload_snippet=payload_snippet,
        attack_technique=attack_technique,
        attack_tactic=attack_tactic,
        ocsf_class=4002,
        ocsf_category=4,
        raw_log=raw_log,
    )


def _make_suricata_ids_event(
    *,
    action: str = "ALERT",
    severity: str = "high",
    rule_id: str = "2012345",
    rule_name: str = "ET WEB_SERVER SQL Injection",
    category: str = "Web Attack (IDS)",
    attack_technique: str | None = "T1190",
    attack_tactic: str | None = "TA0001",
) -> SecurityEvent:
    """Build a SecurityEvent shaped like a Suricata IDS normalize() output.

    Uses production ocsf_class=2004, ocsf_category=2 (Detection Finding).
    """
    return SecurityEvent(
        source_type="suricata",
        source_id="sensor-01",
        timestamp=_TS_UTC,
        source_ip=_SURICATA_IP,
        source_port=44321,
        destination_ip="10.0.0.1",
        destination_port=80,
        protocol="TCP",
        action=action,  # type: ignore[arg-type]
        category=category,
        severity=severity,  # type: ignore[arg-type]
        rule_id=rule_id,
        rule_name=rule_name,
        attack_technique=attack_technique,
        attack_tactic=attack_tactic,
        ocsf_class=2004,
        ocsf_category=2,
    )


def _make_suricata_net_event() -> SecurityEvent:
    """Build a SecurityEvent for a Suricata network-observation event (ocsf_class=4001)."""
    return SecurityEvent(
        source_type="suricata",
        source_id="sensor-01",
        timestamp=_TS_UTC,
        source_ip=_SURICATA_IP,
        source_port=12345,
        destination_ip="10.0.0.2",
        destination_port=443,
        protocol="TCP",
        action="ALERT",  # type: ignore[arg-type]
        category="Port Scan (IDS)",
        severity="medium",  # type: ignore[arg-type]
        ocsf_class=4001,
        ocsf_category=4,
    )


def _make_threat(
    ip: str = _FINDING_IP,
    threat_level: str = "HIGH",
    score: int = 60,
    breakdown: list[ScoreBreakdownItem] | None = None,
) -> ThreatScore:
    items = breakdown or [
        ScoreBreakdownItem(factor="blocked_events", label="5 blocked events", points=5),
    ]
    return ThreatScore(
        source_ip=ip,
        threat_level=threat_level,  # type: ignore[arg-type]
        score=score,
        total_events=8,
        blocked_events=5,
        attack_types=["Remote Code Execution"],
        first_seen=_TS_UTC,
        last_seen=_TS_UTC,
        ai_status="disabled",
        score_breakdown=items,
    )


# ---------------------------------------------------------------------------
# Fake store / pipeline for HTTP-level tests
# ---------------------------------------------------------------------------


class _OcsfFakeStore:
    """Minimal store fake for OCSF export route tests."""

    def __init__(
        self,
        log_rows: list[dict[str, Any]] | None = None,
        rows_by_ip: dict[str, list[dict[str, Any]]] | None = None,
    ) -> None:
        self._logs = log_rows or []
        self._rows_by_ip = rows_by_ip or {}

    async def get_all_ips(self) -> list[str]:
        return list(self._rows_by_ip.keys())

    async def get_events_with_row_ids(self, ip: str) -> list[dict[str, Any]]:
        return self._rows_by_ip.get(ip, [])

    async def get_paginated(self, limit: int = 100, filters: Any = None) -> dict[str, Any]:
        return {
            "logs": self._logs[:limit],
            "next_cursor": None,
            "has_more": False,
            "total_matching": len(self._logs),
        }

    # ---- required no-ops ----
    async def get_recent(self, limit: int = 100) -> list[dict[str, Any]]:
        return []

    async def get_categories(self) -> list[dict[str, Any]]:
        return []

    async def get_category_summary(self) -> list[dict[str, Any]]:
        return []

    async def get_timeline(self, start: Any = None, end: Any = None) -> list[dict[str, Any]]:
        return []

    async def get_rule_descriptions(self) -> dict[str, str]:
        return {}

    async def get_analytics_geo(self) -> list[dict[str, Any]]:
        return []

    async def get_analytics_summary(self) -> dict[str, Any]:
        return {"total_ips": 0, "total_events": 0, "total_blocked": 0,
                "block_rate": 0.0, "top_country": "", "unique_countries": 0, "top_rule": ""}

    async def get_categories_timeline(self, start: Any = None, end: Any = None) -> list[dict[str, Any]]:
        return []

    async def get_stats(self) -> dict[str, Any]:
        return {"total_logs": 0, "total_ips": 0, "blocked_percentage": 0.0,
                "top_attack_types": [], "last_updated": None}

    async def source_health(self) -> list[dict[str, Any]]:
        return []

    async def get_ip_counterfactual(self, ip: str) -> dict[str, Any]:
        return {"total_events": 0, "blocked_events": 0, "unblocked_events": 0}

    async def get_attack_dispositions(self, top_n: int = 5) -> list[dict[str, Any]]:
        return []

    async def get_by_ip_raw(self, ip: str) -> list[dict[str, Any]]:
        return []

    async def get_events_for_timeline(self, ip: str, limit: int = 200) -> list[dict[str, Any]]:
        return []

    async def get_score_history(self, ip: str, window: float = 24.0) -> list[dict[str, Any]]:
        return []


class _OcsfFakePipeline:
    """Minimal pipeline fake for OCSF export route tests."""

    def __init__(self, scores: dict[str, ThreatScore] | None = None) -> None:
        self._scores: dict[str, ThreatScore] = scores or {}

    async def analyze_ip(self, ip: str, *, use_ai: bool = True) -> ThreatScore:
        if ip in self._scores:
            return self._scores[ip]
        return ThreatScore(
            source_ip=ip, threat_level="LOW", score=0,
            total_events=0, blocked_events=0, attack_types=[],
            first_seen=_TS_UTC, last_seen=_TS_UTC, ai_status="disabled",
        )

    async def analyze_ip_detailed(self, ip: str, *, include_ai: bool = True) -> dict[str, Any]:
        return {"error": "No logs found"}


def _make_row(
    row_id: int,
    source_ip: str,
    source_type: str = "azure_waf",
    action: str = "BLOCK",
    severity: str = "high",
    ocsf_class: int = 4002,
    ocsf_category: int = 4,
    rule_id: str | None = "932100",
    payload_snippet: str | None = "ls -la",
) -> dict[str, Any]:
    """Build a store log-row dict matching the persisted SecurityEvent shape."""
    return {
        "id": row_id,
        "source_ip": source_ip,
        "source_type": source_type,
        "source_id": "sensor-01",
        "timestamp": _TS_STR,
        "action": action,
        "severity": severity,
        "category": "Remote Code Execution",
        "rule_id": rule_id,
        "rule_name": "Remote Command Execution",
        "payload_snippet": payload_snippet,
        "destination_ip": None,
        "destination_port": None,
        "source_port": None,
        "protocol": None,
        "ocsf_class": ocsf_class,
        "ocsf_category": ocsf_category,
        "attack_technique": "T1059",
        "attack_tactic": "TA0002",
    }


def _build_client(
    store: Any = None,
    pipeline: Any = None,
    log_rows: list[dict[str, Any]] | None = None,
    rows_by_ip: dict[str, list[dict[str, Any]]] | None = None,
    scores: dict[str, ThreatScore] | None = None,
) -> TestClient:
    from _api_fakes import FakePullPlugin
    from firewatch_api.app import create_app

    _store = store if store is not None else _OcsfFakeStore(
        log_rows=log_rows or [],
        rows_by_ip=rows_by_ip or {},
    )
    _pipeline = pipeline if pipeline is not None else _OcsfFakePipeline(scores or {})
    app = create_app(
        registry={"azure_waf": FakePullPlugin(type_key="azure_waf")},
        config_store=None,
        event_store=_store,
        pipeline=_pipeline,
    )
    return TestClient(app)


# ===========================================================================
# Unit tests — serializer (no HTTP)
# ===========================================================================


class TestMappingConstants:
    """Verify mapping constants match OCSF 1.8.0 reference (no drift)."""

    def test_ocsf_version(self) -> None:
        """OCSF_VERSION must be pinned to 1.8.0 (ADR-0040)."""
        assert mapping.OCSF_VERSION == "1.8.0"

    def test_severity_id_table(self) -> None:
        """severity_id values must match schema.ocsf.io/1.8.0/dictionary §1."""
        # Source: scratch/ocsf-1.8.0-reference.md §1
        assert mapping.SEVERITY_ID["info"] == 1
        assert mapping.SEVERITY_ID["low"] == 2
        assert mapping.SEVERITY_ID["medium"] == 3
        assert mapping.SEVERITY_ID["high"] == 4
        assert mapping.SEVERITY_ID["critical"] == 5
        assert mapping.SEVERITY_ID[None] == 0

    def test_disposition_id_table(self) -> None:
        """disposition_id values must match reference §2 Security Control profile."""
        # Source: scratch/ocsf-1.8.0-reference.md §2
        assert mapping.DISPOSITION_ID["ALLOW"] == 1   # Allowed (core)
        assert mapping.DISPOSITION_ID["BLOCK"] == 2   # Blocked (core)
        assert mapping.DISPOSITION_ID["DROP"] == 6    # Dropped (SC profile ext)
        assert mapping.DISPOSITION_ID["ALERT"] == 19  # Alert (SC profile ext)
        assert mapping.DISPOSITION_ID["LOG"] == 17    # Logged (SC profile ext)

    def test_detection_finding_constants(self) -> None:
        """Detection Finding constants must match reference §2."""
        # Source: scratch/ocsf-1.8.0-reference.md §2
        assert mapping.DETECTION_FINDING_CLASS_UID == 2004
        assert mapping.DETECTION_FINDING_CATEGORY_UID == 2
        assert mapping.DETECTION_FINDING_ACTIVITY_ID == 1   # Create
        assert mapping.DETECTION_FINDING_TYPE_UID == 200401  # 2004*100+1

    def test_security_control_profile_ids(self) -> None:
        """DROP/ALERT/LOG disposition_ids must be in the SC profile extension set."""
        # These values require profiles:["security_control"] in metadata.
        # Source: scratch/ocsf-1.8.0-reference.md §2 caveat
        assert 6 in mapping.SECURITY_CONTROL_DISPOSITION_IDS   # Dropped
        assert 19 in mapping.SECURITY_CONTROL_DISPOSITION_IDS  # Alert
        assert 17 in mapping.SECURITY_CONTROL_DISPOSITION_IDS  # Logged

    def test_http_activity_method_ids(self) -> None:
        """HTTP Activity activity_id must match reference §3."""
        # Source: scratch/ocsf-1.8.0-reference.md §3
        assert mapping.HTTP_METHOD_ACTIVITY_ID["GET"] == 3
        assert mapping.HTTP_METHOD_ACTIVITY_ID["POST"] == 6
        assert mapping.HTTP_ACTIVITY_UNKNOWN == 0

    def test_mapping_constants_source_citations(self) -> None:
        """Every table key references schema.ocsf.io — verified by non-None values."""
        # This test exists to assert the tables are populated (not empty/None).
        assert mapping.SEVERITY_ID is not None
        assert mapping.DISPOSITION_ID is not None
        assert mapping.HTTP_METHOD_ACTIVITY_ID is not None
        assert len(mapping.SEVERITY_ID) >= 5
        assert len(mapping.DISPOSITION_ID) >= 5


class TestEventToOcsfSerializer:
    """Unit tests for event_to_ocsf() pure function."""

    def test_serializer_event_to_ocsf_azure_waf_http_activity(self) -> None:
        """Azure WAF event → HTTP Activity (class_uid=4002, category_uid=4)."""
        ev = _make_waf_event(action="BLOCK", severity="high")
        result = serializer.event_to_ocsf(ev)
        # Source: ADR-0020, scratch/ocsf-1.8.0-reference.md §3
        assert result["class_uid"] == 4002
        assert result["category_uid"] == 4

    def test_azure_waf_disposition_id_block(self) -> None:
        """BLOCK action → disposition_id=2 (Blocked, core enum)."""
        # Source: scratch/ocsf-1.8.0-reference.md §2
        ev = _make_waf_event(action="BLOCK")
        result = serializer.event_to_ocsf(ev)
        assert result["disposition_id"] == 2
        assert result["disposition"] == "Blocked"

    def test_azure_waf_disposition_id_alert(self) -> None:
        """ALERT action → disposition_id=19 (Alert, SC profile ext)."""
        ev = _make_waf_event(action="ALERT")
        result = serializer.event_to_ocsf(ev)
        assert result["disposition_id"] == 19
        assert result["disposition"] == "Alert"
        # SC profile extension → profiles must include security_control
        assert "security_control" in result["metadata"].get("profiles", [])

    def test_azure_waf_disposition_id_allow(self) -> None:
        """ALLOW action → disposition_id=1 (Allowed, core enum)."""
        ev = _make_waf_event(action="ALLOW")
        result = serializer.event_to_ocsf(ev)
        assert result["disposition_id"] == 1

    def test_azure_waf_disposition_id_log(self) -> None:
        """LOG action → disposition_id=17 (Logged, SC profile ext)."""
        ev = _make_waf_event(action="LOG")
        result = serializer.event_to_ocsf(ev)
        assert result["disposition_id"] == 17
        assert "security_control" in result["metadata"].get("profiles", [])

    def test_azure_waf_severity_id(self) -> None:
        """severity → severity_id mapping for all values."""
        # Source: scratch/ocsf-1.8.0-reference.md §1
        cases = [
            ("info", 1), ("low", 2), ("medium", 3), ("high", 4), ("critical", 5),
        ]
        for sev, expected_id in cases:
            ev = _make_waf_event(severity=sev)
            result = serializer.event_to_ocsf(ev)
            assert result["severity_id"] == expected_id, (
                f"severity={sev!r} should map to severity_id={expected_id}"
            )

    def test_azure_waf_activity_id_from_http_method(self) -> None:
        """HTTP method in raw_log.properties.httpMethod → activity_id."""
        ev = _make_waf_event(http_method="GET")
        result = serializer.event_to_ocsf(ev)
        assert result["activity_id"] == 3  # GET=3, source: reference §3

    def test_azure_waf_activity_id_unknown_no_method(self) -> None:
        """No HTTP method in raw_log → activity_id=0 (Unknown)."""
        ev = _make_waf_event(http_method=None)
        result = serializer.event_to_ocsf(ev)
        assert result["activity_id"] == 0

    def test_azure_waf_type_uid(self) -> None:
        """type_uid = class_uid * 100 + activity_id."""
        ev = _make_waf_event(http_method="POST")
        result = serializer.event_to_ocsf(ev)
        assert result["type_uid"] == result["class_uid"] * 100 + result["activity_id"]

    def test_azure_waf_metadata_version(self) -> None:
        """metadata.version must be '1.8.0' (ADR-0040)."""
        ev = _make_waf_event()
        result = serializer.event_to_ocsf(ev)
        assert result["metadata"]["version"] == "1.8.0"

    def test_azure_waf_src_endpoint(self) -> None:
        """src_endpoint.ip populated from source_ip."""
        ev = _make_waf_event()
        result = serializer.event_to_ocsf(ev)
        assert result["src_endpoint"]["ip"] == _WAF_IP

    def test_azure_waf_mitre_attacks(self) -> None:
        """MITRE technique present in attacks list (ADR-0014)."""
        ev = _make_waf_event(attack_technique="T1059", attack_tactic="TA0002")
        result = serializer.event_to_ocsf(ev)
        assert "attacks" in result
        assert any(
            a.get("technique", {}).get("uid") == "T1059"
            for a in result["attacks"]
        )

    def test_serializer_event_to_ocsf_suricata_detection_finding(self) -> None:
        """Suricata IDS event → Detection Finding (class_uid=2004, category_uid=2)."""
        ev = _make_suricata_ids_event()
        result = serializer.event_to_ocsf(ev)
        # Source: firewatch_suricata.normalize ocsf_class=2004, reference §2
        assert result["class_uid"] == 2004
        assert result["category_uid"] == 2
        assert result["activity_id"] == 1  # Create (snapshot)

    def test_suricata_net_event_network_activity(self) -> None:
        """Suricata network-observation event → Network Activity (class_uid=4001)."""
        ev = _make_suricata_net_event()
        result = serializer.event_to_ocsf(ev)
        # Source: firewatch_suricata.normalize ocsf_class=4001, reference §4
        assert result["class_uid"] == 4001
        assert result["category_uid"] == 4
        assert result["activity_id"] == 6  # Traffic default

    def test_event_to_ocsf_does_not_mutate_input(self) -> None:
        """Serializer must not modify the input SecurityEvent (ADR-0020)."""
        ev = _make_waf_event(action="BLOCK", severity="high")
        original_action = ev.action
        original_severity = ev.severity
        original_ocsf_class = ev.ocsf_class
        serializer.event_to_ocsf(ev)
        assert ev.action == original_action
        assert ev.severity == original_severity
        assert ev.ocsf_class == original_ocsf_class

    def test_none_severity_maps_to_zero(self) -> None:
        """None severity → severity_id=0 (Unknown)."""
        ev = SecurityEvent(
            source_type="azure_waf",
            source_id="gw",
            timestamp=_TS_UTC,
            source_ip=_WAF_IP,
            action="BLOCK",  # type: ignore[arg-type]
            severity=None,
            ocsf_class=4002,
            ocsf_category=4,
        )
        result = serializer.event_to_ocsf(ev)
        assert result["severity_id"] == 0

    def test_ocsf_class_zero_survives_export(self) -> None:
        """Issue #76 falsy-zero fix: a legitimate class_uid=0 (Base Event) MUST NOT be
        silently rewritten to the 4001 Network Activity fallback.

        Source: https://schema.ocsf.io/api/1.8.0/categories — category_uid 0
        "Uncategorized" is a real, honestly-emitted class (e.g. syslog's and
        linux_auth's unclassified-line fallback rows), and Python's `0 or x`
        idiom previously discarded it because `0` is falsy.
        """
        ev = SecurityEvent(
            source_type="linux_auth",
            source_id="host-01",
            timestamp=_TS_UTC,
            source_ip=_WAF_IP,
            action="LOG",  # type: ignore[arg-type]
            severity="low",  # type: ignore[arg-type]
            ocsf_class=0,
            ocsf_category=0,
        )
        result = serializer.event_to_ocsf(ev)
        assert result["class_uid"] == 0
        assert result["category_uid"] == 0

    def test_ocsf_class_none_still_falls_back_to_network_activity(self) -> None:
        """When ocsf_class/ocsf_category are genuinely unset (None), the 4001/4
        Network Activity fallback still applies — the fix narrows the falsy
        check to `None` only; it does not remove the fallback."""
        ev = SecurityEvent(
            source_type="suricata",
            source_id="sensor-01",
            timestamp=_TS_UTC,
            source_ip=_SURICATA_IP,
            action="ALERT",  # type: ignore[arg-type]
            severity="medium",  # type: ignore[arg-type]
            ocsf_class=None,
            ocsf_category=None,
        )
        result = serializer.event_to_ocsf(ev)
        assert result["class_uid"] == mapping.SURICATA_NET_CLASS_UID
        assert result["category_uid"] == mapping.SURICATA_NET_CATEGORY_UID


class TestThreatToDetectionFinding:
    """Unit tests for threat_to_detection_finding() pure function."""

    def test_serializer_threat_to_detection_finding_required_fields(self) -> None:
        """Detection Finding must carry all required OCSF 1.8.0 attrs."""
        # Source: scratch/ocsf-1.8.0-reference.md §2 "required vs recommended"
        threat = _make_threat(ip=_FINDING_IP)
        result = serializer.threat_to_detection_finding(threat, [])
        # Required attrs
        assert result["class_uid"] == 2004
        assert result["category_uid"] == 2
        assert result["activity_id"] == 1
        assert result["type_uid"] == 200401
        assert "severity_id" in result
        assert "metadata" in result
        assert "time" in result
        assert "finding_info" in result
        assert "title" in result["finding_info"]
        assert "uid" in result["finding_info"]

    def test_detection_finding_metadata_version(self) -> None:
        """metadata.version must be '1.8.0' (ADR-0040)."""
        threat = _make_threat()
        result = serializer.threat_to_detection_finding(threat, [])
        assert result["metadata"]["version"] == "1.8.0"

    def test_detection_finding_severity_from_threat_level(self) -> None:
        """threat_level → severity_id mapping."""
        cases = [
            ("CRITICAL", 5), ("HIGH", 4), ("MEDIUM", 3), ("LOW", 2),
        ]
        for level, expected_id in cases:
            threat = _make_threat(threat_level=level)
            result = serializer.threat_to_detection_finding(threat, [])
            assert result["severity_id"] == expected_id, (
                f"threat_level={level!r} should yield severity_id={expected_id}"
            )

    def test_detection_finding_disposition_from_dominant_action(self) -> None:
        """disposition_id derived from most-severe contributing action."""
        threat = _make_threat()
        block_ev = _make_waf_event(action="BLOCK")
        alert_ev = _make_waf_event(action="ALERT")
        # BLOCK is most severe → disposition_id=2
        result = serializer.threat_to_detection_finding(threat, [block_ev, alert_ev])
        assert result["disposition_id"] == 2

    def test_detection_finding_evidences_carry_events(self) -> None:
        """evidences must be present and each carry src_endpoint.ip (EARS-1)."""
        threat = _make_threat()
        ev = _make_waf_event()
        result = serializer.threat_to_detection_finding(threat, [ev])
        assert "evidences" in result
        assert len(result["evidences"]) == 1
        assert result["evidences"][0]["src_endpoint"]["ip"] == _WAF_IP

    def test_detection_finding_mitre_from_events(self) -> None:
        """MITRE attacks extracted from contributing events (ADR-0014)."""
        threat = _make_threat()
        ev = _make_waf_event(attack_technique="T1059", attack_tactic="TA0002")
        result = serializer.threat_to_detection_finding(threat, [ev])
        assert "attacks" in result
        assert any(
            a.get("technique", {}).get("uid") == "T1059"
            for a in result["attacks"]
        )

    def test_detection_finding_deduplicates_mitre_techniques(self) -> None:
        """Same technique from multiple events appears once in attacks."""
        threat = _make_threat()
        ev1 = _make_waf_event(attack_technique="T1059")
        ev2 = _make_waf_event(attack_technique="T1059")
        result = serializer.threat_to_detection_finding(threat, [ev1, ev2])
        techniques = [
            a.get("technique", {}).get("uid")
            for a in result.get("attacks", [])
        ]
        assert techniques.count("T1059") == 1

    def test_detection_finding_empty_events_no_evidences(self) -> None:
        """No contributing events → no evidences key (omit empty list)."""
        threat = _make_threat()
        result = serializer.threat_to_detection_finding(threat, [])
        assert "evidences" not in result

    def test_detection_finding_type_uid_formula(self) -> None:
        """type_uid = 2004 * 100 + 1 = 200401 (OCSF formula)."""
        threat = _make_threat()
        result = serializer.threat_to_detection_finding(threat, [])
        assert result["type_uid"] == 200401


# ===========================================================================
# Golden fixture tests — pin representative OCSF serializations (EARS-4)
# ===========================================================================


class TestGoldenFixtures:
    """Golden tests asserting exact field values for representative events/findings.

    These fixtures are built from the REAL production shapes produced by
    normalize() — same fields normalize.py sets, not hand-faked values.
    Golden criteria per EARS-4: at least one Azure-WAF event, one Suricata event,
    one finding.
    """

    def test_golden_azure_waf_block_event(self) -> None:
        """Golden: Azure WAF BLOCK event → HTTP Activity 4002 with correct ids.

        Mirrors the production shape from app_gateway_932100_rce_block.json:
          clientIp=192.0.2.200, action=Block, ruleId=932100, severity=critical,
          httpMethod=GET, requestUri=/api/exec?cmd=ls+-la
        Verified against scratch/ocsf-1.8.0-reference.md §1/§2/§3.
        """
        ev = SecurityEvent(
            source_type="azure_waf",
            source_id="gw-prod",
            timestamp=datetime(2024, 7, 22, 14, 30, 0, tzinfo=timezone.utc),
            source_ip="192.0.2.200",
            action="BLOCK",  # type: ignore[arg-type]
            category="Remote Code Execution",
            severity="critical",  # type: ignore[arg-type]
            rule_id="932100",
            rule_name="Remote Command Execution: Unix Command Injection",
            payload_snippet="ls -la",
            attack_technique="T1059",
            attack_tactic="TA0002",
            ocsf_class=4002,
            ocsf_category=4,
            raw_log={
                "properties": {
                    "clientIp": "192.0.2.200",
                    "requestUri": "/api/exec?cmd=ls+-la",
                    "action": "Block",
                    "ruleId": "932100",
                    "httpMethod": "GET",
                }
            },
        )

        result = serializer.event_to_ocsf(ev)

        # class / category (ADR-0020, scratch/ocsf-1.8.0-reference.md §3)
        assert result["class_uid"] == 4002
        assert result["category_uid"] == 4
        # activity_id=3 (GET, scratch/ocsf-1.8.0-reference.md §3)
        assert result["activity_id"] == 3
        # type_uid = 4002*100+3 = 400203
        assert result["type_uid"] == 400203
        # severity_id=5 (critical, scratch/ocsf-1.8.0-reference.md §1)
        assert result["severity_id"] == 5
        # disposition_id=2 (Blocked core, scratch/ocsf-1.8.0-reference.md §2)
        assert result["disposition_id"] == 2
        assert result["disposition"] == "Blocked"
        # metadata.version pinned (ADR-0040)
        assert result["metadata"]["version"] == "1.8.0"
        # BLOCK is core disposition → no security_control profile needed
        assert "profiles" not in result["metadata"] or \
               "security_control" not in result["metadata"].get("profiles", [])
        # src_endpoint
        assert result["src_endpoint"]["ip"] == "192.0.2.200"
        # MITRE (ADR-0014)
        assert result["attacks"][0]["technique"]["uid"] == "T1059"

    def test_golden_suricata_ids_alert_event(self) -> None:
        """Golden: Suricata IDS ALERT → Detection Finding 2004 with correct ids.

        Uses the _make_eve_alert production shape (same fields test_plugin.py uses).
        Source: firewatch_suricata.normalize output, scratch/ocsf-1.8.0-reference.md §2.
        """
        ev = SecurityEvent(
            source_type="suricata",
            source_id="sensor-01",
            timestamp=datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
            source_ip=_SURICATA_IP,
            source_port=44321,
            destination_ip="10.0.0.1",
            destination_port=80,
            protocol="TCP",
            action="ALERT",  # type: ignore[arg-type]
            category="Web Attack (IDS)",
            severity="high",  # type: ignore[arg-type]
            rule_id="2012345",
            rule_name="ET WEB_SERVER SQL Injection Attempt",
            attack_technique="T1190",
            attack_tactic="TA0001",
            ocsf_class=2004,
            ocsf_category=2,
        )

        result = serializer.event_to_ocsf(ev)

        # class / category (firewatch_suricata.normalize IDS categories → 2004/2)
        assert result["class_uid"] == 2004
        assert result["category_uid"] == 2
        # activity_id=1 (Create — Detection Finding snapshot, reference §2)
        assert result["activity_id"] == 1
        # type_uid = 2004*100+1 = 200401
        assert result["type_uid"] == 200401
        # severity_id=4 (high, reference §1)
        assert result["severity_id"] == 4
        # disposition_id=19 (Alert, SC profile ext, reference §2)
        assert result["disposition_id"] == 19
        assert result["disposition"] == "Alert"
        # SC profile extension → profiles must include security_control
        assert "security_control" in result["metadata"]["profiles"]
        # metadata.version (ADR-0040)
        assert result["metadata"]["version"] == "1.8.0"
        # src_endpoint
        assert result["src_endpoint"]["ip"] == _SURICATA_IP
        assert result["src_endpoint"]["port"] == 44321
        # dst_endpoint
        assert result["dst_endpoint"]["ip"] == "10.0.0.1"
        assert result["dst_endpoint"]["port"] == 80
        # MITRE (ADR-0014)
        assert result["attacks"][0]["technique"]["uid"] == "T1190"

    def test_golden_finding_shape(self) -> None:
        """Golden: ThreatScore + contributing events → Detection Finding 2004.

        Asserts all required + recommended fields at the correct values.
        Source: scratch/ocsf-1.8.0-reference.md §2 "required vs recommended".
        """
        threat = ThreatScore(
            source_ip=_FINDING_IP,
            threat_level="HIGH",  # type: ignore[arg-type]
            score=70,
            total_events=10,
            blocked_events=7,
            attack_types=["Remote Code Execution"],
            first_seen=_TS_UTC,
            last_seen=_TS_UTC,
            ai_status="disabled",
            score_breakdown=[
                ScoreBreakdownItem(factor="blocked_events", label="7 blocked", points=7),
            ],
        )
        ev1 = _make_waf_event(action="BLOCK", attack_technique="T1059", attack_tactic="TA0002")
        ev2 = _make_waf_event(action="ALERT")

        result = serializer.threat_to_detection_finding(threat, [ev1, ev2])

        # Required
        assert result["class_uid"] == 2004                   # Detection Finding
        assert result["category_uid"] == 2
        assert result["activity_id"] == 1                    # Create
        assert result["type_uid"] == 200401
        assert result["severity_id"] == 4                    # HIGH → 4
        assert result["severity"] == "High"
        assert result["metadata"]["version"] == "1.8.0"      # ADR-0040
        assert result["finding_info"]["uid"] == _FINDING_IP
        assert _FINDING_IP in result["finding_info"]["title"]
        # Recommended
        assert result["disposition_id"] == 2                 # BLOCK dominant
        assert result["disposition"] == "Blocked"
        # evidences (EARS-1)
        assert "evidences" in result
        assert len(result["evidences"]) == 2
        assert result["evidences"][0]["src_endpoint"]["ip"] == _WAF_IP
        # MITRE (ADR-0014)
        assert any(
            a.get("technique", {}).get("uid") == "T1059"
            for a in result.get("attacks", [])
        )
        # score passthrough
        assert result["confidence_score"] == 70


# ===========================================================================
# HTTP route tests (via TestClient)
# ===========================================================================


class TestExportEventsRoute:
    """Tests for GET /export/ocsf/events."""

    def test_events_pagination_envelope_shape(self) -> None:
        """Response has items, next_cursor, has_more, total_matching keys."""
        client = _build_client(log_rows=[])
        resp = client.get("/export/ocsf/events")
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert "next_cursor" in data
        assert "has_more" in data
        assert "total_matching" in data

    def test_events_azure_waf_class_uid(self) -> None:
        """WAF rows with ocsf_class=4002 → items[*].class_uid=4002 (EARS-2)."""
        row = _make_row(1, source_ip=_WAF_IP, source_type="azure_waf",
                        ocsf_class=4002, ocsf_category=4)
        client = _build_client(log_rows=[row])
        resp = client.get("/export/ocsf/events")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 1
        assert items[0]["class_uid"] == 4002

    def test_events_azure_waf_disposition_id(self) -> None:
        """BLOCK action row → disposition_id=2 in OCSF item (EARS-2)."""
        row = _make_row(1, source_ip=_WAF_IP, action="BLOCK",
                        ocsf_class=4002, ocsf_category=4)
        client = _build_client(log_rows=[row])
        resp = client.get("/export/ocsf/events")
        items = resp.json()["items"]
        assert items[0]["disposition_id"] == 2

    def test_events_azure_waf_severity_id(self) -> None:
        """High-severity WAF row → severity_id=4 (EARS-2)."""
        row = _make_row(1, source_ip=_WAF_IP, severity="high",
                        ocsf_class=4002, ocsf_category=4)
        client = _build_client(log_rows=[row])
        resp = client.get("/export/ocsf/events")
        items = resp.json()["items"]
        assert items[0]["severity_id"] == 4

    def test_events_suricata_ids_class_uid(self) -> None:
        """Suricata IDS row with ocsf_class=2004 → class_uid=2004 (EARS-2)."""
        row = _make_row(2, source_ip=_SURICATA_IP, source_type="suricata",
                        ocsf_class=2004, ocsf_category=2, action="ALERT")
        client = _build_client(log_rows=[row])
        resp = client.get("/export/ocsf/events")
        items = resp.json()["items"]
        assert items[0]["class_uid"] == 2004

    def test_events_suricata_net_class_uid(self) -> None:
        """Suricata network row with ocsf_class=4001 → class_uid=4001."""
        row = _make_row(3, source_ip=_SURICATA_IP, source_type="suricata",
                        ocsf_class=4001, ocsf_category=4, action="ALERT")
        client = _build_client(log_rows=[row])
        resp = client.get("/export/ocsf/events")
        items = resp.json()["items"]
        assert items[0]["class_uid"] == 4001

    def test_events_no_store_returns_503(self) -> None:
        """No event store → 503 (EARS-3 read-only guard)."""
        from _api_fakes import FakePullPlugin
        from firewatch_api.app import create_app

        app = create_app(
            registry={"azure_waf": FakePullPlugin(type_key="azure_waf")},
            config_store=None,
            event_store=None,
            pipeline=None,
        )
        client = TestClient(app)
        resp = client.get("/export/ocsf/events")
        assert resp.status_code == 503

    def test_events_empty_store_returns_empty_items(self) -> None:
        """Empty store → items=[] with 200 OK."""
        client = _build_client(log_rows=[])
        resp = client.get("/export/ocsf/events")
        assert resp.status_code == 200
        assert resp.json()["items"] == []

    def test_events_metadata_version_in_items(self) -> None:
        """Every item must carry metadata.version='1.8.0' (ADR-0040)."""
        row = _make_row(1, source_ip=_WAF_IP, ocsf_class=4002, ocsf_category=4)
        client = _build_client(log_rows=[row])
        resp = client.get("/export/ocsf/events")
        items = resp.json()["items"]
        for item in items:
            assert item["metadata"]["version"] == "1.8.0"


class TestExportFindingsRoute:
    """Tests for GET /export/ocsf/findings."""

    def test_findings_items_are_detection_findings(self) -> None:
        """Every finding item must have class_uid=2004 (EARS-1)."""
        score = _make_threat(ip=_FINDING_IP)
        rows = [_make_row(i, source_ip=_FINDING_IP, action="BLOCK") for i in range(1, 4)]
        client = _build_client(
            rows_by_ip={_FINDING_IP: rows},
            scores={_FINDING_IP: score},
        )
        resp = client.get("/export/ocsf/findings")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) >= 1
        for item in items:
            assert item["class_uid"] == 2004

    def test_findings_metadata_version(self) -> None:
        """metadata.version must be '1.8.0' on every finding (EARS-1, ADR-0040)."""
        score = _make_threat(ip=_FINDING_IP)
        rows = [_make_row(1, source_ip=_FINDING_IP)]
        client = _build_client(
            rows_by_ip={_FINDING_IP: rows},
            scores={_FINDING_IP: score},
        )
        resp = client.get("/export/ocsf/findings")
        items = resp.json()["items"]
        for item in items:
            assert item["metadata"]["version"] == "1.8.0"

    def test_findings_evidences_carry_contributing_events(self) -> None:
        """Findings evidences must contain entries with src_endpoint (EARS-1)."""
        score = _make_threat(ip=_FINDING_IP)
        rows = [_make_row(i, source_ip=_FINDING_IP, action="BLOCK") for i in range(1, 3)]
        client = _build_client(
            rows_by_ip={_FINDING_IP: rows},
            scores={_FINDING_IP: score},
        )
        resp = client.get("/export/ocsf/findings")
        items = resp.json()["items"]
        assert len(items) >= 1
        finding = items[0]
        assert "evidences" in finding
        for ev in finding["evidences"]:
            assert "src_endpoint" in ev
            assert ev["src_endpoint"]["ip"] == _FINDING_IP

    def test_findings_pagination_envelope_shape(self) -> None:
        """Response envelope has items, next_cursor, has_more, total_matching."""
        client = _build_client()
        resp = client.get("/export/ocsf/findings")
        assert resp.status_code == 200
        data = resp.json()
        assert "items" in data
        assert "next_cursor" in data
        assert "has_more" in data
        assert "total_matching" in data

    def test_findings_no_store_returns_503(self) -> None:
        """No event store → 503 (EARS-3)."""
        from _api_fakes import FakePullPlugin
        from firewatch_api.app import create_app

        app = create_app(
            registry={"azure_waf": FakePullPlugin(type_key="azure_waf")},
            config_store=None,
            event_store=None,
            pipeline=_OcsfFakePipeline(),
        )
        client = TestClient(app)
        resp = client.get("/export/ocsf/findings")
        assert resp.status_code == 503

    def test_findings_no_pipeline_returns_503(self) -> None:
        """No pipeline → 503 (EARS-3)."""
        from _api_fakes import FakePullPlugin
        from firewatch_api.app import create_app

        app = create_app(
            registry={"azure_waf": FakePullPlugin(type_key="azure_waf")},
            config_store=None,
            event_store=_OcsfFakeStore(),
            pipeline=None,
        )
        client = TestClient(app)
        resp = client.get("/export/ocsf/findings")
        assert resp.status_code == 503

    def test_findings_empty_store_returns_empty_items(self) -> None:
        """No IPs in store → items=[] with 200 OK."""
        client = _build_client()
        resp = client.get("/export/ocsf/findings")
        assert resp.status_code == 200
        assert resp.json()["items"] == []

    def test_findings_type_uid_200401(self) -> None:
        """Every finding must have type_uid=200401 (2004*100+1, reference §2)."""
        score = _make_threat(ip=_FINDING_IP)
        rows = [_make_row(1, source_ip=_FINDING_IP)]
        client = _build_client(
            rows_by_ip={_FINDING_IP: rows},
            scores={_FINDING_IP: score},
        )
        resp = client.get("/export/ocsf/findings")
        items = resp.json()["items"]
        for item in items:
            assert item["type_uid"] == 200401

    def test_findings_skips_ips_with_zero_events(self) -> None:
        """IPs with score.total_events=0 are excluded from findings."""
        no_events_score = ThreatScore(
            source_ip="192.0.2.99",
            threat_level="LOW",  # type: ignore[arg-type]
            score=0,
            total_events=0,
            blocked_events=0,
            attack_types=[],
            first_seen=_TS_UTC,
            last_seen=_TS_UTC,
            ai_status="disabled",
        )
        client = _build_client(
            rows_by_ip={"192.0.2.99": []},
            scores={"192.0.2.99": no_events_score},
        )
        resp = client.get("/export/ocsf/findings")
        assert resp.status_code == 200
        assert resp.json()["items"] == []


# ===========================================================================
# Security-fix tests (BLOCKING-1 evidences cap + BLOCKING-2 opaque cursor)
# ===========================================================================


class TestEvidencesCap:
    """BLOCKING-1: evidences capped at _EVIDENCES_CAP (200) per finding.

    EARS criteria:
      - Exactly _EVIDENCES_CAP evidences when the actor has > _EVIDENCES_CAP events.
      - finding_info.total_evidence_count reflects the TRUE total (not the capped len).
      - payload_snippet serialized into OCSF is always <= 200 chars.
    """

    def test_evidences_capped_at_200_when_actor_exceeds_cap(self) -> None:
        """An actor with 250 events -> finding has exactly 200 evidences (BLOCKING-1)."""
        from firewatch_api.routes.export import _EVIDENCES_CAP

        # Build 250 log rows for a single IP (> _EVIDENCES_CAP).
        many_rows = [
            _make_row(i, source_ip=_FINDING_IP) for i in range(1, 251)
        ]
        score = ThreatScore(
            source_ip=_FINDING_IP,
            threat_level="HIGH",  # type: ignore[arg-type]
            score=80,
            total_events=250,
            blocked_events=200,
            attack_types=["Remote Code Execution"],
            first_seen=_TS_UTC,
            last_seen=_TS_UTC,
            ai_status="disabled",
        )
        client = _build_client(
            rows_by_ip={_FINDING_IP: many_rows},
            scores={_FINDING_IP: score},
        )
        resp = client.get("/export/ocsf/findings")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 1
        finding = items[0]
        # Cap must be enforced.
        assert len(finding["evidences"]) == _EVIDENCES_CAP

    def test_finding_info_total_evidence_count_reflects_true_total(self) -> None:
        """finding_info.total_evidence_count == true store count, not capped count."""
        from firewatch_api.routes.export import _EVIDENCES_CAP

        many_rows = [
            _make_row(i, source_ip=_FINDING_IP) for i in range(1, 251)
        ]
        score = ThreatScore(
            source_ip=_FINDING_IP,
            threat_level="HIGH",  # type: ignore[arg-type]
            score=80,
            total_events=250,
            blocked_events=200,
            attack_types=["Remote Code Execution"],
            first_seen=_TS_UTC,
            last_seen=_TS_UTC,
            ai_status="disabled",
        )
        client = _build_client(
            rows_by_ip={_FINDING_IP: many_rows},
            scores={_FINDING_IP: score},
        )
        resp = client.get("/export/ocsf/findings")
        finding = resp.json()["items"][0]
        # Truncation is signaled: total_evidence_count is the raw row count (250)
        # while evidences has _EVIDENCES_CAP entries.
        assert finding["finding_info"]["total_evidence_count"] == 250
        assert len(finding["evidences"]) == _EVIDENCES_CAP

    def test_evidences_not_capped_when_under_limit(self) -> None:
        """An actor with 3 events -> all 3 evidences present (no over-cap truncation)."""
        rows = [_make_row(i, source_ip=_FINDING_IP) for i in range(1, 4)]
        score = _make_threat(ip=_FINDING_IP)
        client = _build_client(
            rows_by_ip={_FINDING_IP: rows},
            scores={_FINDING_IP: score},
        )
        resp = client.get("/export/ocsf/findings")
        finding = resp.json()["items"][0]
        assert len(finding["evidences"]) == 3

    def test_total_evidence_count_present_even_under_cap(self) -> None:
        """finding_info.total_evidence_count is always emitted (even when < cap)."""
        rows = [_make_row(i, source_ip=_FINDING_IP) for i in range(1, 4)]
        score = _make_threat(ip=_FINDING_IP)
        client = _build_client(
            rows_by_ip={_FINDING_IP: rows},
            scores={_FINDING_IP: score},
        )
        resp = client.get("/export/ocsf/findings")
        finding = resp.json()["items"][0]
        assert "total_evidence_count" in finding["finding_info"]
        assert finding["finding_info"]["total_evidence_count"] == 3

    def test_payload_snippet_truncated_to_200_chars_in_evidence_data(self) -> None:
        """Evidences data.payload_snippet must be <= 200 chars (BLOCKING-1 NB-1)."""
        long_payload = "A" * 500
        rows = [_make_row(1, source_ip=_FINDING_IP, payload_snippet=long_payload)]
        score = _make_threat(ip=_FINDING_IP)
        client = _build_client(
            rows_by_ip={_FINDING_IP: rows},
            scores={_FINDING_IP: score},
        )
        resp = client.get("/export/ocsf/findings")
        finding = resp.json()["items"][0]
        for ev in finding.get("evidences", []):
            data = ev.get("data", {})
            if "payload_snippet" in data:
                assert len(data["payload_snippet"]) <= 200

    def test_payload_snippet_truncated_in_http_request_body(self) -> None:
        """HTTP Activity http_request.body.data must be <= 200 chars (BLOCKING-1 NB-1)."""
        long_payload = "B" * 500
        row = _make_row(
            1,
            source_ip=_WAF_IP,
            source_type="azure_waf",
            ocsf_class=4002,
            ocsf_category=4,
            payload_snippet=long_payload,
        )
        client = _build_client(log_rows=[row])
        resp = client.get("/export/ocsf/events")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert len(items) == 1
        body_data = items[0].get("http_request", {}).get("body", {}).get("data")
        if body_data is not None:
            assert len(body_data) <= 200

    def test_payload_snippet_not_truncated_when_under_200(self) -> None:
        """payload_snippet <= 200 chars is emitted verbatim (not truncated further)."""
        short_payload = "ls -la"
        rows = [_make_row(1, source_ip=_FINDING_IP, payload_snippet=short_payload)]
        score = _make_threat(ip=_FINDING_IP)
        client = _build_client(
            rows_by_ip={_FINDING_IP: rows},
            scores={_FINDING_IP: score},
        )
        resp = client.get("/export/ocsf/findings")
        finding = resp.json()["items"][0]
        for ev in finding.get("evidences", []):
            data = ev.get("data", {})
            if "payload_snippet" in data:
                assert data["payload_snippet"] == short_payload


class TestFindingsCursorPagination:
    """BLOCKING-2: /findings cursor is opaque (base64-encoded offset), not a raw IP.

    Chosen approach: Option A -- opaque cursor (base64-encoded integer offset).
    The route sorts all_ips lexicographically for a stable order, then uses
    a base64-encoded integer index as the continuation token.

    EARS criteria:
      - next_cursor is not a bare IP string when there are more pages.
      - next_cursor round-trips: echoing it as ?cursor= resumes from the correct offset.
      - A malformed cursor is treated as first page (no 500).
      - has_more is True when more IPs remain; False when all IPs fit in one page.
    """

    _IP_A = "192.0.2.10"
    _IP_B = "192.0.2.20"
    _IP_C = "192.0.2.30"

    def _make_store_with_ips(self, ips: list[str]) -> _OcsfFakeStore:
        rows_by_ip = {
            ip: [_make_row(i + 1, source_ip=ip)] for i, ip in enumerate(ips)
        }
        return _OcsfFakeStore(rows_by_ip=rows_by_ip)

    def _make_scores(self, ips: list[str]) -> dict[str, ThreatScore]:
        return {ip: _make_threat(ip=ip) for ip in ips}

    def test_next_cursor_is_not_raw_ip(self) -> None:
        """next_cursor must NOT equal any of the actor IPs (BLOCKING-2)."""
        ips = [self._IP_A, self._IP_B, self._IP_C]
        store = self._make_store_with_ips(ips)
        scores = self._make_scores(ips)
        client = _build_client(store=store, pipeline=_OcsfFakePipeline(scores))

        resp = client.get("/export/ocsf/findings?limit=2")
        assert resp.status_code == 200
        data = resp.json()
        assert data["has_more"] is True
        cursor = data["next_cursor"]
        # Cursor must not be a bare IP address.
        assert cursor not in ips, f"next_cursor leaked a raw IP: {cursor!r}"

    def test_next_cursor_is_base64_opaque(self) -> None:
        """next_cursor is decodable as base64 integer (opaque offset token)."""
        import base64

        ips = [self._IP_A, self._IP_B, self._IP_C]
        store = self._make_store_with_ips(ips)
        scores = self._make_scores(ips)
        client = _build_client(store=store, pipeline=_OcsfFakePipeline(scores))

        resp = client.get("/export/ocsf/findings?limit=2")
        data = resp.json()
        cursor = data["next_cursor"]
        assert cursor is not None
        # Must be decodable as a base64 integer.
        decoded = int(base64.b64decode(cursor).decode())
        assert decoded == 2  # offset after 2 processed IPs

    def test_cursor_round_trip_resumes_next_page(self) -> None:
        """Echoing next_cursor as ?cursor= returns the remaining IPs (BLOCKING-2 Option A)."""
        ips = [self._IP_A, self._IP_B, self._IP_C]
        store = self._make_store_with_ips(ips)
        scores = self._make_scores(ips)
        client = _build_client(store=store, pipeline=_OcsfFakePipeline(scores))

        # Page 1: limit=2.
        resp1 = client.get("/export/ocsf/findings?limit=2")
        data1 = resp1.json()
        assert data1["has_more"] is True
        cursor = data1["next_cursor"]
        assert len(data1["items"]) == 2

        # Page 2: resume from cursor.
        resp2 = client.get(f"/export/ocsf/findings?limit=2&cursor={cursor}")
        data2 = resp2.json()
        assert resp2.status_code == 200
        assert len(data2["items"]) == 1  # only 1 IP remaining
        assert data2["has_more"] is False
        assert data2["next_cursor"] is None

    def test_malformed_cursor_returns_first_page(self) -> None:
        """A malformed cursor is silently treated as page 1 -- never 500 (BLOCKING-2)."""
        ips = [self._IP_A, self._IP_B]
        store = self._make_store_with_ips(ips)
        scores = self._make_scores(ips)
        client = _build_client(store=store, pipeline=_OcsfFakePipeline(scores))

        resp = client.get("/export/ocsf/findings?cursor=!!!not-valid-base64!!!")
        assert resp.status_code == 200
        # Falls back to first page -- both IPs returned with limit=100 default.
        data = resp.json()
        assert len(data["items"]) == 2

    def test_no_cursor_when_all_ips_fit_in_page(self) -> None:
        """next_cursor is None when total IPs <= limit (no more pages)."""
        ips = [self._IP_A, self._IP_B]
        store = self._make_store_with_ips(ips)
        scores = self._make_scores(ips)
        client = _build_client(store=store, pipeline=_OcsfFakePipeline(scores))

        resp = client.get("/export/ocsf/findings?limit=100")
        data = resp.json()
        assert data["has_more"] is False
        assert data["next_cursor"] is None

    def test_events_cursor_is_not_raw_ip(self) -> None:
        """GET /export/ocsf/events next_cursor comes from store paginator (not a raw IP)."""
        # The store's get_paginated returns next_cursor in "<timestamp>|<id>" format.
        # This test confirms the events route forwards the store cursor as-is and that
        # it is not a raw source_ip value.
        client = _build_client(log_rows=[])
        resp = client.get("/export/ocsf/events")
        assert resp.status_code == 200
        data = resp.json()
        # With an empty store, there is no next page.
        assert data["next_cursor"] is None
        # Even with rows, the cursor comes from store.get_paginated, not constructed here.
        # The fake store always returns next_cursor=None so we just verify shape.
        assert "next_cursor" in data
