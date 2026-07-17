"""Issue #68 — Suricata + AWS Network Firewall severity recalibration (ADR-0069 D4a).

EARS criteria -> test mapping (issue #68 acceptance criteria):

- AC1: WHEN normalize() maps alert.severity, the map SHALL be
  {1: high, 2: medium, 3: low, 4: info} with missing/unparseable -> low, in BOTH
  firewatch_suricata and firewatch_aws_nfw, and a test SHALL assert the two maps
  are identical (the copy can never silently diverge again).
  -> TestSeverityMapsIdentical, TestFailQuietParity

- Must-NOT (the point of the fix): an actor whose only signal is priority-2
  ALERTs SHALL NOT reach Tier 2 — asserted by a routing test through the REAL
  qualify gate (firewatch_core.escalation.qualify.qualify / decider.decide),
  not only a mapping unit test.
  -> TestPriorityTwoNeverReachesTier2

- WHEN a genuine breach (priority-1) is planted, the breach actor SHALL still
  queue under the new map — the staged equivalent of the #50 breach-among-noise
  variant (per issue #68, until #50 lands).
  -> TestGenuineBreachStillQueues

ADR-0069 D4(a) — the recalibrated map (both Suricata and AWS NFW, same engine):
  priority 1 (trojan-activity/web-application-attack/successful-admin) -> high
  priority 2 (attempted-recon/misc-attack — ambient ET SCAN/DROP mass)  -> medium
  priority 3 (misc-activity — ET INFO)                                  -> low
  priority 4 (unused by shipped classification.config)                 -> info
  missing/unparseable                                                   -> low (fail quiet)

Fixture IPs are RFC 5737 documentation ranges only (203.0.113.0/24, 198.51.100.0/24).
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from firewatch_sdk import RawEvent
from firewatch_core.escalation.decider import decide
from firewatch_core.escalation.qualify import qualify

import firewatch_aws_nfw.normalize as nfw_normalize
import firewatch_suricata.normalize as suricata_normalize
from firewatch_aws_nfw.normalize import normalize as nfw_normalize_fn
from firewatch_suricata.normalize import normalize as suricata_normalize_fn

_RECEIVED_AT = datetime(2026, 7, 16, 8, 0, 0, tzinfo=timezone.utc)
_SURICATA_IP = "203.0.113.40"
_NFW_IP = "198.51.100.40"


# ---------------------------------------------------------------------------
# AC1 — the two maps can never silently diverge again
# ---------------------------------------------------------------------------


class TestSeverityMapsIdentical:
    """AC1: firewatch_suricata and firewatch_aws_nfw carry the identical map.

    AWS NFW's stateful engine IS Suricata (same shipped classification.config,
    same Sigma justification) — the maps must be byte-identical, not merely
    equivalent.
    """

    def test_severity_maps_are_identical(self) -> None:
        assert suricata_normalize._SEVERITY_MAP == nfw_normalize._SEVERITY_MAP, (
            "firewatch_suricata._SEVERITY_MAP and firewatch_aws_nfw._SEVERITY_MAP "
            "have diverged — AWS NFW's stateful engine IS Suricata; the copy must "
            "stay identical (ADR-0069 D4a)."
        )

    def test_severity_map_matches_adr_0069_d4a_table(self) -> None:
        expected = {1: "high", 2: "medium", 3: "low", 4: "info"}
        assert suricata_normalize._SEVERITY_MAP == expected
        assert nfw_normalize._SEVERITY_MAP == expected


class TestFailQuietParity:
    """AC1: missing/unparseable severity fails quiet to 'low' in BOTH sources."""

    def test_suricata_missing_unparseable_is_low(self) -> None:
        for bad in (None, "critical", "unknown", 0, 5, 99):
            assert suricata_normalize._map_severity(bad) == "low", (
                f"firewatch_suricata: severity={bad!r} should fail quiet to 'low'"
            )

    def test_aws_nfw_missing_unparseable_is_low(self) -> None:
        for bad in (None, "critical", "unknown", 0, 5, 99):
            assert nfw_normalize._map_severity(bad) == "low", (
                f"firewatch_aws_nfw: severity={bad!r} should fail quiet to 'low'"
            )


# ---------------------------------------------------------------------------
# Helpers — build raw EVE alerts routed through the REAL normalize() +
# REAL qualify()/decide(), not synthetic SecurityEvent literals.
# ---------------------------------------------------------------------------


def _eve_alert(
    *,
    severity: int,
    src_ip: str,
    category: str = "Attempted Information Leak",
    action: str = "allowed",
    flow_id: int = 5550001,
) -> dict[str, Any]:
    """A minimal Suricata EVE alert record."""
    return {
        "timestamp": "2026-07-16T08:00:00.000000+0000",
        "event_type": "alert",
        "src_ip": src_ip,
        "src_port": 40000,
        "dest_ip": "192.0.2.50",
        "dest_port": 80,
        "proto": "TCP",
        "flow_id": flow_id,
        "alert": {
            "action": action,
            "category": category,
            "signature": f"ET SCAN test signature (sev={severity})",
            "signature_id": 2000000 + severity,
            "severity": severity,
        },
    }


def _nfw_envelope(**kwargs: Any) -> dict[str, Any]:
    """Wrap an EVE alert in the AWS CloudWatch Logs envelope."""
    return {
        "firewall_name": "test-firewall",
        "availability_zone": "us-east-1a",
        "event_timestamp": kwargs.get("ts", "2026-07-16T08:00:00.000000+0000"),
        "event": _eve_alert(**{k: v for k, v in kwargs.items() if k != "ts"}),
    }


def _suricata_event(*, severity: int, src_ip: str = _SURICATA_IP):
    raw = RawEvent(
        source_type="suricata", received_at=_RECEIVED_AT,
        data=_eve_alert(severity=severity, src_ip=src_ip),
    )
    return suricata_normalize_fn(raw, source_id="pi-home")


def _nfw_event(*, severity: int, src_ip: str = _NFW_IP):
    raw = RawEvent(
        source_type="aws_network_firewall", received_at=_RECEIVED_AT,
        data=_nfw_envelope(severity=severity, src_ip=src_ip),
    )
    return nfw_normalize_fn(raw, source_id="test-nfw")


# ---------------------------------------------------------------------------
# Must-NOT: priority-2 ambient noise never reaches Tier 2, through the REAL gate
# ---------------------------------------------------------------------------


class TestPriorityTwoNeverReachesTier2:
    """Must-NOT (the point of the fix): an actor whose only signal is
    priority-2 ALERTs SHALL NOT reach Tier 2.

    Routed through the real ``qualify()``/``decide()`` — NOT a mapping-only
    unit test — on events produced by the REAL ``normalize()``.
    """

    def test_suricata_priority_2_actor_does_not_qualify(self) -> None:
        events = [_suricata_event(severity=2) for _ in range(20)]
        result = qualify(events, [])
        assert result.qualified is False, (
            "A priority-2-only Suricata actor qualified for Tier 2 — this is "
            "exactly the flood ADR-0069 D4(a) closes."
        )

    def test_suricata_priority_2_actor_is_observed_not_tier_2(self) -> None:
        events = [_suricata_event(severity=2) for _ in range(20)]
        verdict = decide(events, [])
        assert verdict.tier is None, f"Expected observed (tier=None); got tier={verdict.tier}"
        assert verdict.disposition == "observed"

    def test_aws_nfw_priority_2_actor_does_not_qualify(self) -> None:
        events = [_nfw_event(severity=2) for _ in range(20)]
        result = qualify(events, [])
        assert result.qualified is False, (
            "A priority-2-only AWS NFW actor qualified for Tier 2 — same "
            "defect, second file (ADR-0069 D4a)."
        )

    def test_aws_nfw_priority_2_actor_is_observed_not_tier_2(self) -> None:
        events = [_nfw_event(severity=2) for _ in range(20)]
        verdict = decide(events, [])
        assert verdict.tier is None
        assert verdict.disposition == "observed"

    def test_priority_3_and_4_ambient_noise_also_does_not_qualify(self) -> None:
        """Sanity: priority 3 (low) and 4 (info) are, a fortiori, non-qualifying."""
        for sev in (3, 4):
            events = [_suricata_event(severity=sev) for _ in range(20)]
            result = qualify(events, [])
            assert result.qualified is False, f"severity={sev} unexpectedly qualified"


# ---------------------------------------------------------------------------
# A genuine breach still queues under the new map (staged #50-equivalent)
# ---------------------------------------------------------------------------


class TestGenuineBreachStillQueues:
    """WHEN a genuine breach (priority-1) is planted among ambient noise, the
    breach actor SHALL still queue under the new map (issue #68 AC; the staged
    equivalent of the #50 breach-among-noise variant)."""

    def test_suricata_priority_1_alone_still_qualifies(self) -> None:
        result = qualify([_suricata_event(severity=1)], [])
        assert result.qualified is True, (
            "A single priority-1 Suricata ALERT must still qualify for Tier 2 "
            "under the recalibrated map (high still qualifies, ADR-0067 D1(b))."
        )

    def test_suricata_priority_1_alone_reaches_tier_2(self) -> None:
        verdict = decide([_suricata_event(severity=1)], [])
        assert verdict.tier == 2, f"Expected Tier 2 for a lone priority-1 ALERT; got {verdict.tier}"

    def test_aws_nfw_priority_1_alone_still_qualifies(self) -> None:
        result = qualify([_nfw_event(severity=1)], [])
        assert result.qualified is True

    def test_breach_among_ambient_noise_still_queues(self) -> None:
        """A genuine breach actor (1 priority-1 ALERT) planted among a large
        volume of priority-2 ambient noise from the SAME actor still queues —
        the recalibration must not suppress the real signal."""
        noise = [_suricata_event(severity=2) for _ in range(50)]
        breach = [_suricata_event(severity=1)]
        verdict = decide(noise + breach, [])
        assert verdict.tier == 2, (
            f"Expected the lone priority-1 breach signal to still queue Tier 2 "
            f"amid 50 priority-2 ambient events; got tier={verdict.tier}"
        )

    def test_ambient_noise_alone_without_breach_stays_observed(self) -> None:
        """Control: the same volume of priority-2 noise WITHOUT the breach event
        stays observed — proving the queue entry above came from the breach
        signal, not from volume."""
        noise = [_suricata_event(severity=2) for _ in range(50)]
        verdict = decide(noise, [])
        assert verdict.tier is None
        assert verdict.disposition == "observed"
