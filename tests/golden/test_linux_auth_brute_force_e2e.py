"""End-to-end golden test — linux_auth SSH brute-force demo (issue #3).

Proves the M1 DoD demo criterion: "a scripted burst of failed SSH logins
against a fresh install surfaces the attacking IP on the dashboard with zero
network config." Drives raw sshd auth lines through the real
``firewatch_linux_auth.normalize`` → ``firewatch_core.detector.detect`` →
``firewatch_core.escalation.decider.decide`` chain (no DB/HTTP — the
deterministic pipeline pieces, mirroring ``test_suricata_e2e_demo.py``'s own
scope) and asserts the attacker passes the ADR-0067 Tier-2 gate.

EARS-criteria coverage (issue #3)
──────────────────────────────────
AC4  WHEN a burst of failed SSH logins from one IP arrives, a core-owned,
     source-agnostic correlation SHALL fire with declared severity >= high (or
     auto_escalate=True), so the actor passes the ADR-0067 Tier-2 gate.
     → TestBruteForceDemo.test_burst_reaches_tier_2

AC5  WHEN isolated/low-volume failed logins arrive (no correlation fires), the
     actor SHALL receive the observed verdict (tier=None) and NOT enter the
     triage queue.
     → TestIsolatedFailures.test_isolated_failures_stay_observed

Fixture IPs are RFC 5737 documentation ranges (203.0.113.0/24) — never
real/routable IPs (testing-conventions skill / gitleaks public-ipv4 rule).
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from firewatch_sdk import RawEvent

from firewatch_linux_auth.normalize import normalize
from firewatch_core.detector import detect
from firewatch_core.escalation.decider import decide

_ATTACKER_IP = "203.0.113.77"
_T0 = datetime(2026, 6, 15, 8, 0, 0, tzinfo=timezone.utc)
_SOURCE_ID = "solo-install"


def _failed_login_raw(offset_seconds: int) -> RawEvent:
    """Build a RawEvent shaped exactly like the linux_auth collector's output
    for one sshd "Failed password" line — real normalize() input, not a hand-
    built SecurityEvent, so this test exercises the actual mapping."""
    ts = (_T0 + timedelta(seconds=offset_seconds)).isoformat()
    return RawEvent(
        source_type="linux_auth",
        received_at=_T0,
        data={
            "message": (
                f"Failed password for root from {_ATTACKER_IP} port 51234 ssh2"
            ),
            "timestamp": ts,
            "reader": "journald",
        },
    )


class TestBruteForceDemo:
    """A scripted burst of 8 failed SSH logins in under 2 minutes — a classic
    brute-force script's cadence, well over the 5-in-10-min threshold."""

    def test_burst_reaches_tier_2(self):
        raws = [_failed_login_raw(offset_seconds=10 * i) for i in range(8)]
        events = [normalize(raw, _SOURCE_ID) for raw in raws]

        # ADR-0069 D4(e): a failed SSH login is ALERT/low (Sigma low — "notable
        # event but rarely an incident... relevant in high numbers or
        # combination with others") — never fabricated up to high/critical
        # just to "look" more severe; escalation rides the correlation rule.
        assert all(e.action == "ALERT" for e in events)
        assert all(e.severity == "low" for e in events)
        assert all(e.category == "SSH Login Failure" for e in events)

        detections = detect(events)
        detection = next(
            (d for d in detections if d.rule_name == "ssh_login_failure_burst"), None
        )
        assert detection is not None, (
            "ssh_login_failure_burst did not fire for an 8-event burst in "
            "80 seconds — the M1 DoD demo would not surface this actor"
        )
        assert detection.severity == "high" or detection.auto_escalate is True

        verdict = decide(events, detections)
        assert verdict.tier is not None and verdict.tier <= 2, (
            f"Expected the actor to pass the ADR-0067 Tier-2 gate, got "
            f"tier={verdict.tier!r}, disposition={verdict.disposition!r}"
        )
        assert verdict.disposition != "observed"


class TestIsolatedFailures:
    """A couple of isolated failed logins — routine host activity, no burst —
    must stay on the record, not enter the triage queue (ADR-0067 D2/D3)."""

    def test_isolated_failures_stay_observed(self):
        raws = [_failed_login_raw(offset_seconds=3600 * i) for i in range(2)]  # 1h apart
        events = [normalize(raw, _SOURCE_ID) for raw in raws]

        detections = detect(events)
        assert not any(d.rule_name == "ssh_login_failure_burst" for d in detections)

        verdict = decide(events, detections)
        assert verdict.tier is None
        assert verdict.disposition == "observed"

    def test_single_failed_login_stays_observed(self):
        events = [normalize(_failed_login_raw(0), _SOURCE_ID)]
        verdict = decide(events, detect(events))
        assert verdict.tier is None
        assert verdict.disposition == "observed"
