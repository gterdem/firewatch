"""End-to-end golden test — linux_auth SSH brute-force demo (issue #3).

Drives raw sshd auth lines through the real ``firewatch_linux_auth.normalize``
→ ``firewatch_core.detector.detect`` → ``firewatch_core.escalation.decider.decide``
chain (no DB/HTTP — the deterministic pipeline pieces, mirroring
``test_suricata_e2e_demo.py``'s own scope).

**Amended 2026-07-15 (architect ruling, post-implementation):** issue #3's
original criterion ordered a correlation that "passes the ADR-0067 Tier-2
gate" on a bare 5-event failed-login burst — that directly contradicted the
must-NOT half of the intensity model the maintainer separately adopted
(ambient volume must never queue). The fix splits the single correlation rule
into two: ``ssh_login_failure_burst`` (ambient — score/band visibility only,
never queues) and ``ssh_login_failure_intense`` (**INTERIM** — an active,
high-intensity brute force, which DOES queue). This file now proves BOTH
halves of that split, not just the flood-safe one.

EARS-criteria coverage (issue #3, as amended)
──────────────────────────────────────────────
AC4  WHEN a genuinely intense burst of failed SSH logins from one IP arrives
     (>=30 in 10 min — an active attack, not ambient scanner noise), the
     interim ``ssh_login_failure_intense`` correlation SHALL fire with
     declared severity=high/auto_escalate=True, so the actor passes the
     ADR-0067 Tier-2 gate.
     → TestIntenseBruteForceDemo.test_intense_burst_reaches_tier_2

AC4'  WHEN only an AMBIENT burst arrives (5-29 in 10 min — fail2ban's own
     default cadence, ordinary internet-exposed background), the actor
     SHALL NOT reach Tier 2 — this is the flood the milestone exists to drain.
     → TestAmbientBurstStaysOffQueue.test_ambient_burst_stays_observed

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


def _failed_login_raw(offset_seconds: float) -> RawEvent:
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


class TestIntenseBruteForceDemo:
    """A scripted, genuinely active brute force: 32 failed logins in ~62
    seconds (>=3/min sustained, well over the interim 30-in-10-min threshold)
    — Galip's motivating case (50/min) trips this even faster."""

    def test_intense_burst_reaches_tier_2(self):
        raws = [_failed_login_raw(offset_seconds=2 * i) for i in range(32)]
        events = [normalize(raw, _SOURCE_ID) for raw in raws]

        # ADR-0069 D4(e): a failed SSH login is ALERT/low — never fabricated
        # up to high/critical just to "look" more severe; escalation rides
        # the correlation rule's OWN declared severity, not the event's.
        assert all(e.action == "ALERT" for e in events)
        assert all(e.severity == "low" for e in events)
        assert all(e.category == "SSH Login Failure" for e in events)

        detections = detect(events)
        detection = next(
            (d for d in detections if d.rule_name == "ssh_login_failure_intense"), None
        )
        assert detection is not None, (
            "ssh_login_failure_intense did not fire for a 32-event burst in "
            "62 seconds — an active brute force would not surface"
        )
        assert detection.severity == "high"
        assert detection.auto_escalate is True

        verdict = decide(events, detections)
        assert verdict.tier is not None and verdict.tier <= 2, (
            f"Expected the actor to pass the ADR-0067 Tier-2 gate, got "
            f"tier={verdict.tier!r}, disposition={verdict.disposition!r}"
        )
        assert verdict.disposition != "observed"


class TestAmbientBurstStaysOffQueue:
    """8 failed SSH logins in under 2 minutes — the exact fail2ban-cadence
    scenario (maxretry=5/findtime~10m) that used to flood the queue. Must
    contribute to the record only, never reach Tier 2 — this is the fix."""

    def test_ambient_burst_stays_observed(self):
        raws = [_failed_login_raw(offset_seconds=10 * i) for i in range(8)]
        events = [normalize(raw, _SOURCE_ID) for raw in raws]

        detections = detect(events)
        burst = next(
            (d for d in detections if d.rule_name == "ssh_login_failure_burst"), None
        )
        assert burst is not None
        assert burst.severity == "medium"
        assert burst.auto_escalate is False
        assert not any(d.rule_name == "ssh_login_failure_intense" for d in detections)

        verdict = decide(events, detections)
        assert verdict.tier is None
        assert verdict.disposition == "observed"


class TestIsolatedFailures:
    """A couple of isolated failed logins — routine host activity, no burst —
    must stay on the record, not enter the triage queue (ADR-0067 D2/D3)."""

    def test_isolated_failures_stay_observed(self):
        raws = [_failed_login_raw(offset_seconds=3600 * i) for i in range(2)]  # 1h apart
        events = [normalize(raw, _SOURCE_ID) for raw in raws]

        detections = detect(events)
        assert not any(d.rule_name.startswith("ssh_login_failure") for d in detections)

        verdict = decide(events, detections)
        assert verdict.tier is None
        assert verdict.disposition == "observed"

    def test_single_failed_login_stays_observed(self):
        events = [normalize(_failed_login_raw(0), _SOURCE_ID)]
        verdict = decide(events, detect(events))
        assert verdict.tier is None
        assert verdict.disposition == "observed"
