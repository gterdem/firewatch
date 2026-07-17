"""Tests for GET /banner/summary and firewatch_api.banner_assembler
(issue #55 Part 1/backend — the attempts headline + pressure-strip banner
feed, ADR-0070 D1/D3/D5, tier-attribution correction 2026-07-16).

EARS -> test mapping
────────────────────
AC-1  The banner feed SHALL include attempt_count and actor_count over the
      state window, computed from firewatch_core.attempts (the D1 predicate).
      -> TestAttemptAndActorCount

AC-2  succeeded_count SHALL be the union of Tier-1 verdicts and actors
      carrying a critical-severity qualifying detection — NEVER Tier-1 alone.
      -> TestSucceededSetUnion (covers both arms + the negative case)

AC-3  Must-NOT (the false-calm regression pin): a host-auth actor
      (syslog/linux_auth — never emits ALLOW) whose window fires
      `brute_force_then_login` (critical) SHALL be counted succeeded — NOT
      "0 succeeded".
      -> TestSucceededSetUnion::test_host_auth_brute_force_then_login_counts_as_succeeded

AC-4  queue_size (K) SHALL count only actors with a Tier-1/Tier-2 verdict.
      -> TestQueueSize

AC-5  top_pressure SHALL be bounded to <= 5 rows, each (source_ip,
      attempt_count, span_minutes) — engine integers only, ranked by peak
      pressure.
      -> TestTopPressure

AC-6  Counts SHALL come from firewatch_core.attempts — the banner's
      attempt_count for an actor SHALL equal a direct is_attempt() tally over
      the same events.
      -> TestAttemptAndActorCount::test_attempt_count_matches_is_attempt_predicate

AC-7  WHEN no attempts/actors exist (empty store), the summary SHALL be all
      zeros / empty list (200 OK) — the calm banner state renders unchanged.
      -> TestRouteBehavior::test_empty_store_returns_all_zero_summary

AC-8  GET /banner/summary SHALL return 503 when the event store is
      unavailable.
      -> TestRouteBehavior::test_no_store_returns_503

Security: RFC 5737 TEST-NET IPs only (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) — testing-conventions skill.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from fastapi.testclient import TestClient

from firewatch_sdk.models import ActionLiteral, SecurityEvent, SeverityLiteral

from firewatch_core.detector import detect
from firewatch_core.escalation.decider import decide

from firewatch_api.app import create_app
from firewatch_api.banner_assembler import (
    ActorAttemptStats,
    assemble_banner_attempt_summary,
    compute_actor_attempt_stats,
)

_IP_A = "192.0.2.10"
_IP_B = "198.51.100.10"
_IP_C = "203.0.113.10"
_IP_D = "192.0.2.20"
_NOW = datetime(2026, 7, 16, 12, 0, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _event(
    ip: str,
    *,
    source_type: str = "syslog",
    action: ActionLiteral = "ALERT",
    category: str | None = None,
    severity: SeverityLiteral | None = None,
    ts: datetime = _NOW,
) -> SecurityEvent:
    return SecurityEvent(
        source_type=source_type,
        source_id="default",
        timestamp=ts,
        source_ip=ip,
        action=action,
        category=category,
        severity=severity,
    )


def _host_auth_brute_force_then_login(ip: str, base: datetime) -> list[SecurityEvent]:
    """Real host-auth event shapes (ALERT failures + LOG success) — the exact
    case the Tier-1-only "succeeded" derivation gets wrong (ADR-0070 D3).

    Never emits ALLOW anywhere — syslog/linux_auth authenticate hosts, they do
    not pass traffic (ADR-0070 D3 tier-attribution correction).
    """
    failures = [
        _event(
            ip,
            source_type="linux_auth",
            action="ALERT",
            category="SSH Login Failure",
            severity="medium",
            ts=base + timedelta(minutes=i),
        )
        for i in range(3)
    ]
    success = _event(
        ip,
        source_type="linux_auth",
        action="LOG",
        category="SSH Login Success",
        ts=base + timedelta(minutes=20),
    )
    return [*failures, success]


def _decide_for(events: list[SecurityEvent], *, now: datetime = _NOW):
    """Run the real detect()/decide() pipeline seam on *events* (no windowing
    — callers pass already-windowed lists, matching pipeline.analyze_ip)."""
    detections = detect(events, now=now)
    verdict = decide(events, detections)
    return detections, verdict


# ---------------------------------------------------------------------------
# AC-2/AC-3 — the success-set union (THE correctness crux)
# ---------------------------------------------------------------------------


class TestSucceededSetUnion:
    def test_host_auth_brute_force_then_login_counts_as_succeeded(self) -> None:
        """Must-NOT regression pin: a pure host-auth actor firing the
        critical `brute_force_then_login` rule is Tier 2 (never Tier 1 — no
        ALLOW exists anywhere in its partition), so this MUST be caught by
        the critical-severity arm, not the tier==1 arm."""
        events = _host_auth_brute_force_then_login(_IP_A, _NOW - timedelta(minutes=25))
        detections, verdict = _decide_for(events)

        assert verdict.tier == 2, "sanity: Tier 1 is structurally unreachable here"
        assert any(d.rule_name == "brute_force_then_login" for d in detections)

        stats = compute_actor_attempt_stats(
            _IP_A,
            state_events=events,
            campaign_events=events,
            detections=detections,
            verdict=verdict,
            now=_NOW,
        )
        assert stats.succeeded is True, "0 succeeded during an active compromise — the false calm"

        summary = assemble_banner_attempt_summary([stats])
        assert summary.succeeded_count == 1

    def test_traffic_source_tier1_actor_succeeds_via_first_arm(self) -> None:
        """A traffic-source actor (ALLOW + a non-critical detection) reaches
        Tier 1 via the untouched ADR-0067 D1(a) gate — first arm, independent
        of severity."""
        events = [
            _event(_IP_B, source_type="azure_waf", action="ALLOW", category="waf-a",
                   ts=_NOW - timedelta(minutes=10)),
            _event(_IP_B, source_type="suricata", action="ALLOW", category="ids-a",
                   ts=_NOW - timedelta(minutes=5)),
        ]
        detections, verdict = _decide_for(events)
        assert verdict.tier == 1
        assert all(d.severity != "critical" for d in detections), (
            "sanity: multi_source_attack is medium severity, not critical"
        )

        stats = compute_actor_attempt_stats(
            _IP_B, state_events=events, campaign_events=events,
            detections=detections, verdict=verdict, now=_NOW,
        )
        assert stats.succeeded is True

    def test_mixed_telemetry_actor_reaches_tier1_via_unrelated_allow(self) -> None:
        """A mixed-telemetry actor (host-auth brute force + an UNRELATED CEF
        firewall ALLOW, same IP) reaches Tier 1 through the per-actor gate —
        ADR-0070 D3's worked partition example."""
        host_auth = _host_auth_brute_force_then_login(_IP_C, _NOW - timedelta(minutes=25))
        unrelated_allow = _event(
            _IP_C, source_type="syslog_cef", action="ALLOW", category="firewall-permit",
            ts=_NOW - timedelta(minutes=1),
        )
        events = [*host_auth, unrelated_allow]
        detections, verdict = _decide_for(events)
        assert verdict.tier == 1, "the per-actor gate: unrelated ALLOW + any detection -> Tier 1"

        stats = compute_actor_attempt_stats(
            _IP_C, state_events=events, campaign_events=events,
            detections=detections, verdict=verdict, now=_NOW,
        )
        assert stats.succeeded is True

    def test_ordinary_failed_login_only_actor_not_succeeded(self) -> None:
        """An ordinary actor with only unqualified low/medium ALERT failures
        (no success, no critical detection, no ALLOW) SHALL NOT count as
        succeeded — "0 succeeded" derives from the absence of ANY success
        verdict."""
        events = [
            _event(_IP_D, source_type="linux_auth", action="ALERT",
                   category="SSH Login Failure", severity="medium",
                   ts=_NOW - timedelta(minutes=i))
            for i in range(2)
        ]
        detections, verdict = _decide_for(events)
        assert verdict.tier is None, "sanity: observed stratum — no qualifying signal"

        stats = compute_actor_attempt_stats(
            _IP_D, state_events=events, campaign_events=events,
            detections=detections, verdict=verdict, now=_NOW,
        )
        assert stats.succeeded is False

        summary = assemble_banner_attempt_summary([stats])
        assert summary.succeeded_count == 0

    def test_qualified_high_severity_tier2_actor_not_succeeded(self) -> None:
        """A qualified Tier-2 actor whose top detection is `high` (not
        `critical`) SHALL NOT count as succeeded — distinguishes the
        critical-severity arm from "any qualifying Tier-2 signal"."""
        suricata = [
            _event(_IP_A, source_type="suricata", action="ALERT", category="ids",
                   severity="high", ts=_NOW - timedelta(minutes=9))
        ]
        ssh_bf = [
            _event(_IP_A, source_type="syslog", action="ALERT", category="SSH Brute Force",
                   severity="medium", ts=_NOW - timedelta(minutes=9 - i))
            for i in range(3)
        ]
        events = [*suricata, *ssh_bf]
        detections, verdict = _decide_for(events)
        assert any(d.rule_name == "ids_then_brute_force" for d in detections)
        assert verdict.tier == 2
        assert not any(d.severity == "critical" for d in detections)

        stats = compute_actor_attempt_stats(
            _IP_A, state_events=events, campaign_events=events,
            detections=detections, verdict=verdict, now=_NOW,
        )
        assert stats.succeeded is False


# ---------------------------------------------------------------------------
# AC-4 — queue_size (K)
# ---------------------------------------------------------------------------


class TestQueueSize:
    def test_tier_1_and_2_count_toward_queue(self) -> None:
        stats = [
            ActorAttemptStats(_IP_A, 1, 0, 0.0, succeeded=True, queued=True),
            ActorAttemptStats(_IP_B, 1, 0, 0.0, succeeded=False, queued=True),
        ]
        summary = assemble_banner_attempt_summary(stats)
        assert summary.queue_size == 2

    def test_observed_and_blocked_tiers_excluded_from_queue(self) -> None:
        """tier=None (observed) actors never count toward queue_size —
        matches the compute-level derivation directly."""
        events = [
            _event(_IP_D, source_type="linux_auth", action="ALERT",
                   category="SSH Login Failure", severity="low", ts=_NOW)
        ]
        detections, verdict = _decide_for(events)
        assert verdict.tier is None

        stats = compute_actor_attempt_stats(
            _IP_D, state_events=events, campaign_events=events,
            detections=detections, verdict=verdict, now=_NOW,
        )
        assert stats.queued is False

        summary = assemble_banner_attempt_summary([stats])
        assert summary.queue_size == 0

    def test_tier_3_persistent_block_excluded_from_queue(self) -> None:
        """Tier 3 (blocked_persistent) is a terminal disposition, not a
        pending queue entry — queue_size counts Tier 1/2 only."""
        events = [
            _event(_IP_A, source_type="azure_waf", action="BLOCK", category="sqli",
                   severity="high", ts=_NOW - timedelta(minutes=i))
            for i in range(5)
        ]
        detections, verdict = _decide_for(events)
        assert verdict.tier == 3

        stats = compute_actor_attempt_stats(
            _IP_A, state_events=events, campaign_events=events,
            detections=detections, verdict=verdict, now=_NOW,
        )
        assert stats.queued is False


# ---------------------------------------------------------------------------
# AC-1 / AC-6 — attempt_count / actor_count over the state window
# ---------------------------------------------------------------------------


class TestAttemptAndActorCount:
    def test_attempt_count_matches_is_attempt_predicate(self) -> None:
        """The banner's per-actor attempt_count SHALL equal a direct
        is_attempt() tally over the same events — the banner may never count
        differently than the engine (issue #55 hard constraint)."""
        from firewatch_core.attempts import is_attempt

        events = [
            _event(_IP_A, action="ALERT", severity="medium", ts=_NOW - timedelta(minutes=1)),
            _event(_IP_A, action="ALLOW", ts=_NOW - timedelta(minutes=2)),  # never counts
            _event(_IP_A, action="LOG", ts=_NOW - timedelta(minutes=3)),  # never counts
            _event(_IP_A, action="ALERT", severity="info", ts=_NOW - timedelta(minutes=4)),  # excluded
            _event(_IP_A, action="BLOCK", ts=_NOW - timedelta(minutes=5)),
        ]
        expected = sum(1 for e in events if is_attempt(e))
        assert expected == 2  # sanity on the fixture itself

        detections, verdict = _decide_for(events)
        stats = compute_actor_attempt_stats(
            _IP_A, state_events=events, campaign_events=events,
            detections=detections, verdict=verdict, now=_NOW,
        )
        assert stats.attempt_count == expected

    def test_actor_count_excludes_actors_with_zero_attempts_in_window(self) -> None:
        """An actor whose only events are ALLOW (no D1 attempt) contributes 0
        to attempt_count/actor_count even though it may still be
        succeeded/queued independently."""
        allow_only = ActorAttemptStats(_IP_B, 0, 0, 0.0, succeeded=True, queued=True)
        attempting = ActorAttemptStats(_IP_A, 3, 10, 2.0, succeeded=False, queued=False)

        summary = assemble_banner_attempt_summary([allow_only, attempting])
        assert summary.attempt_count == 3
        assert summary.actor_count == 1
        # succeeded_count/queue_size are independent aggregates (unaffected by
        # attempt_count == 0):
        assert summary.succeeded_count == 1
        assert summary.queue_size == 1

    def test_attempts_outside_state_window_are_excluded(self) -> None:
        """compute_actor_attempt_stats only sees what its caller passes as
        state_events — events older than W_STATE (the pipeline.analyze_ip
        seam, ADR-0070 D4) must already be sliced out by the caller. This
        pins that the assembler itself performs NO additional slicing (it
        counts exactly what it is handed)."""
        old_event = _event(_IP_A, action="BLOCK", ts=_NOW - timedelta(hours=48))
        recent_event = _event(_IP_A, action="BLOCK", ts=_NOW - timedelta(minutes=5))

        # Caller already excluded the 48h-old event from state_events (mirrors
        # pipeline._window_slice / routes/banner._window_slice at W_STATE=24h):
        state_events = [recent_event]
        detections, verdict = _decide_for(state_events)
        stats = compute_actor_attempt_stats(
            _IP_A, state_events=state_events, campaign_events=[old_event, recent_event],
            detections=detections, verdict=verdict, now=_NOW,
        )
        assert stats.attempt_count == 1


# ---------------------------------------------------------------------------
# AC-5 — top_pressure: bounded, engine integers, ranked
# ---------------------------------------------------------------------------


class TestTopPressure:
    def test_bounded_to_five_rows(self) -> None:
        stats = [
            ActorAttemptStats(f"192.0.2.{i}", 10, 5, float(i), succeeded=False, queued=False)
            for i in range(1, 8)  # 7 pressuring actors
        ]
        summary = assemble_banner_attempt_summary(stats)
        assert len(summary.top_pressure) == 5

    def test_ranked_by_peak_intensity_descending(self) -> None:
        low = ActorAttemptStats(_IP_A, 3, 5, 1.0, succeeded=False, queued=False)
        high = ActorAttemptStats(_IP_B, 3, 5, 9.0, succeeded=False, queued=False)
        summary = assemble_banner_attempt_summary([low, high])
        assert [row.source_ip for row in summary.top_pressure] == [_IP_B, _IP_A]

    def test_rows_carry_engine_integers_only(self) -> None:
        """attempt_count and span_minutes are the ONLY fields exposed per row
        — no raw peak_intensity float leaves this module (ADR-0035)."""
        stats = [ActorAttemptStats(_IP_A, 12, 45, 7.25, succeeded=False, queued=False)]
        summary = assemble_banner_attempt_summary(stats)
        row = summary.top_pressure[0]
        assert row.source_ip == _IP_A
        assert row.attempt_count == 12
        assert row.span_minutes == 45
        assert not hasattr(row, "peak_intensity")

    def test_zero_attempt_actors_excluded_from_ranking(self) -> None:
        zero = ActorAttemptStats(_IP_A, 0, 0, 0.0, succeeded=True, queued=True)
        summary = assemble_banner_attempt_summary([zero])
        assert summary.top_pressure == ()

    def test_span_minutes_derivation(self) -> None:
        events = [
            _event(_IP_A, action="BLOCK", ts=_NOW - timedelta(minutes=90)),
            _event(_IP_A, action="BLOCK", ts=_NOW - timedelta(minutes=30)),
        ]
        detections, verdict = _decide_for(events)
        stats = compute_actor_attempt_stats(
            _IP_A, state_events=events, campaign_events=events,
            detections=detections, verdict=verdict, now=_NOW,
        )
        assert stats.span_minutes == 60

    def test_span_minutes_zero_for_single_attempt(self) -> None:
        events = [_event(_IP_A, action="BLOCK", ts=_NOW)]
        detections, verdict = _decide_for(events)
        stats = compute_actor_attempt_stats(
            _IP_A, state_events=events, campaign_events=events,
            detections=detections, verdict=verdict, now=_NOW,
        )
        assert stats.span_minutes == 0


# ---------------------------------------------------------------------------
# AC-7 / AC-8 — route behavior
# ---------------------------------------------------------------------------


class _FakeStore:
    """Minimal in-memory EventStore fake — get_all_ips + get_by_ip only
    (the lifetime-fetch pattern pipeline.analyze_ip and this route share)."""

    def __init__(self, events: list[SecurityEvent] | None = None) -> None:
        self._events = events or []

    async def get_all_ips(self) -> list[str]:
        return sorted({e.source_ip for e in self._events})

    async def get_by_ip(self, ip: str) -> list[SecurityEvent]:
        return [e for e in self._events if e.source_ip == ip]


def _make_client(events: list[SecurityEvent] | None = None) -> TestClient:
    app = create_app(registry={}, event_store=_FakeStore(events))
    return TestClient(app)


class TestRouteBehavior:
    def test_empty_store_returns_all_zero_summary(self) -> None:
        client = _make_client([])
        resp = client.get("/banner/summary")
        assert resp.status_code == 200
        body: dict[str, Any] = resp.json()
        assert body["attempt_count"] == 0
        assert body["actor_count"] == 0
        assert body["succeeded_count"] == 0
        assert body["queue_size"] == 0
        assert body["top_pressure"] == []

    def test_no_store_returns_503(self) -> None:
        app = create_app(registry={}, event_store=None)
        client = TestClient(app)
        resp = client.get("/banner/summary")
        assert resp.status_code == 503

    def test_route_reproduces_host_auth_must_not_regression(self) -> None:
        """End-to-end: the must-not pin at the HTTP boundary — a host-auth
        actor firing brute_force_then_login within the trailing 24h SHALL
        contribute to succeeded_count, not read as "0 succeeded"."""
        now = datetime.now(timezone.utc)
        events = _host_auth_brute_force_then_login(_IP_A, now - timedelta(hours=1))
        client = _make_client(events)

        resp = client.get("/banner/summary")
        assert resp.status_code == 200
        body = resp.json()
        assert body["succeeded_count"] == 1
        assert body["queue_size"] == 1

    def test_route_response_shape(self) -> None:
        now = datetime.now(timezone.utc)
        events = [
            _event(_IP_A, action="BLOCK", ts=now - timedelta(minutes=5)),
            _event(_IP_A, action="BLOCK", ts=now - timedelta(minutes=10)),
        ]
        client = _make_client(events)
        resp = client.get("/banner/summary")
        assert resp.status_code == 200
        body = resp.json()
        for key in (
            "attempt_count", "actor_count", "succeeded_count", "queue_size",
            "top_pressure", "generated_at",
        ):
            assert key in body
        assert body["attempt_count"] == 2
        assert body["actor_count"] == 1
        row = body["top_pressure"][0]
        assert row["source_ip"] == _IP_A
        assert row["attempt_count"] == 2
        assert row["span_minutes"] == 5
