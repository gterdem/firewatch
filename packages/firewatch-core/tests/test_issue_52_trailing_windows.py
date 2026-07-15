"""Tests for issue #52 — trailing analysis windows (ADR-0070 D4).

Gives the analysis pipeline a time denominator: rule scoring and the escalation
verdict compute over a trailing state window (``W_STATE``, 24h), and correlation
detection over a trailing campaign horizon (``W_CAMPAIGN``, 7d) — instead of every
event the actor has ever produced.

EARS → test mapping
────────────────────
AC1  WHEN analyze_ip (and analyze_ip_detailed) computes run_rules,
     build_score_breakdown, and decide(), the system SHALL supply only events with
     timestamp >= now - W_STATE.
     → test_recent_blocks_still_fire_brute_force_and_tier3 (control)
     → test_stale_blocks_no_longer_fire_brute_force_or_tier3 (the defect fix)
     → test_analyze_ip_detailed_windowed_to_state (analyze_ip_detailed variant)

AC2  WHEN detect() is invoked, the system SHALL supply only events with
     timestamp >= now - W_CAMPAIGN.
     → test_detect_sees_campaign_window_not_state_window
     → test_detect_excludes_events_older_than_campaign_horizon

AC3  The window is applied at the pipeline fetch/slice seam — run_rules(events),
     detect(events), and decide() gain NO time-filtering logic of their own (the
     golden-oracle constraint: these functions are called directly on in-memory
     lists by tests/golden).
     → test_run_rules_has_no_internal_time_filtering
     → test_detect_has_no_internal_time_filtering
     → test_decide_has_no_internal_time_filtering

AC4  ThreatScore.first_seen/last_seen/total_events/blocked_events keep lifetime
     semantics regardless of windowing.
     → test_lifetime_fields_unaffected_by_window

AC5  WHEN an actor's most recent block is older than W_STATE, analyze_ip SHALL NOT
     emit brute_force/persistence factors nor a Tier-3/4 blocked verdict for it
     (the lifetime-persistence defect).
     → test_stale_blocks_no_longer_fire_brute_force_or_tier3

AC6  tests/golden/fixtures/expected_scores.json is byte-identical after this
     change — verified structurally (git status / the golden suite itself is the
     oracle; not re-asserted here to avoid duplicating that suite's job).

AC7  W_STATE (24h) / W_CAMPAIGN (7d) are named, code-declared constants.
     → test_window_constants_values

Structural:
     → test_analyze_ip_fetches_store_exactly_once (ADR-0070 "one fetch, three views")

Security note: all test IPs use RFC 5737 documentation ranges (203.0.113.0/24) —
no real/routable addresses.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from firewatch_core.detector import detect
from firewatch_core.escalation.decider import decide
from firewatch_core.pipeline import Pipeline, W_CAMPAIGN, W_STATE
from firewatch_core.scoring import run_rules
from _fakes import FakeAIEngine, FakeStore, make_event

IP = "203.0.113.50"

# Fixed synthetic "now" — no wall-clock flakiness (ADR-0070 D4 windows are
# measured from "now", so every test below pins it via Pipeline(clock=...)).
NOW = datetime(2026, 7, 15, 12, 0, 0, tzinfo=timezone.utc)


def _pipeline(store) -> Pipeline:  # type: ignore[no-untyped-def]
    return Pipeline(store, FakeAIEngine(), clock=lambda: NOW)


class _CountingStore(FakeStore):
    """FakeStore that records how many times get_by_ip was called."""

    def __init__(self, events: list) -> None:  # type: ignore[no-untyped-def]
        super().__init__(events)
        self.get_by_ip_calls = 0

    async def get_by_ip(self, ip: str) -> list:  # type: ignore[no-untyped-def]
        self.get_by_ip_calls += 1
        return await super().get_by_ip(ip)


# ---------------------------------------------------------------------------
# AC7 — named, code-declared window constants
# ---------------------------------------------------------------------------


def test_window_constants_values() -> None:
    """AC7: W_STATE=24h and W_CAMPAIGN=7d are the provisional, code-declared values."""
    assert W_STATE == timedelta(hours=24)
    assert W_CAMPAIGN == timedelta(days=7)


# ---------------------------------------------------------------------------
# AC1 / AC5 — run_rules/build_score_breakdown/decide() windowed to W_STATE
# ---------------------------------------------------------------------------


async def test_recent_blocks_still_fire_brute_force_and_tier3() -> None:
    """Control: 10 blocked events 1h old (inside W_STATE) still score brute_force
    and reach Tier 3 — proves the window doesn't merely zero everything out."""
    events = [
        make_event(source_ip=IP, action="BLOCK", timestamp=NOW - timedelta(hours=1))
        for _ in range(10)
    ]
    store = FakeStore(events)
    score = await _pipeline(store).analyze_ip(IP)

    assert score.score == 40, "brute_force(30) + persistence(10) = 40"
    assert "brute_force" in score.attack_types
    assert score.escalation is not None
    assert score.escalation.tier == 3
    assert score.escalation.disposition == "blocked_persistent"


async def test_stale_blocks_no_longer_fire_brute_force_or_tier3() -> None:
    """AC5 (the defect fix): 10 blocked events 25h old (just outside W_STATE) no
    longer score brute_force/persistence, and no longer reach Tier 3/4.

    Before this fix, analyze_ip's lifetime `store.get_by_ip` fetch meant these
    same 10 blocks would score brute_force(+30)+persistence(+10)=40 and Tier 3
    PERMANENTLY, no matter how long ago the actor last acted.
    """
    events = [
        make_event(source_ip=IP, action="BLOCK", timestamp=NOW - timedelta(hours=25))
        for _ in range(10)
    ]
    store = FakeStore(events)
    score = await _pipeline(store).analyze_ip(IP)

    assert score.score == 0, f"Expected 0 (all blocks outside W_STATE), got {score.score}"
    assert score.attack_types == []
    assert "brute_force" not in score.attack_types
    assert score.escalation is not None
    assert score.escalation.tier is None, (
        f"Expected tier=None (observed) — no Tier-3/4 blocked verdict for a stale "
        f"actor, got tier={score.escalation.tier}"
    )
    assert score.escalation.disposition == "observed"


async def test_analyze_ip_detailed_windowed_to_state() -> None:
    """AC1/AC8: analyze_ip_detailed's run_rules/build_score_breakdown are windowed
    to W_STATE the same way analyze_ip's are."""
    events = [
        make_event(source_ip=IP, action="BLOCK", timestamp=NOW - timedelta(hours=25))
        for _ in range(10)
    ]
    store = FakeStore(events)
    result = await _pipeline(store).analyze_ip_detailed(IP, include_ai=False)

    assert result["score"] == 0, f"Expected rules-only score 0, got {result['score']}"
    assert result["attack_types"] == []
    # Lifetime facts are unaffected (AC4, re-verified on the detailed path).
    assert result["total_events"] == 10
    assert result["blocked_events"] == 10


# ---------------------------------------------------------------------------
# AC2 — detect() windowed to W_CAMPAIGN (independent of W_STATE)
# ---------------------------------------------------------------------------


def _sustained_attack_shape(base: datetime) -> list:  # type: ignore[no-untyped-def]
    """10 BLOCK events spanning 36 minutes from *base* — the _sustained_attack shape."""
    return [
        make_event(source_ip=IP, action="BLOCK", timestamp=base + timedelta(minutes=4 * i))
        for i in range(10)
    ]


async def test_detect_sees_campaign_window_not_state_window() -> None:
    """AC2: events 2 days old are outside W_STATE (24h) but inside W_CAMPAIGN (7d) —
    run_rules sees nothing (state_events empty) while detect() still fires
    sustained_attack from the campaign-window view. Proves the two windows are
    applied independently, at their own respective call sites.
    """
    events = _sustained_attack_shape(NOW - timedelta(days=2))
    store = FakeStore(events)
    score = await _pipeline(store).analyze_ip(IP)

    assert score.attack_types == [], "run_rules must see an empty W_STATE slice"
    assert any(d.rule_name == "sustained_attack" for d in score.detections), (
        "detect() must see the W_CAMPAIGN slice (2 days < 7 days) and fire "
        "sustained_attack even though W_STATE excluded these events"
    )
    assert score.score == 15, "rule_score(0) + detection_boost(15) = 15"


async def test_detect_excludes_events_older_than_campaign_horizon() -> None:
    """AC2: events 10 days old are outside BOTH W_STATE and W_CAMPAIGN — detect()
    must not fire sustained_attack either."""
    events = _sustained_attack_shape(NOW - timedelta(days=10))
    store = FakeStore(events)
    score = await _pipeline(store).analyze_ip(IP)

    assert score.detections == []
    assert score.score == 0


# ---------------------------------------------------------------------------
# AC3 — run_rules/detect/decide gain NO internal time-filtering (the seam
# constraint): calling them DIRECTLY on ancient in-memory events still produces
# the full, un-windowed result — proving the window lives only at the pipeline
# fetch/slice seam, never inside these pure functions (ADR-0070 D4 / golden
# oracle).
# ---------------------------------------------------------------------------


_ANCIENT = datetime(2000, 1, 1, tzinfo=timezone.utc)


def test_run_rules_has_no_internal_time_filtering() -> None:
    events = [make_event(source_ip=IP, action="BLOCK", timestamp=_ANCIENT) for _ in range(10)]
    rule_score, attack_types = run_rules(events)
    assert rule_score == 40, "run_rules must not filter by time — it is a pure function"
    assert "brute_force" in attack_types


def test_detect_has_no_internal_time_filtering() -> None:
    events = [
        make_event(source_ip=IP, action="BLOCK", timestamp=_ANCIENT + timedelta(minutes=4 * i))
        for i in range(10)
    ]
    detections = detect(events)
    assert any(d.rule_name == "sustained_attack" for d in detections), (
        "detect() must not filter by time — it is a pure function"
    )


def test_decide_has_no_internal_time_filtering() -> None:
    events = [make_event(source_ip=IP, action="BLOCK", timestamp=_ANCIENT) for _ in range(10)]
    verdict = decide(events, [])
    assert verdict.tier == 3, "decide() must not filter by time — it is a pure function"
    assert verdict.disposition == "blocked_persistent"


# ---------------------------------------------------------------------------
# AC4 — lifetime facts (first_seen/last_seen/total_events/blocked_events) keep
# their existing meaning regardless of the analysis windows.
# ---------------------------------------------------------------------------


async def test_lifetime_fields_unaffected_by_window() -> None:
    stale_blocks = [
        make_event(source_ip=IP, action="BLOCK", timestamp=NOW - timedelta(days=10))
        for _ in range(3)
    ]
    recent_alert = [
        make_event(source_ip=IP, action="ALERT", timestamp=NOW - timedelta(hours=1))
    ]
    events = stale_blocks + recent_alert
    store = FakeStore(events)
    score = await _pipeline(store).analyze_ip(IP)

    # Lifetime facts: unchanged semantics — computed from the FULL event list.
    assert score.total_events == 4
    assert score.blocked_events == 3
    assert score.first_seen == NOW - timedelta(days=10)
    assert score.last_seen == NOW - timedelta(hours=1)

    # But the counting rules only saw the 1 recent ALERT (state window) — the 3
    # stale blocks do not count toward persistence/brute_force.
    assert score.attack_types == []


# ---------------------------------------------------------------------------
# Structural — ADR-0070 "one fetch, three views": the pipeline fetches the
# actor's event list from the store exactly once per analyze_ip call and slices
# it in-process; it does NOT issue a second (windowed) store query.
# ---------------------------------------------------------------------------


async def test_analyze_ip_fetches_store_exactly_once() -> None:
    events = [make_event(source_ip=IP, action="BLOCK", timestamp=NOW - timedelta(hours=1))]
    store = _CountingStore(events)
    await _pipeline(store).analyze_ip(IP)
    assert store.get_by_ip_calls == 1, (
        "analyze_ip must fetch the store exactly once (ADR-0070 D4: one fetch, "
        f"three views) — got {store.get_by_ip_calls} calls"
    )
