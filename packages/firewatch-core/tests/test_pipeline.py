"""Pipeline.analyze_ip + ingest tests (EARS-3 — orchestration, ONE AI call, fail-safe)."""
from datetime import datetime, timedelta, timezone

from firewatch_sdk import AIEngine, EventStore

from firewatch_core.pipeline import Pipeline
from _fakes import FakeAIEngine, FakeStore, make_event

T0 = datetime(2026, 6, 3, 12, 0, 0, tzinfo=timezone.utc)
IP = "203.0.113.5"

# Issue #52 (ADR-0070 D4): analyze_ip now windows run_rules/detect/decide to a
# trailing W_STATE/W_CAMPAIGN slice measured from "now". These tests assert
# scoring behavior against fixed T0-relative event timestamps, so they inject a
# synthetic clock fixed shortly after T0 — well inside both windows — rather
# than relying on the real wall clock (no wall-clock flakiness).
_NOW = T0 + timedelta(hours=1)


def _pipeline(store: EventStore, ai: AIEngine) -> Pipeline:
    return Pipeline(store, ai, clock=lambda: _NOW)


def _sqli_events(n: int) -> list:
    return [
        make_event(action="BLOCK", rule_id="942100", payload_snippet="' OR '1'='1")
        for _ in range(n)
    ]


async def test_analyze_ip_empty_is_low():
    store: EventStore = FakeStore([])
    ai: AIEngine = FakeAIEngine()
    score = await _pipeline(store, ai).analyze_ip(IP)
    assert score.threat_level == "LOW"
    assert score.score == 0
    assert score.total_events == 0


async def test_analyze_ip_exactly_one_ai_call():
    fake_ai = FakeAIEngine()
    store: EventStore = FakeStore(_sqli_events(3))
    ai: AIEngine = fake_ai
    await _pipeline(store, ai).analyze_ip(IP)
    assert fake_ai.concise_calls == 1


async def test_analyze_ip_score_parity():
    # 10 blocked SQLi events → brute_force(30) + sqli_BLOCK(20) + persistence(10) = 60 (#651)
    # Old math (removed): +30 brute-force + +40 sqli + +10 per-blocked = 80.
    # New (#651): sqli on BLOCK = round(40×0.5)=20; persistence floor +10 (10≥3).
    # All 10 events share _sqli_events'/make_event's default (identical) timestamp,
    # so they are 10 SIMULTANEOUS attempts — decayed intensity lambda_hat=10 >=
    # theta_press=5 (issue #53, ADR-0070 Revision 1): +15 attempt_pressure boost.
    store: EventStore = FakeStore(_sqli_events(10))
    ai: AIEngine = FakeAIEngine()  # LOW / 0.0 → no AI boost
    score = await _pipeline(store, ai).analyze_ip(IP)
    assert score.score == 75  # 60 (#651) + 15 (attempt_pressure, #53) = 75
    assert score.threat_level == "HIGH"  # HIGH <= 75 < CRITICAL
    assert any(d.rule_name == "attempt_pressure" for d in score.detections)
    assert "brute_force" in score.attack_types
    assert "sql_injection" in score.attack_types
    assert score.source_types == ["suricata"]
    assert score.ai_status == "active"


async def test_analyze_ip_ai_failure_is_rules_only():
    store: EventStore = FakeStore(_sqli_events(3))
    ai: AIEngine = FakeAIEngine(fail=True)
    score = await _pipeline(store, ai).analyze_ip(IP)
    assert score.ai_status == "unavailable"
    # rules-only: 3 blocked SQLi → sqli_BLOCK(20) + persistence(10) = 30 (#651)
    # Old math (removed): +40 sqli + 3 per-blocked = 43
    assert score.score == 30  # sqli on BLOCK=round(40×0.5)=20; persistence floor=10 (#651)


async def test_analyze_ip_ai_boost_applied():
    store: EventStore = FakeStore(_sqli_events(3))  # rules-only 30 (#651)
    ai: AIEngine = FakeAIEngine({"threat_level": "CRITICAL", "confidence": 0.9})
    score = await _pipeline(store, ai).analyze_ip(IP)
    assert score.score == 50  # 30 (rules) + 20 (CRITICAL boost) = 50 (#651)
    assert score.ai_confidence == 0.9


async def test_analyze_ip_detection_boost_flows():
    # 10 BLOCK spanning 36 min → brute-force(+30)+10 blocked = 40 rule;
    # attempt_pressure(+15) boost (ADR-0070 Revision 1 R1 — retired
    # sustained_attack's replacement; same score_delta, issue #53).
    #
    # This is ALSO the exact fixture that surfaced the false-`campaign`
    # defect PR #86 caught (ADR-0070 Amendment 1): the closed-form decayed
    # intensity climbs through theta_press=5 gradually (event 6 of 10, at
    # t=24min, lambda_hat=5.396), then the 4-min gap to event 7 lets it dip
    # fractionally BELOW 5 — to ~4.92, ~98% of the pressure floor — for
    # ~42 seconds before event 7's own jump restores it. Under exact-crossing
    # separation (Revision 1, pre-amendment) that 42-second dip was read as a
    # full episode boundary, so `episodes()` reported 2 episodes and R3's
    # recidivism clause fired `campaign` on a single continuous burst.
    # Quiet-collapse hysteresis (theta_quiet = theta_press/2 = 2.5) fixes
    # this: the trough (4.92) sits well above theta_quiet, so `episodes()`
    # now reports ONE continuous episode — no recidivism, no endurance
    # (span << D_ENDURE), no breadth — a single continuous moderate burst
    # must NOT fire `campaign`.
    # detection_boost = 15 (attempt_pressure only) → 40 (rule) + 15 = 55.
    events = [
        make_event(action="BLOCK", rule_id="900001",
                   timestamp=T0 + timedelta(minutes=4 * i))
        for i in range(10)
    ]
    store: EventStore = FakeStore(events)
    ai: AIEngine = FakeAIEngine()
    score = await _pipeline(store, ai).analyze_ip(IP)
    assert any(d.rule_name == "attempt_pressure" for d in score.detections)
    assert not any(d.rule_name == "campaign" for d in score.detections), (
        "a single continuous moderate burst must NOT fire campaign"
    )
    assert score.score == 55  # 40 (rule) + 15 (attempt_pressure) = 55


async def test_analyze_ip_jittery_grinder_below_d_endure_does_not_fire_campaign():
    """A jittery ~8/h grinder (alternating 3-min/12-min gaps — ADR-0070
    Amendment 1 A1.2's "boundary oscillator") holds decayed intensity
    straddling theta_press (5) on both sides, without ever collapsing
    anywhere near theta_quiet (2.5): ONE merged pressure episode, well short
    of D_ENDURE (24h). No recidivism (one episode), no endurance (span <<
    24h), no breadth (no categories/ports set) — `campaign` must NOT fire."""
    events = [
        make_event(action="BLOCK", rule_id="900001", timestamp=T0)
        for _ in range(6)
    ]
    elapsed = timedelta(0)
    gaps = (timedelta(minutes=3), timedelta(minutes=12))
    i = 0
    while elapsed < timedelta(minutes=45):
        elapsed += gaps[i % 2]
        events.append(
            make_event(action="BLOCK", rule_id="900001", timestamp=T0 + elapsed)
        )
        i += 1
    store: EventStore = FakeStore(events)
    ai: AIEngine = FakeAIEngine()
    score = await _pipeline(store, ai).analyze_ip(IP)
    assert not any(d.rule_name == "campaign" for d in score.detections)


async def test_use_ai_false_skips_ai():
    """use_ai=False is a per-request CALLER opt-out, not an admin/config choice.

    ADR-0066: caller_opted_out -> 'skipped' (never 'disabled', which is
    reserved for ai_enabled=false at the config layer — see
    test_issue_39_40_ai_status_stamping.py for the admin-disabled case).
    """
    fake_ai = FakeAIEngine()
    store: EventStore = FakeStore(_sqli_events(3))
    ai: AIEngine = fake_ai
    score = await _pipeline(store, ai).analyze_ip(IP, use_ai=False)
    assert fake_ai.concise_calls == 0
    assert score.ai_status == "skipped"


async def test_ingest_returns_inserted_count():
    store: EventStore = FakeStore([])
    ai: AIEngine = FakeAIEngine()
    inserted = await Pipeline(store, ai).ingest(_sqli_events(4))
    assert inserted == 4
