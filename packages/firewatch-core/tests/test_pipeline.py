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
    # issue #54 (R3 `campaign`, +20) also fires for this EXACT fixture: the
    # closed-form decayed intensity climbs through theta_press=5 gradually
    # (event 6 of 10, at t=24min, lambda_hat=5.396) and — because the 4-min
    # gap to event 7 is just wide enough for decay to dip fractionally BELOW
    # 5 for ~42 seconds before event 7's own jump pushes it back above —
    # `episodes()` (the exact, closed-form, no-grace-period segmentation
    # ADR-0070 D3/#53 already ships) reports 2 episodes rather than 1,
    # satisfying R3's recidivism clause (>=2 episodes). Verified numerically
    # (not assumed): intensity_at dips to ~4.95 at 12:27:45 then jumps to
    # ~5.92 at the next event (12:28:00). This is a genuine, if narrow,
    # consequence of the ADR's exact-crossing episode definition applied to
    # a fixture that happens to hover at the theta_press boundary while
    # still ramping — flagged in issue #54's PR description for the
    # ADR-0068 D3 live-calibration pass, not silently absorbed here.
    # detection_boost = 15 (attempt_pressure) + 20 (campaign) = 35, capped
    # at +30 (ADR-0036 D4) → 40 (rule) + 30 (capped boost) = 70.
    events = [
        make_event(action="BLOCK", rule_id="900001",
                   timestamp=T0 + timedelta(minutes=4 * i))
        for i in range(10)
    ]
    store: EventStore = FakeStore(events)
    ai: AIEngine = FakeAIEngine()
    score = await _pipeline(store, ai).analyze_ip(IP)
    assert any(d.rule_name == "attempt_pressure" for d in score.detections)
    assert any(d.rule_name == "campaign" for d in score.detections)
    assert score.score == 70  # 40 (rule) + min(15+20, 30) (capped boost) = 70


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
