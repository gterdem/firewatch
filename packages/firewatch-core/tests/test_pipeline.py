"""Pipeline.analyze_ip + ingest tests (EARS-3 — orchestration, ONE AI call, fail-safe)."""
from datetime import datetime, timedelta, timezone

from firewatch_sdk import AIEngine, EventStore

from firewatch_core.pipeline import Pipeline
from _fakes import FakeAIEngine, FakeStore, make_event

T0 = datetime(2026, 6, 3, 12, 0, 0, tzinfo=timezone.utc)
IP = "203.0.113.5"


def _sqli_events(n: int) -> list:
    return [
        make_event(action="BLOCK", rule_id="942100", payload_snippet="' OR '1'='1")
        for _ in range(n)
    ]


async def test_analyze_ip_empty_is_low():
    store: EventStore = FakeStore([])
    ai: AIEngine = FakeAIEngine()
    score = await Pipeline(store, ai).analyze_ip(IP)
    assert score.threat_level == "LOW"
    assert score.score == 0
    assert score.total_events == 0


async def test_analyze_ip_exactly_one_ai_call():
    fake_ai = FakeAIEngine()
    store: EventStore = FakeStore(_sqli_events(3))
    ai: AIEngine = fake_ai
    await Pipeline(store, ai).analyze_ip(IP)
    assert fake_ai.concise_calls == 1


async def test_analyze_ip_score_parity():
    # 10 blocked SQLi events → brute_force(30) + sqli_BLOCK(20) + persistence(10) = 60 (#651)
    # Old math (removed): +30 brute-force + +40 sqli + +10 per-blocked = 80.
    # New (#651): sqli on BLOCK = round(40×0.5)=20; persistence floor +10 (10≥3).
    store: EventStore = FakeStore(_sqli_events(10))
    ai: AIEngine = FakeAIEngine()  # LOW / 0.0 → no AI boost
    score = await Pipeline(store, ai).analyze_ip(IP)
    assert score.score == 60  # brute_force(30)+sqli_BLOCK(20)+persistence(10)=60 (#651)
    assert score.threat_level == "HIGH"  # 60 >= 51 → HIGH (#651; was CRITICAL at 80)
    assert "brute_force" in score.attack_types
    assert "sql_injection" in score.attack_types
    assert score.source_types == ["suricata"]
    assert score.ai_status == "active"


async def test_analyze_ip_ai_failure_is_rules_only():
    store: EventStore = FakeStore(_sqli_events(3))
    ai: AIEngine = FakeAIEngine(fail=True)
    score = await Pipeline(store, ai).analyze_ip(IP)
    assert score.ai_status == "unavailable"
    # rules-only: 3 blocked SQLi → sqli_BLOCK(20) + persistence(10) = 30 (#651)
    # Old math (removed): +40 sqli + 3 per-blocked = 43
    assert score.score == 30  # sqli on BLOCK=round(40×0.5)=20; persistence floor=10 (#651)


async def test_analyze_ip_ai_boost_applied():
    store: EventStore = FakeStore(_sqli_events(3))  # rules-only 30 (#651)
    ai: AIEngine = FakeAIEngine({"threat_level": "CRITICAL", "confidence": 0.9})
    score = await Pipeline(store, ai).analyze_ip(IP)
    assert score.score == 50  # 30 (rules) + 20 (CRITICAL boost) = 50 (#651)
    assert score.ai_confidence == 0.9


async def test_analyze_ip_detection_boost_flows():
    # 10 BLOCK spanning 36 min → brute-force(+30)+10 blocked = 40 rule; sustained(+15) boost.
    events = [
        make_event(action="BLOCK", rule_id="900001",
                   timestamp=T0 + timedelta(minutes=4 * i))
        for i in range(10)
    ]
    store: EventStore = FakeStore(events)
    ai: AIEngine = FakeAIEngine()
    score = await Pipeline(store, ai).analyze_ip(IP)
    assert any(d.rule_name == "sustained_attack" for d in score.detections)
    assert score.score == 55  # 40 + 15


async def test_use_ai_false_skips_ai():
    fake_ai = FakeAIEngine()
    store: EventStore = FakeStore(_sqli_events(3))
    ai: AIEngine = fake_ai
    score = await Pipeline(store, ai).analyze_ip(IP, use_ai=False)
    assert fake_ai.concise_calls == 0
    assert score.ai_status == "disabled"


async def test_ingest_returns_inserted_count():
    store: EventStore = FakeStore([])
    ai: AIEngine = FakeAIEngine()
    inserted = await Pipeline(store, ai).ingest(_sqli_events(4))
    assert inserted == 4
