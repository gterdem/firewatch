"""Tests for Pipeline.analyze_ip_detailed — issue #19 (M2.4).

Each test maps 1:1 to an EARS acceptance criterion.

EARS-1 (Event-driven): one AI call; returns augmented result dict.
EARS-2 (Event-driven): detailed samples — uncapped, 300-char, timestamps, descriptions.
EARS-3 (State-driven): security_mode → security-worded detailed prompt.
EARS-4 (Unwanted): empty IP → {"error": "No logs found"}, NO AI call.
EARS-5 (Unwanted): AI failure → rules-only result, never raises.
EARS-6 (State-driven — NB-3): fallback envelope (ai_status=="unavailable") → no schema
        validation, rules-only score.
EARS-7 (Ubiquitous): additive-only merge — AI may raise but never lower rules score.
EARS-8 (Ubiquitous): v1 return shape preserved (score, threat_level, total_events,
        blocked_events, attack_types, source_ip).

Security hardening (F1/F2 — post-review non-blocking findings):
F1 (DoS-via-legitimate-input): detailed path bounds event load to MAX_DETAILED_EVENTS
        most-recent events; tests with >MAX_DETAILED_EVENTS events for one IP.
F2 (broad except → logger.exception): AI failure handler logs at exception level so a
        misbehaving engine surfaces a traceback in dev, while still degrading gracefully.

Issue #268 (include_ai=False fast path — staged honest AI loading):
I268-1: include_ai=False → ai_status='skipped', zero AI calls.
I268-2: include_ai=False → rules-only score (no AI boost even if engine available).
I268-3: include_ai=False → all v1 rule-derived fields still present.
I268-4: golden unchanged — include_ai=True (default) still calls AI exactly once.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from firewatch_sdk import AIEngine, EventStore

from firewatch_core.pipeline import Pipeline
from firewatch_core.scoring import MAX_DETAILED_EVENTS
from _fakes import FakeAIEngine, FakeStore, make_event

IP = "203.0.113.5"
IP_AZURE = "192.0.2.10"
T0 = datetime(2026, 6, 3, 12, 0, 0, tzinfo=timezone.utc)

# Issue #52 (ADR-0070 D4): analyze_ip_detailed now windows run_rules/
# build_score_breakdown to a trailing W_STATE slice measured from "now". These
# tests assert scoring behavior against fixed T0-relative event timestamps, so
# every Pipeline() construction below injects this synthetic clock — fixed
# shortly after T0, well inside W_STATE — instead of the real wall clock.
_CLOCK = lambda: T0 + timedelta(hours=1)  # noqa: E731

# A valid detailed AI result (matches the closed schema)
_VALID_AI_RESULT: dict[str, Any] = {
    "threat_level": "HIGH",
    "confidence": 0.85,
    "executive_summary": "Attacker performing SQL injection.",
    "intent": "Data exfiltration",
    "attack_stage": "exploitation",
    "attack_progression": ["Step 1: scan", "Step 2: exploit"],
    "insights": {"patterns": ["SQLi"], "risks": ["data breach"], "mitigations": ["WAF rule"]},
    "ioc_indicators": ["942100 triggered repeatedly"],
    "recommended_action": "block",
    "false_positive_likelihood": 0.05,
    "ai_status": "ok",
}

# The AIEngine fallback envelope — deliberately OUTSIDE closed schema (NB-3)
_FALLBACK_ENVELOPE: dict[str, Any] = {
    "threat_level": "UNKNOWN",
    "confidence": 0.0,
    "executive_summary": "Detailed AI analysis unavailable.",
    "intent": "AI analysis failed",
    "attack_stage": "reconnaissance",
    "attack_progression": [],
    "insights": {"patterns": [], "risks": [], "mitigations": []},
    "ioc_indicators": ["Analysis failed: LLM endpoint error"],
    "recommended_action": "investigate",
    "false_positive_likelihood": 0.5,
    "ai_status": "unavailable",
}


def _sqli_events(n: int, source_type: str = "azure_waf") -> list:
    return [
        make_event(
            action="BLOCK",
            rule_id="942100",
            payload_snippet="' OR '1'='1",
            source_type=source_type,
        )
        for _ in range(n)
    ]


# ---------------------------------------------------------------------------
# EARS-1: exactly one AI call per IP, returns dict
# ---------------------------------------------------------------------------


async def test_analyze_ip_detailed_exactly_one_ai_call() -> None:
    """EARS-1: analyze_ip_detailed issues exactly ONE analyze_detailed call."""
    fake_ai = FakeAIEngine(result=_VALID_AI_RESULT)
    store: EventStore = FakeStore(_sqli_events(3))
    await Pipeline(store, fake_ai, clock=_CLOCK).analyze_ip_detailed(IP)
    assert fake_ai.detailed_calls == 1, (
        f"Expected exactly 1 AI call, got {fake_ai.detailed_calls}. "
        "ADR-0003: one LLM call per IP."
    )
    assert fake_ai.concise_calls == 0, (
        "analyze_ip_detailed must NOT call analyze_concise."
    )


async def test_analyze_ip_detailed_returns_dict() -> None:
    """EARS-1: returns a dict (not a ThreatScore), consistent with v1 shape."""
    store: EventStore = FakeStore(_sqli_events(3))
    result = await Pipeline(store, FakeAIEngine(result=_VALID_AI_RESULT), clock=_CLOCK).analyze_ip_detailed(IP)
    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# EARS-4 (Unwanted): empty IP returns error dict, no AI call
# ---------------------------------------------------------------------------


async def test_analyze_ip_detailed_empty_returns_error() -> None:
    """EARS-4: no events → returns {'error': 'No logs found'} (v1 behavior)."""
    fake_ai = FakeAIEngine()
    store: EventStore = FakeStore([])
    result = await Pipeline(store, fake_ai, clock=_CLOCK).analyze_ip_detailed(IP)
    assert result == {"error": "No logs found"}, (
        f"Expected {{'error': 'No logs found'}}, got {result!r}"
    )


async def test_analyze_ip_detailed_empty_no_ai_call() -> None:
    """EARS-4: no events → AI engine must NOT be called."""
    fake_ai = FakeAIEngine()
    store: EventStore = FakeStore([])
    await Pipeline(store, fake_ai, clock=_CLOCK).analyze_ip_detailed(IP)
    assert fake_ai.detailed_calls == 0, (
        "AI engine must not be called when there are no events (EARS-4)."
    )


# ---------------------------------------------------------------------------
# EARS-5 (Unwanted): AI failure → rules-only result, never raises
# ---------------------------------------------------------------------------


async def test_analyze_ip_detailed_ai_failure_does_not_raise() -> None:
    """EARS-5: AI engine failure must not propagate an exception."""
    store: EventStore = FakeStore(_sqli_events(3))
    ai: AIEngine = FakeAIEngine(fail=True)
    # Must not raise
    result = await Pipeline(store, ai, clock=_CLOCK).analyze_ip_detailed(IP)
    assert isinstance(result, dict)


async def test_analyze_ip_detailed_ai_failure_rules_only_score() -> None:
    """EARS-5: AI failure → score is rules-only (no AI boost)."""
    # 3 blocked SQLi: sqli_BLOCK=round(40×0.5)=20 + persistence=10 = 30 (#651)
    # Old math (removed): +40 sqli + 3 per-blocked = 43
    store: EventStore = FakeStore(_sqli_events(3))
    ai: AIEngine = FakeAIEngine(fail=True)
    result = await Pipeline(store, ai, clock=_CLOCK).analyze_ip_detailed(IP)
    assert result["score"] == 30, (
        f"Expected rules-only score 30, got {result['score']}. "
        "AI failure must degrade to rules-only, not zero. (#651)"
    )


# ---------------------------------------------------------------------------
# EARS-6 (NB-3): AIEngine fallback envelope — branch on ai_status FIRST
# ---------------------------------------------------------------------------


async def test_analyze_ip_detailed_fallback_envelope_rules_only() -> None:
    """EARS-6 (NB-3): fallback envelope (ai_status='unavailable') → rules-only score.

    The fallback shape deliberately has threat_level='UNKNOWN' which is outside the
    closed schema. The pipeline MUST branch on ai_status BEFORE any schema validation.
    This test proves the result uses the rules-only score, not a boosted or errored one.
    """
    # 3 blocked SQLi: sqli_BLOCK=round(40×0.5)=20 + persistence=10 = 30 (#651)
    # Old math (removed): +40 sqli + 3 per-blocked = 43
    store: EventStore = FakeStore(_sqli_events(3))
    ai: AIEngine = FakeAIEngine(result=_FALLBACK_ENVELOPE)
    result = await Pipeline(store, ai, clock=_CLOCK).analyze_ip_detailed(IP)
    assert result["score"] == 30, (
        f"Expected rules-only score 30 for fallback envelope, got {result['score']}. "
        "NB-3: branch on ai_status BEFORE schema validating. (#651)"
    )


async def test_analyze_ip_detailed_fallback_does_not_raise_on_unknown_threat_level() -> None:
    """EARS-6 (NB-3): fallback envelope with threat_level='UNKNOWN' must not raise.

    'UNKNOWN' is outside the closed schema — if the pipeline incorrectly schema-validates
    the fallback before branching, it would raise. This test guards that.
    """
    store: EventStore = FakeStore(_sqli_events(3))
    ai: AIEngine = FakeAIEngine(result=_FALLBACK_ENVELOPE)
    # Must not raise ValueError or any other exception
    result = await Pipeline(store, ai, clock=_CLOCK).analyze_ip_detailed(IP)
    assert isinstance(result, dict)


async def test_analyze_ip_detailed_fallback_ai_does_not_boost_score() -> None:
    """EARS-6 (NB-3): fallback envelope must not add AI boost.

    Even though the fallback has confidence=0.0 and threat_level='UNKNOWN',
    the pipeline must treat it as 'no AI contribution', not attempt to merge it.
    """
    store: EventStore = FakeStore(_sqli_events(3))
    rules_only_score = 30  # sqli_BLOCK(20) + persistence(10) = 30 (#651)

    ai: AIEngine = FakeAIEngine(result=_FALLBACK_ENVELOPE)
    result = await Pipeline(store, ai, clock=_CLOCK).analyze_ip_detailed(IP)
    assert result["score"] == rules_only_score


# ---------------------------------------------------------------------------
# EARS-7 (Ubiquitous): additive-only merge
# ---------------------------------------------------------------------------


async def test_analyze_ip_detailed_ai_boost_applied() -> None:
    """EARS-7: CRITICAL AI verdict with confidence>0.7 adds +20 to rule score."""
    # 3 blocked SQLi: rules-only = 30 (#651); CRITICAL boost +20 → 50
    # Old math (removed): rules-only=43 + 20 = 63
    store: EventStore = FakeStore(_sqli_events(3))
    ai_result = {**_VALID_AI_RESULT, "threat_level": "CRITICAL", "confidence": 0.9}
    ai: AIEngine = FakeAIEngine(result=ai_result)
    result = await Pipeline(store, ai, clock=_CLOCK).analyze_ip_detailed(IP)
    assert result["score"] == 50, (
        f"Expected 30 (rules) + 20 (CRITICAL boost) = 50, got {result['score']}. (#651)"
    )


async def test_analyze_ip_detailed_ai_high_boost() -> None:
    """EARS-7: HIGH AI verdict with confidence>0.7 adds +10 to rule score."""
    # 3 blocked SQLi: rules-only=30 (#651); HIGH boost +10 → 40
    # Old math (removed): 43 + 10 = 53
    store: EventStore = FakeStore(_sqli_events(3))
    ai_result = {**_VALID_AI_RESULT, "threat_level": "HIGH", "confidence": 0.85}
    ai: AIEngine = FakeAIEngine(result=ai_result)
    result = await Pipeline(store, ai, clock=_CLOCK).analyze_ip_detailed(IP)
    assert result["score"] == 40  # 30 (rules, #651) + 10 (HIGH boost) = 40


async def test_analyze_ip_detailed_ai_low_confidence_no_boost() -> None:
    """EARS-7: CRITICAL at confidence=0.7 (not >0.7) gives NO boost (boundary check)."""
    # 3 blocked SQLi: rules-only=30 (#651); 0.7 not > 0.7 → no AI boost
    # Old math (removed): rules-only=43; no boost; = 43
    store: EventStore = FakeStore(_sqli_events(3))
    ai_result = {**_VALID_AI_RESULT, "threat_level": "CRITICAL", "confidence": 0.7}
    ai: AIEngine = FakeAIEngine(result=ai_result)
    result = await Pipeline(store, ai, clock=_CLOCK).analyze_ip_detailed(IP)
    assert result["score"] == 30  # no boost; 0.7 is not > 0.7; rules-only=30 (#651)


async def test_analyze_ip_detailed_ai_cannot_lower_score() -> None:
    """EARS-7: additive-only invariant — AI LOW result must not lower the rules score.

    ai-engine-invariants: AI may RAISE but never LOWER the deterministic score.
    """
    store: EventStore = FakeStore(_sqli_events(10))
    # 10 blocked SQLi: brute_force(30) + sqli_BLOCK(20) + persistence(10) = 60 (#651)
    # Old math (removed): +30 (brute-force) + 40 (sqli) + 10 (per-blocked) = 80
    ai_result = {**_VALID_AI_RESULT, "threat_level": "LOW", "confidence": 0.9}
    ai: AIEngine = FakeAIEngine(result=ai_result)
    result = await Pipeline(store, ai, clock=_CLOCK).analyze_ip_detailed(IP)
    assert result["score"] >= 60, (
        f"AI LOW verdict must not lower the rules score 60; got {result['score']}. (#651)"
    )


async def test_analyze_ip_detailed_score_capped_at_100() -> None:
    """EARS-7: score is capped at 100 even after AI boost.

    (#651) New scenario to force cap: 10 BLOCK events with distinct ports + sqli payload
    → brute_force(30) + port_scan(25) + sqli_BLOCK(20) + persistence(10) = 85;
    CRITICAL AI boost +20 = 105 → capped to 100.
    Old scenario (10 blocked SQLi) no longer caps: rules=60+20=80 < 100.
    """
    # 10 BLOCK events, each with a distinct dest port and sqli payload:
    events = [
        make_event(
            action="BLOCK",
            destination_port=p,
            payload_snippet="' OR '1'='1",
            source_type="azure_waf",
        )
        for p in range(10)
    ]
    store: EventStore = FakeStore(events)
    # brute_force(30)+port_scan(25)+sqli_BLOCK(20)+persistence(10)+CRITICAL(20)=105→100 (#651)
    ai_result = {**_VALID_AI_RESULT, "threat_level": "CRITICAL", "confidence": 0.9}
    ai: AIEngine = FakeAIEngine(result=ai_result)
    result = await Pipeline(store, ai, clock=_CLOCK).analyze_ip_detailed(IP)
    assert result["score"] == 100


# ---------------------------------------------------------------------------
# EARS-8 (Ubiquitous): v1 return shape
# ---------------------------------------------------------------------------


async def test_analyze_ip_detailed_v1_shape() -> None:
    """EARS-8: result dict contains v1-required fields.

    v1 shape (legacy/app/analyzer.py:280-286):
      score, threat_level, total_events, blocked_events, attack_types, source_ip.
    """
    store: EventStore = FakeStore(_sqli_events(3))
    result = await Pipeline(store, FakeAIEngine(result=_VALID_AI_RESULT), clock=_CLOCK).analyze_ip_detailed(IP)
    for key in ("score", "threat_level", "total_events", "blocked_events",
                "attack_types", "source_ip"):
        assert key in result, f"Missing required v1 field: {key!r}"


async def test_analyze_ip_detailed_v1_shape_values() -> None:
    """EARS-8: v1 fields carry correct computed values."""
    store: EventStore = FakeStore(_sqli_events(3))
    result = await Pipeline(store, FakeAIEngine(result=_VALID_AI_RESULT), clock=_CLOCK).analyze_ip_detailed(IP)
    assert result["source_ip"] == IP
    assert result["total_events"] == 3
    assert result["blocked_events"] == 3  # all BLOCK
    assert "sql_injection" in result["attack_types"]
    assert isinstance(result["score"], int)
    assert result["threat_level"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


# ---------------------------------------------------------------------------
# EARS-3 (State-driven): security_mode
# ---------------------------------------------------------------------------


class _SecurityModeCapturingAI:
    """AIEngine fake that records the security_mode passed in each call."""

    def __init__(self) -> None:
        self.security_mode_calls: list[bool] = []
        self.detailed_calls = 0
        self.concise_calls = 0

    async def is_available(self) -> bool:
        return True

    async def analyze_concise(self, **kwargs: Any) -> dict[str, Any]:  # type: ignore[override]
        self.concise_calls += 1
        return {"threat_level": "LOW", "confidence": 0.0, "insights": []}

    async def analyze_detailed(  # type: ignore[override]
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
        self.detailed_calls += 1
        self.security_mode_calls.append(security_mode)
        return _VALID_AI_RESULT


async def test_analyze_ip_detailed_security_mode_non_azure_waf() -> None:
    """EARS-3: non-azure_waf source → security_mode=True passed to AI."""
    fake_ai = _SecurityModeCapturingAI()
    events = _sqli_events(3, source_type="suricata")  # non-azure_waf
    store: EventStore = FakeStore(events)
    await Pipeline(store, fake_ai, clock=_CLOCK).analyze_ip_detailed(IP)  # type: ignore[arg-type]
    assert fake_ai.security_mode_calls == [True], (
        "Non-azure_waf source must trigger security_mode=True for detailed analysis."
    )


async def test_analyze_ip_detailed_security_mode_azure_waf_only() -> None:
    """EARS-3: pure azure_waf source → security_mode=False passed to AI."""
    fake_ai = _SecurityModeCapturingAI()
    # Events must use the same IP we query for
    events = [
        make_event(
            source_ip=IP,
            action="BLOCK",
            rule_id="942100",
            payload_snippet="' OR '1'='1",
            source_type="azure_waf",
        )
        for _ in range(3)
    ]
    store: EventStore = FakeStore(events)
    await Pipeline(store, fake_ai, clock=_CLOCK).analyze_ip_detailed(IP)  # type: ignore[arg-type]
    assert fake_ai.security_mode_calls == [False], (
        "Pure azure_waf source must use security_mode=False."
    )


# ---------------------------------------------------------------------------
# EARS-2 (Event-driven): rule_descriptions passed through to detailed samples
# ---------------------------------------------------------------------------


class _DescriptionCapturingAI:
    """Captures the samples list passed to analyze_detailed."""

    def __init__(self) -> None:
        self.captured_samples: list[dict[str, Any]] = []
        self.detailed_calls = 0
        self.concise_calls = 0

    async def is_available(self) -> bool:
        return True

    async def analyze_concise(self, **kwargs: Any) -> dict[str, Any]:  # type: ignore[override]
        self.concise_calls += 1
        return {"threat_level": "LOW", "confidence": 0.0}

    async def analyze_detailed(  # type: ignore[override]
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
        self.detailed_calls += 1
        self.captured_samples = list(samples)
        return _VALID_AI_RESULT


class _StoreWithDescriptions(FakeStore):
    """FakeStore that returns scripted rule descriptions."""

    def __init__(
        self,
        events: list,
        descs: dict[str, str] | None = None,
    ) -> None:
        super().__init__(events)
        self._descs = descs or {}

    async def get_rule_descriptions(self) -> dict[str, str]:
        return self._descs


async def test_analyze_ip_detailed_passes_descriptions_to_samples() -> None:
    """EARS-2: rule descriptions from store.get_rule_descriptions() appear in samples."""
    descs = {"942100": "SQL injection via numeric parameter"}
    store = _StoreWithDescriptions(_sqli_events(3), descs=descs)
    fake_ai = _DescriptionCapturingAI()
    await Pipeline(store, fake_ai, clock=_CLOCK).analyze_ip_detailed(IP)  # type: ignore[arg-type]
    assert fake_ai.detailed_calls == 1
    assert len(fake_ai.captured_samples) == 1
    assert fake_ai.captured_samples[0]["description"] == "SQL injection via numeric parameter"


async def test_analyze_ip_detailed_graceful_with_empty_rule_descs() -> None:
    """EARS-2: empty rule descriptions → blank strings (graceful degradation)."""
    store = _StoreWithDescriptions(_sqli_events(3), descs={})
    fake_ai = _DescriptionCapturingAI()
    await Pipeline(store, fake_ai, clock=_CLOCK).analyze_ip_detailed(IP)  # type: ignore[arg-type]
    assert fake_ai.captured_samples[0]["description"] == ""


async def test_analyze_ip_detailed_samples_uncapped() -> None:
    """EARS-2: all rules included in detailed samples — no 15-cap."""
    events = [
        make_event(action="BLOCK", rule_id=f"9{i:05d}", payload_snippet="x")
        for i in range(20)
    ]
    store = _StoreWithDescriptions(events)
    fake_ai = _DescriptionCapturingAI()
    await Pipeline(store, fake_ai, clock=_CLOCK).analyze_ip_detailed(IP)  # type: ignore[arg-type]
    assert len(fake_ai.captured_samples) == 20, (
        f"Detailed path must send all 20 rules to AI, got {len(fake_ai.captured_samples)}."
    )


# ---------------------------------------------------------------------------
# F1 (DoS-via-legitimate-input): event load bounded to MAX_DETAILED_EVENTS
# ---------------------------------------------------------------------------


async def test_analyze_ip_detailed_bounds_event_load_to_cap() -> None:
    """F1: fabricate more than MAX_DETAILED_EVENTS events and assert the detailed path
    bounds the loaded set to MAX_DETAILED_EVENTS and still returns a valid result.

    The cap applies to the detailed path only; the concise path is unaffected.
    """
    # Build MAX_DETAILED_EVENTS + 500 events for the target IP with a single rule_id
    # so we can verify the cap is applied (total_events reported equals the cap).
    cap = MAX_DETAILED_EVENTS
    n_events = cap + 500
    events = [
        make_event(
            source_ip=IP,
            action="BLOCK",
            rule_id="942100",
            payload_snippet="' OR '1'='1",
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=i),
        )
        for i in range(n_events)
    ]
    store: EventStore = FakeStore(events)
    result = await Pipeline(store, FakeAIEngine(result=_VALID_AI_RESULT), clock=_CLOCK).analyze_ip_detailed(IP)
    assert isinstance(result, dict)
    # total_events in the result must reflect the cap, not the full n_events
    assert result["total_events"] == cap, (
        f"Expected total_events == {cap} (cap), got {result['total_events']}. "
        f"The detailed path must bound the event load to MAX_DETAILED_EVENTS."
    )


async def test_analyze_ip_detailed_cap_preserves_most_recent_events() -> None:
    """F1: when the cap fires, the most-recent events are kept (not oldest or arbitrary).

    We create cap + 1 events where the oldest event has a unique rule_id that should
    be dropped, and the most-recent cap events share a different rule_id.
    """
    cap = MAX_DETAILED_EVENTS
    base_ts = datetime(2026, 1, 1, tzinfo=timezone.utc)

    # Oldest event (will be dropped by the cap)
    old_event = make_event(
        source_ip=IP,
        action="BLOCK",
        rule_id="999999",  # unique old rule — should NOT appear after cap
        payload_snippet="old",
        timestamp=base_ts,
    )
    # cap most-recent events (all kept)
    recent_events = [
        make_event(
            source_ip=IP,
            action="BLOCK",
            rule_id="942100",
            payload_snippet="recent",
            timestamp=base_ts + timedelta(seconds=i + 1),
        )
        for i in range(cap)
    ]
    store: EventStore = FakeStore([old_event] + recent_events)
    fake_ai = _DescriptionCapturingAI()
    result = await Pipeline(store, fake_ai, clock=_CLOCK).analyze_ip_detailed(IP)  # type: ignore[arg-type]

    assert result["total_events"] == cap, (
        f"Expected cap ({cap}) events in result, got {result['total_events']}."
    )
    # The unique old rule_id must NOT appear in the samples (was outside the window)
    sample_rule_ids = {s["rule_id"] for s in fake_ai.captured_samples}
    assert "999999" not in sample_rule_ids, (
        "The oldest event (rule_id=999999) should have been excluded by the cap."
    )


async def test_analyze_ip_detailed_no_cap_when_under_limit() -> None:
    """F1: when total events are under MAX_DETAILED_EVENTS, ALL events are used."""
    # Use 3 events — well under the cap
    store: EventStore = FakeStore(_sqli_events(3))
    result = await Pipeline(store, FakeAIEngine(result=_VALID_AI_RESULT), clock=_CLOCK).analyze_ip_detailed(IP)
    assert result["total_events"] == 3, (
        "When events < MAX_DETAILED_EVENTS, all events must be used (no truncation)."
    )


async def test_analyze_ip_detailed_cap_returns_valid_result_structure() -> None:
    """F1: even when the cap fires, the result dict retains all required v1 fields."""
    cap = MAX_DETAILED_EVENTS
    n_events = cap + 100
    events = [
        make_event(
            source_ip=IP,
            action="BLOCK",
            rule_id="942100",
            payload_snippet="' OR '1'='1",
            timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=i),
        )
        for i in range(n_events)
    ]
    store: EventStore = FakeStore(events)
    result = await Pipeline(store, FakeAIEngine(result=_VALID_AI_RESULT), clock=_CLOCK).analyze_ip_detailed(IP)
    for key in ("score", "threat_level", "total_events", "blocked_events",
                "attack_types", "source_ip"):
        assert key in result, f"Missing required v1 field after cap: {key!r}"
    assert result["score"] > 0, "Score must be non-zero with blocked SQLi events."


# ---------------------------------------------------------------------------
# F2 (broad except → logger.exception): AI failure logs at exception level
# ---------------------------------------------------------------------------


class _AvailableButThrowsAI:
    """AI engine that reports itself available but throws during analyze_detailed.

    Models a misbehaving engine implementation (e.g. returns None, throws from
    inside the model) — distinct from is_available()=False (engine unreachable).
    F2 tests this case: the exception must surface as logger.exception (ERROR).
    """

    def __init__(self) -> None:
        self.detailed_calls: int = 0
        self.concise_calls: int = 0

    async def is_available(self) -> bool:
        return True  # engine claims it is up…

    async def analyze_concise(self, **kwargs: Any) -> dict[str, Any]:  # type: ignore[override]
        self.concise_calls += 1
        return {"threat_level": "LOW", "confidence": 0.0}

    async def analyze_detailed(  # type: ignore[override]
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
        self.detailed_calls += 1
        raise RuntimeError("model returned None")  # …but blows up on the call


async def test_analyze_ip_detailed_ai_failure_logs_at_exception_level(
    caplog: Any,
) -> None:
    """F2: AI engine exception must be logged at ERROR level via logger.exception.

    logger.exception() logs at ERROR and attaches the traceback.  This test asserts
    that a RuntimeError raised during analyze_detailed appears in the log at ERROR
    level, so a misbehaving engine implementation (e.g. returns None, throws from
    inside the model) is visible during development.  The result must still be a
    valid rules-only dict (graceful degradation is preserved).

    Note: this tests the case where is_available()=True but the call throws —
    distinct from is_available()=False (engine offline; issue #313 fix 1), which
    skips the call entirely and stamps ai_status='unavailable'.
    """
    store: EventStore = FakeStore(_sqli_events(3))
    ai = _AvailableButThrowsAI()

    with caplog.at_level(logging.ERROR, logger="firewatch.pipeline"):
        result = await Pipeline(store, ai, clock=_CLOCK).analyze_ip_detailed(IP)  # type: ignore[arg-type]

    # Graceful degradation still holds
    assert isinstance(result, dict)
    assert "error" not in result  # did not return the empty-events error
    assert result["score"] == 30  # rules-only: sqli_BLOCK(20)+persistence(10)=30 (#651)

    # The failure must have been logged at ERROR (logger.exception logs at ERROR)
    error_records = [
        r for r in caplog.records
        if r.levelno == logging.ERROR and "detailed analysis failed" in r.message
    ]
    assert error_records, (
        "Expected an ERROR-level log record from logger.exception() when AI fails. "
        "Replace logger.warning() with logger.exception() (F2)."
    )


# ---------------------------------------------------------------------------
# Issue #268 (include_ai=False fast path — staged honest AI loading)
# ---------------------------------------------------------------------------


async def test_analyze_ip_detailed_include_ai_false_skipped_status() -> None:
    """I268-1: include_ai=False → ai_status='skipped', zero AI calls.

    The server MUST stamp ai_status='skipped' when the caller explicitly opted out
    of AI — it must NEVER claim success when the engine was not called (ADR-0035).
    The AI engine must not be invoked at all (no analyze_detailed call).
    """
    fake_ai = FakeAIEngine(result=_VALID_AI_RESULT)
    store: EventStore = FakeStore(_sqli_events(3))
    result = await Pipeline(store, fake_ai, clock=_CLOCK).analyze_ip_detailed(IP, include_ai=False)
    assert result.get("ai_status") == "skipped", (
        f"Expected ai_status='skipped' for include_ai=False, got {result.get('ai_status')!r}."
    )
    assert fake_ai.detailed_calls == 0, (
        f"AI engine must NOT be called when include_ai=False; got {fake_ai.detailed_calls} calls."
    )


async def test_analyze_ip_detailed_include_ai_false_rules_only_score() -> None:
    """I268-2: include_ai=False → rules-only score (no AI boost even if engine available).

    3 blocked SQLi: sqli_BLOCK(20)+persistence(10)=30 (#651).
    Even though a valid AI result is configured, no boost should be applied.
    Old math (removed): +40 sqli + 3 blocked = 43.
    """
    store: EventStore = FakeStore(_sqli_events(3))
    result = await Pipeline(store, FakeAIEngine(result=_VALID_AI_RESULT), clock=_CLOCK).analyze_ip_detailed(
        IP, include_ai=False
    )
    assert result["score"] == 30, (
        f"Expected rules-only score 30 when include_ai=False, got {result['score']}. (#651)"
    )


async def test_analyze_ip_detailed_include_ai_false_v1_fields_present() -> None:
    """I268-3: include_ai=False → all v1 rule-derived fields still present.

    Skipping AI does not remove the rule-derived fields. score, threat_level,
    total_events, blocked_events, attack_types, source_ip must all be present.
    """
    store: EventStore = FakeStore(_sqli_events(3))
    result = await Pipeline(store, FakeAIEngine(result=_VALID_AI_RESULT), clock=_CLOCK).analyze_ip_detailed(
        IP, include_ai=False
    )
    for key in ("score", "threat_level", "total_events", "blocked_events",
                "attack_types", "source_ip"):
        assert key in result, (
            f"v1 field '{key}' missing from include_ai=False result (I268-3)."
        )


async def test_analyze_ip_detailed_include_ai_true_default_unchanged() -> None:
    """I268-4: include_ai=True (the default) still calls AI exactly once — no regression.

    The default path is unchanged; this test guards that the include_ai flag
    does not break the standard full-analysis path.
    """
    fake_ai = FakeAIEngine(result=_VALID_AI_RESULT)
    store: EventStore = FakeStore(_sqli_events(3))
    result = await Pipeline(store, fake_ai, clock=_CLOCK).analyze_ip_detailed(IP)  # default include_ai=True
    assert fake_ai.detailed_calls == 1, (
        f"Expected exactly 1 AI call with include_ai=True (default), got {fake_ai.detailed_calls}."
    )
    assert result.get("ai_status") != "skipped", (
        "ai_status must not be 'skipped' when include_ai=True."
    )
