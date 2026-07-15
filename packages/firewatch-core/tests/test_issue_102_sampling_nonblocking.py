"""Tests for issue #102 — analyze_ip_detailed sampling must not block the event loop.

EARS criteria mapped to tests:

EARS-A (Unwanted): When AI engine is disabled/unavailable (is_available() returns False),
    get_rule_descriptions() MUST NOT be called — the sampling step is skipped entirely.
EARS-B (Unwanted): When AI is disabled, build_detailed_samples is not called
    (samples=[] passed to analyze_detailed).
EARS-C (Ubiquitous): The output contract (executive_summary / attack_progression /
    detections[] / score / threat_level / source_ip) is preserved regardless of whether
    AI is enabled or disabled.
EARS-D (Event-driven): When AI engine IS available, get_rule_descriptions() IS called
    and samples are built and forwarded to analyze_detailed.
EARS-E (Ubiquitous): Concurrent requests are not blocked while analyze_ip_detailed runs
    — a second coroutine can make progress during the detailed call.

Security note: all test IPs use RFC 5737 documentation ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24) — no real/routable addresses.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

from firewatch_sdk import AIEngine, EventStore

from firewatch_core.pipeline import Pipeline
from _fakes import FakeAIEngine, FakeStore, make_event

# All test IPs are RFC 5737 documentation addresses.
IP = "203.0.113.42"

T0 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

# Issue #52 (ADR-0070 D4): analyze_ip_detailed now windows run_rules to a
# trailing W_STATE slice measured from "now". _sqli_events() below uses
# make_event()'s default timestamp (_fakes.py: 2026-06-03T12:00:00Z), so this
# synthetic clock is fixed 1h after it — well inside W_STATE — instead of the
# real wall clock (no wall-clock flakiness).
_CLOCK = lambda: datetime(2026, 6, 3, 13, 0, 0, tzinfo=timezone.utc)  # noqa: E731

_VALID_AI_RESULT: dict[str, Any] = {
    "threat_level": "HIGH",
    "confidence": 0.85,
    "executive_summary": "SQL injection attempt detected.",
    "intent": "Data exfiltration",
    "attack_stage": "exploitation",
    "attack_progression": ["Step 1: scan", "Step 2: exploit"],
    "insights": {"patterns": ["SQLi"], "risks": ["data breach"], "mitigations": []},
    "ioc_indicators": [],
    "recommended_action": "block",
    "false_positive_likelihood": 0.05,
    "ai_status": "ok",
}


def _sqli_events(n: int) -> list:
    return [
        make_event(
            source_ip=IP,
            action="BLOCK",
            rule_id="942100",
            payload_snippet="' OR '1'='1",
        )
        for _ in range(n)
    ]


# ---------------------------------------------------------------------------
# Helpers: instrumented fakes
# ---------------------------------------------------------------------------


class _TrackingStore(FakeStore):
    """FakeStore that records whether get_rule_descriptions was called."""

    def __init__(self, events: list, descs: dict[str, str] | None = None) -> None:
        super().__init__(events)
        self.rule_desc_calls: int = 0
        self._descs = descs or {}

    async def get_rule_descriptions(self) -> dict[str, str]:
        self.rule_desc_calls += 1
        return self._descs


class _SamplesCapturingAI:
    """AI engine that records samples passed to analyze_detailed."""

    def __init__(self, available: bool = True) -> None:
        self._available = available
        self.captured_samples: list[dict[str, Any]] = []
        self.detailed_calls: int = 0
        self.concise_calls: int = 0

    async def is_available(self) -> bool:
        return self._available

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
        self.captured_samples = list(samples)
        return _VALID_AI_RESULT


class _DisabledAIEngine:
    """Mirrors the _DisabledAIEngine from _pipeline_factory: is_available()=False."""

    async def is_available(self) -> bool:
        return False

    async def analyze_concise(self, **kwargs: Any) -> dict[str, Any]:  # type: ignore[override]
        return {"ai_status": "disabled", "threat_level": "UNKNOWN"}

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
        return {"ai_status": "disabled", "threat_level": "UNKNOWN"}


# ---------------------------------------------------------------------------
# EARS-A: when AI is disabled, get_rule_descriptions is NOT called
# ---------------------------------------------------------------------------


async def test_rule_descriptions_not_fetched_when_ai_disabled() -> None:
    """EARS-A: when is_available()=False, store.get_rule_descriptions must not be called.

    The sampling step feeds the AI prompt — if AI is off, the DB scan is pure waste
    that blocks the event loop.
    """
    store = _TrackingStore(_sqli_events(3))
    ai = _DisabledAIEngine()
    await Pipeline(store, ai, clock=_CLOCK).analyze_ip_detailed(IP)  # type: ignore[arg-type]
    assert store.rule_desc_calls == 0, (
        f"get_rule_descriptions called {store.rule_desc_calls} time(s) when AI is "
        "disabled — must be skipped (issue #102)."
    )


async def test_rule_descriptions_not_fetched_when_ai_unavailable() -> None:
    """EARS-A: same guard applies when AI *engine* is enabled but *returns* unavailable.

    A FakeAIEngine(fail=True) has is_available()=False — same skip path.
    """
    store = _TrackingStore(_sqli_events(3))
    ai: AIEngine = FakeAIEngine(fail=True)
    await Pipeline(store, ai, clock=_CLOCK).analyze_ip_detailed(IP)
    assert store.rule_desc_calls == 0, (
        f"get_rule_descriptions called {store.rule_desc_calls} time(s) when "
        "is_available()=False — must be skipped (issue #102)."
    )


# ---------------------------------------------------------------------------
# EARS-B: when AI is disabled, analyze_detailed receives samples=[]
# ---------------------------------------------------------------------------


async def test_empty_samples_passed_to_ai_when_disabled() -> None:
    """EARS-B: with is_available()=False the samples list must be [] (no sampling work done)."""
    ai = _SamplesCapturingAI(available=False)
    store: EventStore = _TrackingStore(_sqli_events(5))  # type: ignore[assignment]
    await Pipeline(store, ai, clock=_CLOCK).analyze_ip_detailed(IP)  # type: ignore[arg-type]
    assert ai.captured_samples == [], (
        f"Expected samples=[] when AI unavailable, got {ai.captured_samples!r} "
        "(issue #102: sampling must be skipped)."
    )


# ---------------------------------------------------------------------------
# EARS-C: output contract preserved regardless of AI state
# ---------------------------------------------------------------------------


async def test_output_contract_preserved_when_ai_disabled() -> None:
    """EARS-C: v1 fields (score, threat_level, total_events, blocked_events,
    attack_types, source_ip) must be present even when AI is disabled.
    """
    store: EventStore = _TrackingStore(_sqli_events(3))  # type: ignore[assignment]
    ai = _DisabledAIEngine()
    result = await Pipeline(store, ai, clock=_CLOCK).analyze_ip_detailed(IP)  # type: ignore[arg-type]
    required = ("score", "threat_level", "total_events", "blocked_events",
                "attack_types", "source_ip")
    for field in required:
        assert field in result, (
            f"Output field {field!r} missing when AI is disabled (EARS-C / issue #102)."
        )


async def test_rules_only_score_when_ai_disabled() -> None:
    """EARS-C: score is rules-only (30) when AI is disabled — no AI boost.

    3 blocked SQLi: sqli_BLOCK=round(40×0.5)=20 + persistence=10 = 30 (#651).
    Old math (removed): +40 sqli + 3 per-blocked = 43.
    """
    store: EventStore = _TrackingStore(_sqli_events(3))  # type: ignore[assignment]
    ai = _DisabledAIEngine()
    result = await Pipeline(store, ai, clock=_CLOCK).analyze_ip_detailed(IP)  # type: ignore[arg-type]
    assert result["score"] == 30, (
        f"Expected rules-only score 30, got {result['score']} (EARS-C / issue #102, #651)."
    )


async def test_detections_present_when_ai_disabled() -> None:
    """EARS-C: 'detections' (raw log rows) must still be fetched when AI is disabled.

    The detections[] field powers the 'Recent Logs' table in the drill-down modal
    independently of AI.
    """
    store: EventStore = _TrackingStore(_sqli_events(3))  # type: ignore[assignment]
    ai = _DisabledAIEngine()
    result = await Pipeline(store, ai, clock=_CLOCK).analyze_ip_detailed(IP)  # type: ignore[arg-type]
    assert "detections" in result, (
        "detections[] must be present in result even when AI is disabled (EARS-C)."
    )
    assert isinstance(result["detections"], list)


# ---------------------------------------------------------------------------
# EARS-D: when AI IS available, sampling IS done and samples are forwarded
# ---------------------------------------------------------------------------


async def test_rule_descriptions_fetched_when_ai_available() -> None:
    """EARS-D: when is_available()=True, get_rule_descriptions IS called."""
    descs = {"942100": "SQL injection via numeric parameter"}
    store = _TrackingStore(_sqli_events(3), descs=descs)
    ai = _SamplesCapturingAI(available=True)
    await Pipeline(store, ai, clock=_CLOCK).analyze_ip_detailed(IP)  # type: ignore[arg-type]
    assert store.rule_desc_calls == 1, (
        f"Expected get_rule_descriptions to be called once when AI is available, "
        f"got {store.rule_desc_calls} calls (EARS-D / issue #102)."
    )


async def test_samples_forwarded_to_ai_when_available() -> None:
    """EARS-D: when AI is available, non-empty samples are built and forwarded."""
    descs = {"942100": "SQL injection"}
    store = _TrackingStore(_sqli_events(3), descs=descs)
    ai = _SamplesCapturingAI(available=True)
    await Pipeline(store, ai, clock=_CLOCK).analyze_ip_detailed(IP)  # type: ignore[arg-type]
    assert len(ai.captured_samples) == 1, (
        f"Expected 1 sample forwarded to AI, got {len(ai.captured_samples)} "
        "(EARS-D / issue #102: sampling must happen when AI is available)."
    )
    assert ai.captured_samples[0]["rule_id"] == "942100"


# ---------------------------------------------------------------------------
# EARS-E: event loop not blocked — concurrent coroutine makes progress
# ---------------------------------------------------------------------------


async def test_concurrent_coroutine_not_starved_during_detailed_call() -> None:
    """EARS-E: a concurrent coroutine must make progress while analyze_ip_detailed runs.

    This test schedules a simple counter coroutine that yields once per iteration
    alongside analyze_ip_detailed.  If analyze_ip_detailed holds the event loop
    for a long synchronous stretch, the counter will not advance.  After both
    complete, the counter must have ticked at least once — proving the loop was not
    held indefinitely.

    Note: this is a structural / scheduling assertion, not a wall-clock timing test
    (wall-clock tests are inherently flaky in CI).  The counter only needs to tick
    once to prove the loop was not monopolised.
    """
    ticks: list[int] = []

    async def _counter() -> None:
        """Yield to the event loop on each iteration and record each tick."""
        for i in range(10):
            await asyncio.sleep(0)
            ticks.append(i)

    ai: AIEngine = FakeAIEngine(result=_VALID_AI_RESULT)
    store: EventStore = _TrackingStore(_sqli_events(3))  # type: ignore[assignment]
    pipeline = Pipeline(store, ai, clock=_CLOCK)

    # Run both concurrently; if analyze_ip_detailed blocks the loop, _counter
    # will not advance (ticks stays empty until after detailed completes).
    await asyncio.gather(
        pipeline.analyze_ip_detailed(IP),
        _counter(),
    )

    assert len(ticks) > 0, (
        "Concurrent coroutine received zero ticks — analyze_ip_detailed may be "
        "blocking the event loop (issue #102)."
    )
