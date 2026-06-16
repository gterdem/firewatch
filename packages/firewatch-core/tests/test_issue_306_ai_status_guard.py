"""Tests for NB-3 (issue #306): ai_status='skipped' cannot be claimed by AI output.

EARS criteria:
  NB3-1 (Unwanted): When include_ai=True and AI returns ai_status='skipped', the pipeline
         must strip/reject that value — 'skipped' is a pipeline-only stamp.
  NB3-2 (Unwanted): _validate_detailed_schema raises ValueError when ai_status='skipped'
         is present in the AI dict, so the OpenAIEngine fallback path triggers.
  NB3-3 (Ubiquitous): ai_status='skipped' from AI output on include_ai=True path does not
         propagate to the caller; the result must not carry ai_status='skipped'.
  NB3-4 (State-driven): On include_ai=False, the pipeline still stamps ai_status='skipped'
         correctly (regression guard — the fix must not break the legitimate skipped path).
"""
from __future__ import annotations

import pytest

from firewatch_core.adapters.ai_openai import _validate_detailed_schema
from firewatch_core.pipeline import Pipeline
from firewatch_sdk import EventStore

from _fakes import FakeAIEngine, FakeStore, make_event

IP = "203.0.113.5"

# A valid detailed AI result with ai_status='ok'
_VALID_AI_RESULT = {
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

# Malicious AI dict: claims ai_status='skipped' (only the pipeline may stamp this)
_MALICIOUS_AI_SKIPPED = {
    **_VALID_AI_RESULT,
    "ai_status": "skipped",
}


def _sqli_events(n: int = 3) -> list:
    return [
        make_event(action="BLOCK", rule_id="942100", payload_snippet="' OR '1'='1")
        for _ in range(n)
    ]


# ---------------------------------------------------------------------------
# NB3-2: _validate_detailed_schema rejects ai_status='skipped'
# ---------------------------------------------------------------------------


def test_validate_detailed_schema_rejects_ai_status_skipped() -> None:
    """NB3-2: _validate_detailed_schema raises ValueError for ai_status='skipped'.

    The value 'skipped' is reserved exclusively for the pipeline to stamp on the
    include_ai=False path.  A misbehaving LLM returning this value must be caught
    at the schema validation layer so the fallback path triggers.
    """
    with pytest.raises(ValueError, match="skipped"):
        _validate_detailed_schema(_MALICIOUS_AI_SKIPPED)


def test_validate_detailed_schema_accepts_ai_status_ok() -> None:
    """NB3-2 (regression): ai_status='ok' must continue to pass validation."""
    # Must not raise
    _validate_detailed_schema(_VALID_AI_RESULT)


def test_validate_detailed_schema_accepts_absent_ai_status() -> None:
    """NB3-2 (regression): ai_status is optional — absent must pass validation."""
    data_no_status = {k: v for k, v in _VALID_AI_RESULT.items() if k != "ai_status"}
    # Must not raise
    _validate_detailed_schema(data_no_status)


# ---------------------------------------------------------------------------
# NB3-1 / NB3-3: pipeline strips ai_status='skipped' from AI output on include_ai=True
# ---------------------------------------------------------------------------


async def test_pipeline_overrides_ai_status_skipped_from_ai_output() -> None:
    """NB3-1 / NB3-3: malicious AI dict with ai_status='skipped' is overridden on include_ai=True.

    The pipeline must not propagate ai_status='skipped' from AI output to the caller.
    Only the pipeline's own include_ai=False branch may stamp that value.  The
    defence-in-depth guard stamps 'unavailable' to keep the API field present
    (required by the TS client) while correctly signalling degradation.
    """
    fake_ai = FakeAIEngine(result=_MALICIOUS_AI_SKIPPED)
    store: EventStore = FakeStore(_sqli_events())
    result = await Pipeline(store, fake_ai).analyze_ip_detailed(IP, include_ai=True)

    assert result.get("ai_status") != "skipped", (
        f"Pipeline must not propagate ai_status='skipped' from AI output. "
        f"Got ai_status={result.get('ai_status')!r}. "
        "NB-3 (issue #306): only the pipeline may stamp 'skipped'."
    )
    # The field must be present — 'unavailable' keeps the API contract intact.
    assert "ai_status" in result, (
        "ai_status must not be absent after the defence-in-depth guard fires. "
        "NB-3: stamp 'unavailable', not pop."
    )
    assert result["ai_status"] == "unavailable", (
        f"Expected ai_status='unavailable' after defence-in-depth guard, "
        f"got {result['ai_status']!r}."
    )


async def test_pipeline_ai_status_skipped_from_ai_does_not_affect_score() -> None:
    """NB3-3: when AI returns ai_status='skipped', score must still be computed correctly.

    The pipeline degrades gracefully: the malicious status is stripped and the
    result uses the rules-only or properly AI-boosted score (not corrupted).
    """
    fake_ai = FakeAIEngine(result=_MALICIOUS_AI_SKIPPED)
    store: EventStore = FakeStore(_sqli_events())
    result = await Pipeline(store, fake_ai).analyze_ip_detailed(IP, include_ai=True)

    # The score must be a valid integer (not zero, not errored)
    assert isinstance(result.get("score"), int), (
        f"score must be an int, got {result.get('score')!r}"
    )
    assert result["score"] > 0, "Score must be non-zero with blocked SQLi events."


# ---------------------------------------------------------------------------
# NB3-4: include_ai=False still stamps ai_status='skipped' correctly (regression)
# ---------------------------------------------------------------------------


async def test_pipeline_include_ai_false_still_stamps_skipped() -> None:
    """NB3-4: the legitimate include_ai=False path still stamps ai_status='skipped'.

    The NB-3 fix must not break the intended behavior: when the caller opts out
    of AI with include_ai=False, the pipeline must still stamp 'skipped'.
    """
    fake_ai = FakeAIEngine(result=_VALID_AI_RESULT)
    store: EventStore = FakeStore(_sqli_events())
    result = await Pipeline(store, fake_ai).analyze_ip_detailed(IP, include_ai=False)

    assert result.get("ai_status") == "skipped", (
        f"include_ai=False must still produce ai_status='skipped'. "
        f"Got ai_status={result.get('ai_status')!r}. "
        "NB-3 fix must not regress the legitimate skipped path."
    )
    # AI engine must NOT have been called
    assert fake_ai.detailed_calls == 0, (
        "AI engine must not be called when include_ai=False."
    )
