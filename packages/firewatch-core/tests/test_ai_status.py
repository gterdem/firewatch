"""Tests for ``resolve_ai_status`` — the ONE stamping authority (ADR-0066, #39/#40).

EARS criteria mapped to tests:

EARS-1 (Ubiquitous) — WHEN the caller opts out, the result SHALL be 'skipped',
        regardless of every other input (highest precedence).
        -> test_caller_opted_out_always_skipped (exhaustive over the other 4 booleans)

EARS-2 (Ubiquitous) — WHEN AI is administratively disabled (and the caller did not
        opt out), the result SHALL be 'disabled'.
        -> test_admin_disabled_when_not_opted_out

EARS-3 (Ubiquitous) — WHEN the engine is unreachable (and not opted out / not admin
        disabled), the result SHALL be 'unavailable'.
        -> test_engine_unavailable

EARS-4 (Ubiquitous) — WHEN the engine is reachable but there is nothing to send,
        the result SHALL be 'no_input' — never 'active' (the core honesty bug).
        -> test_no_input_when_engine_available_but_no_samples

EARS-5 (Ubiquitous) — WHEN the engine ran and returned a real verdict, the result
        SHALL be 'active'.
        -> test_active_on_successful_engine_result
        -> test_active_even_when_engine_result_lacks_ai_status_key (real LLM output
           usually omits the internal 'ok' discriminator entirely)

EARS-6 (Unwanted) — WHEN the engine call failed/errored (engine_result=None) or
        returned its own fallback envelope (ai_status='unavailable'), the result
        SHALL be 'unavailable', never 'active'.
        -> test_unavailable_on_none_engine_result
        -> test_unavailable_on_fallback_envelope

EARS-7 (Ubiquitous) — the function is exhaustive: for every reachable combination
        of inputs, the return value is one of the five closed-vocabulary literals.
        -> test_exhaustive_truth_table_only_produces_closed_vocabulary
"""
from __future__ import annotations

import itertools
from typing import Any

from firewatch_core.ai_status import resolve_ai_status

_CLOSED_VOCAB = {"active", "disabled", "skipped", "no_input", "unavailable"}


# ---------------------------------------------------------------------------
# EARS-1: caller_opted_out has the highest precedence
# ---------------------------------------------------------------------------


def test_caller_opted_out_always_skipped() -> None:
    """EARS-1: caller_opted_out=True -> 'skipped' regardless of every other input."""
    bools = (True, False)
    for admin_disabled, engine_available, had_input in itertools.product(bools, bools, bools):
        for engine_result in (None, {}, {"ai_status": "unavailable"}):
            status = resolve_ai_status(
                caller_opted_out=True,
                admin_disabled=admin_disabled,
                engine_available=engine_available,
                had_input=had_input,
                engine_result=engine_result,
            )
            assert status == "skipped", (
                f"caller_opted_out=True must always yield 'skipped'; got {status!r} "
                f"for admin_disabled={admin_disabled}, engine_available={engine_available}, "
                f"had_input={had_input}, engine_result={engine_result!r}"
            )


# ---------------------------------------------------------------------------
# EARS-2: admin_disabled wins over everything except caller_opted_out
# ---------------------------------------------------------------------------


def test_admin_disabled_when_not_opted_out() -> None:
    """EARS-2: admin_disabled=True (not opted out) -> 'disabled' regardless of engine state."""
    bools = (True, False)
    for engine_available, had_input in itertools.product(bools, bools):
        for engine_result in (None, {}, {"ai_status": "unavailable"}):
            status = resolve_ai_status(
                caller_opted_out=False,
                admin_disabled=True,
                engine_available=engine_available,
                had_input=had_input,
                engine_result=engine_result,
            )
            assert status == "disabled", (
                f"admin_disabled=True (not opted out) must yield 'disabled'; got {status!r}"
            )


# ---------------------------------------------------------------------------
# EARS-3: engine unreachable
# ---------------------------------------------------------------------------


def test_engine_unavailable() -> None:
    """EARS-3: engine_available=False (not opted out, not admin disabled) -> 'unavailable'."""
    for had_input in (True, False):
        status = resolve_ai_status(
            caller_opted_out=False,
            admin_disabled=False,
            engine_available=False,
            had_input=had_input,
            engine_result=None,
        )
        assert status == "unavailable"


# ---------------------------------------------------------------------------
# EARS-4: no input -> 'no_input', never 'active' (the core honesty bug)
# ---------------------------------------------------------------------------


def test_no_input_when_engine_available_but_no_samples() -> None:
    """EARS-4: engine reachable but had_input=False -> 'no_input', never 'active'."""
    status = resolve_ai_status(
        caller_opted_out=False,
        admin_disabled=False,
        engine_available=True,
        had_input=False,
        engine_result=None,
    )
    assert status == "no_input"
    assert status != "active"


# ---------------------------------------------------------------------------
# EARS-5: engine ran and returned a real verdict -> 'active'
# ---------------------------------------------------------------------------


def test_active_on_successful_engine_result() -> None:
    """EARS-5: a real (non-fallback) engine envelope resolves to 'active'."""
    status = resolve_ai_status(
        caller_opted_out=False,
        admin_disabled=False,
        engine_available=True,
        had_input=True,
        engine_result={"threat_level": "HIGH", "confidence": 0.8, "ai_status": "ok"},
    )
    assert status == "active"


def test_active_even_when_engine_result_lacks_ai_status_key() -> None:
    """EARS-5: real LLM output typically has no 'ai_status' key at all -> still 'active'.

    The closed concise/detailed prompt schema does not require the model to
    self-report an 'ai_status' field; only the fallback envelope sets it
    (to 'unavailable'). Absence must not be misread as a fault.
    """
    status = resolve_ai_status(
        caller_opted_out=False,
        admin_disabled=False,
        engine_available=True,
        had_input=True,
        engine_result={"threat_level": "HIGH", "confidence": 0.8},
    )
    assert status == "active"


# ---------------------------------------------------------------------------
# EARS-6: engine call failed / returned its own fallback envelope -> 'unavailable'
# ---------------------------------------------------------------------------


def test_unavailable_on_none_engine_result() -> None:
    """EARS-6: engine_result=None (call raised, caught by the caller) -> 'unavailable'."""
    status = resolve_ai_status(
        caller_opted_out=False,
        admin_disabled=False,
        engine_available=True,
        had_input=True,
        engine_result=None,
    )
    assert status == "unavailable"
    assert status != "active"


def test_unavailable_on_fallback_envelope() -> None:
    """EARS-6: engine's own fallback envelope (ai_status='unavailable') -> 'unavailable'."""
    status = resolve_ai_status(
        caller_opted_out=False,
        admin_disabled=False,
        engine_available=True,
        had_input=True,
        engine_result={"threat_level": "UNKNOWN", "confidence": 0.0, "ai_status": "unavailable"},
    )
    assert status == "unavailable"


# ---------------------------------------------------------------------------
# EARS-7: exhaustive — only the five closed-vocabulary values are ever produced
# ---------------------------------------------------------------------------


def test_exhaustive_truth_table_only_produces_closed_vocabulary() -> None:
    """EARS-7: every combination of inputs yields one of the five closed values.

    This is the "exhaustive truth-table unit test" called for by ADR-0066 /
    issue #39's module sketch.
    """
    bools = (True, False)
    engine_results: list[dict[str, Any] | None] = [
        None,
        {},
        {"ai_status": "unavailable"},
        {"ai_status": "ok"},
        {"threat_level": "LOW", "confidence": 0.1},
    ]
    seen: set[str] = set()
    for caller_opted_out, admin_disabled, engine_available, had_input in itertools.product(
        bools, bools, bools, bools
    ):
        for engine_result in engine_results:
            status = resolve_ai_status(
                caller_opted_out=caller_opted_out,
                admin_disabled=admin_disabled,
                engine_available=engine_available,
                had_input=had_input,
                engine_result=engine_result,
            )
            assert status in _CLOSED_VOCAB, (
                f"resolve_ai_status produced a value outside the closed vocabulary: "
                f"{status!r} for caller_opted_out={caller_opted_out}, "
                f"admin_disabled={admin_disabled}, engine_available={engine_available}, "
                f"had_input={had_input}, engine_result={engine_result!r}"
            )
            seen.add(status)
    # All five values must be reachable somewhere in the table (no dead branch).
    assert seen == _CLOSED_VOCAB, f"Not every closed-vocabulary value was reachable: {seen!r}"
