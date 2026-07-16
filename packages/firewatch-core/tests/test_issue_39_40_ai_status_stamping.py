"""Tests for issues #39/#40 — honest AI status through the real pipeline paths.

``test_ai_status.py`` exhaustively unit-tests the pure ``resolve_ai_status``
function in isolation; this file proves both ``Pipeline.analyze_ip`` (concise)
and ``Pipeline.analyze_ip_detailed`` wire the ``DisabledAIEngine`` adapter
(core-owned, relocated from firewatch-cli by issue #39) through it correctly,
end to end.

EARS criteria mapped to tests:

EARS-1 (issue #39 AC1) — WHEN AI is disabled by configuration (admin-disabled
        engine wired) and any analysis is served, the payload SHALL carry
        ai_status="disabled" — never "unavailable" and never treated as a
        fault. Off-by-choice must never be reported as broken.
        -> test_concise_admin_disabled_reports_disabled_never_fault
        -> test_detailed_admin_disabled_reports_disabled_never_fault

EARS-2 (issue #40 AC4) — WHEN engine construction failed (fault=True) while
        ai_enabled=true, the payload SHALL carry ai_status="unavailable"
        (a fault), never "disabled" (a choice) — even though both engines
        never contact an inference endpoint.
        -> test_concise_fault_engine_reports_unavailable_never_disabled
        -> test_detailed_fault_engine_reports_unavailable_never_disabled

EARS-3 (issue #39 AC3) — WHEN the caller opts out (use_ai=False /
        include_ai=False), the payload SHALL carry ai_status="skipped".
        -> test_concise_caller_opt_out_is_skipped
        -> test_detailed_caller_opt_out_is_skipped

EARS-4 (issue #39 AC4) — WHEN AI would run but sampling yields nothing to
        analyze, the concise payload SHALL carry ai_status="no_input" —
        never "active" (the core honesty bug this ADR fixes).
        -> test_concise_no_samples_is_no_input_never_active

EARS-5 — a disabled/fault engine never dials an inference endpoint (both
        adapters are fully inert regardless of mode).
        -> test_disabled_engine_never_calls_http_either_mode

Security note: all IPs are RFC 5737 documentation addresses.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from firewatch_core.adapters.ai_disabled import DisabledAIEngine
from firewatch_core.pipeline import Pipeline

from _fakes import FakeStore, make_event

# make_event()'s default source_ip (_fakes.py) — events must match the IP
# queried below or FakeStore.get_by_ip returns [] and the early-empty branch
# masks every scenario behind its own ai_status default.
IP = "203.0.113.5"
T0 = datetime(2026, 6, 3, 12, 0, 0, tzinfo=timezone.utc)
_CLOCK = lambda: T0 + timedelta(hours=1)  # noqa: E731


def _sqli_events(n: int = 3) -> list:
    return [
        make_event(
            source_ip=IP, action="BLOCK", rule_id="942100", payload_snippet="' OR '1'='1"
        )
        for _ in range(n)
    ]


# ---------------------------------------------------------------------------
# EARS-1: admin-disabled -> 'disabled', never a fault label
# ---------------------------------------------------------------------------


async def test_concise_admin_disabled_reports_disabled_never_fault():
    """Off-by-choice (admin-disabled engine) is never reported as broken (concise)."""
    store = FakeStore(_sqli_events(3))
    engine = DisabledAIEngine()  # default: fault=False -> administratively_disabled=True
    score = await Pipeline(store, engine, clock=_CLOCK).analyze_ip(IP)
    assert score.ai_status == "disabled"
    assert score.ai_status != "unavailable", (
        "A deliberately-off engine must never be reported as a fault (issue #39)."
    )


async def test_detailed_admin_disabled_reports_disabled_never_fault():
    """Off-by-choice (admin-disabled engine) is never reported as broken (detailed)."""
    store = FakeStore(_sqli_events(3))
    engine = DisabledAIEngine()
    result = await Pipeline(store, engine, clock=_CLOCK).analyze_ip_detailed(IP)
    assert result["ai_status"] == "disabled"
    assert result["ai_status"] != "unavailable", (
        "A deliberately-off engine must never be reported as a fault (issue #39)."
    )


# ---------------------------------------------------------------------------
# EARS-2: construction-failure fault engine -> 'unavailable', never 'disabled'
# ---------------------------------------------------------------------------


async def test_concise_fault_engine_reports_unavailable_never_disabled():
    """Issue #40 AC4: a FAULT engine (construction failed) reports 'unavailable' (concise)."""
    store = FakeStore(_sqli_events(3))
    engine = DisabledAIEngine(fault=True)
    score = await Pipeline(store, engine, clock=_CLOCK).analyze_ip(IP)
    assert score.ai_status == "unavailable"
    assert score.ai_status != "disabled", (
        "A construction fault must never be labeled 'disabled' — that is a choice, "
        "this is a fault (issue #40 AC4)."
    )


async def test_detailed_fault_engine_reports_unavailable_never_disabled():
    """Issue #40 AC4: a FAULT engine (construction failed) reports 'unavailable' (detailed)."""
    store = FakeStore(_sqli_events(3))
    engine = DisabledAIEngine(fault=True)
    result = await Pipeline(store, engine, clock=_CLOCK).analyze_ip_detailed(IP)
    assert result["ai_status"] == "unavailable"
    assert result["ai_status"] != "disabled"


# ---------------------------------------------------------------------------
# EARS-3: caller opt-out -> 'skipped'
# ---------------------------------------------------------------------------


async def test_concise_caller_opt_out_is_skipped():
    """use_ai=False (caller opt-out) -> ai_status='skipped', even with a live engine."""
    from _fakes import FakeAIEngine

    store = FakeStore(_sqli_events(3))
    fake_ai = FakeAIEngine()
    score = await Pipeline(store, fake_ai, clock=_CLOCK).analyze_ip(IP, use_ai=False)
    assert score.ai_status == "skipped"
    assert fake_ai.concise_calls == 0


async def test_detailed_caller_opt_out_is_skipped():
    """include_ai=False (caller opt-out) -> ai_status='skipped', even with a live engine."""
    from _fakes import FakeAIEngine

    store = FakeStore(_sqli_events(3))
    fake_ai = FakeAIEngine()
    result = await Pipeline(store, fake_ai, clock=_CLOCK).analyze_ip_detailed(
        IP, include_ai=False
    )
    assert result["ai_status"] == "skipped"
    assert fake_ai.detailed_calls == 0


# ---------------------------------------------------------------------------
# EARS-4: no samples -> 'no_input', never 'active' (concise honesty bug)
# ---------------------------------------------------------------------------


async def test_concise_no_samples_is_no_input_never_active():
    """Engine available, caller wants AI, but no BLOCK/DROP events -> 'no_input'.

    build_samples() only groups BLOCK/DROP events with a rule_id — an IP with
    only ALLOW/LOG events yields zero samples, so the engine must never be
    called and 'active' must never be claimed for a call that never happened.
    """
    from _fakes import FakeAIEngine

    store = FakeStore([make_event(source_ip=IP, action="ALLOW", rule_id=None)])
    fake_ai = FakeAIEngine()
    score = await Pipeline(store, fake_ai, clock=_CLOCK).analyze_ip(IP)
    assert score.ai_status == "no_input"
    assert score.ai_status != "active"
    assert fake_ai.concise_calls == 0, (
        "The engine must never be called when there are no samples to analyze."
    )


# ---------------------------------------------------------------------------
# EARS-5: both DisabledAIEngine modes are fully inert (no HTTP ever)
# ---------------------------------------------------------------------------


async def test_disabled_engine_never_calls_http_either_mode():
    """Neither DisabledAIEngine() nor DisabledAIEngine(fault=True) ever dials HTTP."""
    store = FakeStore(_sqli_events(3))
    with patch("httpx.AsyncClient") as mock_client:
        await Pipeline(store, DisabledAIEngine(), clock=_CLOCK).analyze_ip(IP)
        await Pipeline(store, DisabledAIEngine(fault=True), clock=_CLOCK).analyze_ip(IP)
        await Pipeline(store, DisabledAIEngine(), clock=_CLOCK).analyze_ip_detailed(IP)
        await Pipeline(store, DisabledAIEngine(fault=True), clock=_CLOCK).analyze_ip_detailed(IP)
    mock_client.assert_not_called()
