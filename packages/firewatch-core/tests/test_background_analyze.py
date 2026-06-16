"""Tests for Pipeline.background_analyze_and_alert (issue #88, MC.3).

EARS → test mapping:

  Event-driven:
    E1 — WHEN background_analyze_and_alert runs, it calls analyze_ip exactly once
         (ADR-0003: one AI call per IP).
         → test_background_analyze_calls_analyze_ip_once
    E2 — WHEN the ThreatScore meets the alert threshold, check_and_alert is called.
         → test_background_analyze_calls_check_and_alert
    E3 — WHEN AI is offline, alerting still proceeds on rules-only score
         (ADR-0003 fail-safe; analyze_ip already degrades).
         → test_background_analyze_ai_offline_still_alerts

  Unwanted / fault:
    W1 — IF the background task raises, it SHALL NOT propagate to the caller
         (isolated, logged; does NOT crash the API process).
         → test_background_analyze_exception_is_logged_not_raised
    W2 — IF the notifier raises inside background_analyze_and_alert, the exception
         is caught and logged — the ingest is already committed and must not be affected.
         → test_background_analyze_notifier_exception_is_isolated
    W3 — IF AI is offline and analyze_ip succeeds with rules-only, notifier still
         receives the ThreatScore (AI degraded → rules score → threshold check).
         → test_background_analyze_rules_only_score_passed_to_notifier
    W4 — IF Pipeline has no notifier, background_analyze_and_alert completes safely.
         → test_background_analyze_no_notifier_is_safe
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from firewatch_sdk.models import SecurityEvent, ThreatScore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_event(ip: str = "192.0.2.10") -> SecurityEvent:
    return SecurityEvent(
        source_type="suricata",
        source_id="pi-home",
        timestamp=datetime(2026, 6, 5, 10, 0, 0, tzinfo=timezone.utc),
        source_ip=ip,
        action="ALERT",
    )


def _make_threat(ip: str = "192.0.2.10", level: str = "HIGH") -> ThreatScore:
    return ThreatScore(
        source_ip=ip,
        threat_level=level,  # type: ignore[arg-type]
        score=60,
        total_events=3,
        blocked_events=2,
        attack_types=["sqli"],
        first_seen=datetime(2026, 6, 5, 10, 0, 0, tzinfo=timezone.utc),
        last_seen=datetime(2026, 6, 5, 10, 1, 0, tzinfo=timezone.utc),
    )


# ---------------------------------------------------------------------------
# E-series: event-driven behavior
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_background_analyze_calls_analyze_ip_once() -> None:
    """E1 — background_analyze_and_alert calls analyze_ip exactly once for the IP."""
    from firewatch_core.pipeline import Pipeline

    threat = _make_threat(ip="192.0.2.10")
    pipeline = Pipeline(store=MagicMock(), ai_engine=MagicMock(), notifier=AsyncMock())
    pipeline.notifier.check_and_alert = AsyncMock(return_value=False)  # type: ignore[union-attr]
    pipeline.analyze_ip = AsyncMock(return_value=threat)  # type: ignore[method-assign]

    await pipeline.background_analyze_and_alert("192.0.2.10")

    pipeline.analyze_ip.assert_awaited_once_with("192.0.2.10")


@pytest.mark.asyncio
async def test_background_analyze_calls_check_and_alert() -> None:
    """E2 — background_analyze_and_alert calls notifier.check_and_alert with the ThreatScore."""
    from firewatch_core.pipeline import Pipeline

    threat = _make_threat(ip="192.0.2.11", level="CRITICAL")
    notifier = AsyncMock()
    notifier.check_and_alert.return_value = True

    pipeline = Pipeline(store=MagicMock(), ai_engine=MagicMock(), notifier=notifier)
    pipeline.analyze_ip = AsyncMock(return_value=threat)  # type: ignore[method-assign]

    await pipeline.background_analyze_and_alert("192.0.2.11")

    notifier.check_and_alert.assert_awaited_once_with(threat)


@pytest.mark.asyncio
async def test_background_analyze_ai_offline_still_alerts() -> None:
    """E3 — AI offline: analyze_ip degrades to rules-only; alerting still proceeds."""
    from firewatch_core.pipeline import Pipeline

    # analyze_ip returning a rules-only score (ai_status='unavailable').
    rules_only_threat = ThreatScore(
        source_ip="192.0.2.12",
        threat_level="MEDIUM",
        score=35,
        total_events=2,
        blocked_events=1,
        attack_types=[],
        first_seen=datetime(2026, 6, 5, 10, 0, 0, tzinfo=timezone.utc),
        last_seen=datetime(2026, 6, 5, 10, 0, 0, tzinfo=timezone.utc),
        ai_status="unavailable",
    )
    notifier = AsyncMock()
    notifier.check_and_alert.return_value = False

    pipeline = Pipeline(store=MagicMock(), ai_engine=MagicMock(), notifier=notifier)
    pipeline.analyze_ip = AsyncMock(return_value=rules_only_threat)  # type: ignore[method-assign]

    # Must complete without raising, and must call check_and_alert with the rules-only score.
    await pipeline.background_analyze_and_alert("192.0.2.12")

    notifier.check_and_alert.assert_awaited_once_with(rules_only_threat)


# ---------------------------------------------------------------------------
# W-series: fault / unwanted behavior
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_background_analyze_exception_is_logged_not_raised(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """W1 — If analyze_ip raises, background_analyze_and_alert catches + logs; never propagates."""
    from firewatch_core.pipeline import Pipeline

    notifier = AsyncMock()
    pipeline = Pipeline(store=MagicMock(), ai_engine=MagicMock(), notifier=notifier)
    pipeline.analyze_ip = AsyncMock(side_effect=RuntimeError("boom"))  # type: ignore[method-assign]

    with caplog.at_level(logging.ERROR, logger="firewatch.pipeline"):
        # Must NOT raise.
        await pipeline.background_analyze_and_alert("192.0.2.20")

    # The failure must be logged with the IP for correlation.
    assert any("192.0.2.20" in record.message for record in caplog.records)
    # Notifier must NOT be called when analyze_ip fails.
    notifier.check_and_alert.assert_not_called()


@pytest.mark.asyncio
async def test_background_analyze_notifier_exception_is_isolated(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """W2 — If the notifier raises, the exception is caught and logged, not propagated."""
    from firewatch_core.pipeline import Pipeline

    threat = _make_threat(ip="192.0.2.21")
    notifier = AsyncMock()
    notifier.check_and_alert.side_effect = RuntimeError("notifier exploded")

    pipeline = Pipeline(store=MagicMock(), ai_engine=MagicMock(), notifier=notifier)
    pipeline.analyze_ip = AsyncMock(return_value=threat)  # type: ignore[method-assign]

    with caplog.at_level(logging.ERROR, logger="firewatch.pipeline"):
        # Must NOT raise.
        await pipeline.background_analyze_and_alert("192.0.2.21")

    assert any("192.0.2.21" in record.message for record in caplog.records)


@pytest.mark.asyncio
async def test_background_analyze_rules_only_score_passed_to_notifier() -> None:
    """W3 — Rules-only score (no AI) is passed to check_and_alert for threshold gating."""
    from firewatch_core.pipeline import Pipeline

    rules_threat = ThreatScore(
        source_ip="192.0.2.30",
        threat_level="HIGH",
        score=55,
        total_events=5,
        blocked_events=4,
        attack_types=["xss"],
        first_seen=datetime(2026, 6, 5, 12, 0, 0, tzinfo=timezone.utc),
        last_seen=datetime(2026, 6, 5, 12, 1, 0, tzinfo=timezone.utc),
        ai_status="unavailable",
    )
    notifier = AsyncMock()
    notifier.check_and_alert.return_value = True

    pipeline = Pipeline(store=MagicMock(), ai_engine=MagicMock(), notifier=notifier)
    pipeline.analyze_ip = AsyncMock(return_value=rules_threat)  # type: ignore[method-assign]

    await pipeline.background_analyze_and_alert("192.0.2.30")

    # The rules-only ThreatScore is passed verbatim to check_and_alert.
    notifier.check_and_alert.assert_awaited_once_with(rules_threat)


@pytest.mark.asyncio
async def test_background_analyze_no_notifier_is_safe() -> None:
    """W4 — If Pipeline has no notifier (None), background_analyze_and_alert completes safely."""
    from firewatch_core.pipeline import Pipeline

    threat = _make_threat(ip="192.0.2.40")
    pipeline = Pipeline(store=MagicMock(), ai_engine=MagicMock(), notifier=None)
    pipeline.analyze_ip = AsyncMock(return_value=threat)  # type: ignore[method-assign]

    # Must not raise even with no notifier.
    await pipeline.background_analyze_and_alert("192.0.2.40")
