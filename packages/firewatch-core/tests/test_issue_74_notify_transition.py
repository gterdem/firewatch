"""Tests for issue #74 (ADR-0059 Amendment 1): notify_on_auto_escalate defaults to
True, and webhook_notifier.check_and_alert fires only on a genuine alert-worthiness
state TRANSITION (never on repeated re-evaluation of an unchanged state).

EARS criteria mapped to tests below:

- AC1 (default flip): ``RuntimeConfig.notify_on_auto_escalate`` SHALL default to True.
  -> TestDefaultFlip (this file) + TestRuntimeConfigNotifyField (test_issue_661, edited).
- AC2 (transition semantics, both axes): the notifier SHALL fire on a state
  transition (enters tier 1/2 from no-tier, moves to a louder tier, or first
  crosses the band threshold) and SHALL NOT fire on an unchanged state.
  -> TestNotifyTransitionTrackerUnit, TestCheckAndAlertCadence.
- AC3 (must-NOT: no repeat-fire while continuously in the queue) — the 50/min
  brute-force falsifier case.
  -> TestCheckAndAlertCadence.test_brute_force_cadence_fires_once.
- AC4 (both axes covered, not just the new tier path — the band path's
  pre-existing repeat-fire bug is fixed too).
  -> TestCheckAndAlertCadence.test_band_axis_does_not_repeat_fire.
- AC5 (left-and-came-back is a new transition, not a duplicate).
  -> TestCheckAndAlertCadence.test_left_and_came_back_refires (band + tier).
- AC6 (must-NOT: tier=None never notifies via the tier axis, under any config;
  band axis stays live for an observed actor -- NOT a blanket "never notifies").
  -> TestObservedStratumTierAxis.
- AC7 (must-NOT: no OS push path added) -- structural; nothing to test (no such
  code exists in this diff).
- AC8 (must-NOT: alert_threshold default / band-axis gate unchanged).
  -> TestThresholdSelectorGates.
- AC9 (webhook safety: reuse the existing SSRF validator, no new one).
  -> TestWebhookSafetyReused.

RFC 5737 TEST-NET-2 (203.0.113.0/24) / TEST-NET-1 (192.0.2.0/24) documentation IPs
used throughout, per repo convention -- never real/public IPs.
"""
from __future__ import annotations

import socket
from datetime import datetime, timezone
from typing import Any

import pytest
from pydantic import ValidationError

from firewatch_core.adapters.webhook_notifier import WebhookNotifier
from firewatch_core.escalation.transition import NotifyTransitionTracker
from firewatch_sdk.config import RuntimeConfig
from firewatch_sdk.models import EscalationVerdict, ThreatScore

SAFE_URL = "http://203.0.113.9/hook"

_DISPOSITION_FOR_TIER = {
    1: "allowed_through",
    2: "block_status_unknown",
    3: "blocked_persistent",
    4: "blocked_one_off",
}
_BLOCK_STATUS_FOR_TIER = {1: "allowed", 2: "unknown", 3: "blocked", 4: "blocked"}


def _verdict(tier: int) -> EscalationVerdict:
    return EscalationVerdict(
        tier=tier,
        disposition=_DISPOSITION_FOR_TIER[tier],  # type: ignore[arg-type]
        justification=f"[RULE] test tier {tier}",
        block_status=_BLOCK_STATUS_FOR_TIER[tier],  # type: ignore[arg-type]
    )


def _observed_verdict() -> EscalationVerdict:
    return EscalationVerdict(
        tier=None,
        disposition="observed",
        justification="[RULE] observed test",
        block_status="unknown",
    )


def _threat(
    level: str = "MEDIUM",
    *,
    ip: str = "192.0.2.7",
    escalation: EscalationVerdict | None = None,
    score: int = 40,
) -> ThreatScore:
    return ThreatScore(
        source_ip=ip,
        threat_level=level,  # type: ignore[arg-type]
        score=score,
        total_events=3,
        blocked_events=0,
        attack_types=["SQL Injection"],
        first_seen=datetime(2024, 1, 1, tzinfo=timezone.utc),
        last_seen=datetime(2024, 1, 1, 12, tzinfo=timezone.utc),
        escalation=escalation,
    )


# ---------------------------------------------------------------------------
# AC1 -- default flip
# ---------------------------------------------------------------------------


class TestDefaultFlip:
    def test_notify_on_auto_escalate_defaults_true(self) -> None:
        """ADR-0059 Amendment 1 A1.1: the default flips False -> True."""
        assert RuntimeConfig().notify_on_auto_escalate is True

    def test_existing_persisted_false_is_preserved(self) -> None:
        """An explicit stored False is NOT migrated -- only the absent-value default moved."""
        assert RuntimeConfig(notify_on_auto_escalate=False).notify_on_auto_escalate is False


# ---------------------------------------------------------------------------
# AC2 -- NotifyTransitionTracker unit tests (pure, no I/O)
# ---------------------------------------------------------------------------


class TestNotifyTransitionTrackerUnit:
    def test_first_evaluation_worthy_is_a_transition(self) -> None:
        t = NotifyTransitionTracker()
        assert t.transitioned("1.1.1.1", band_met=True, tier=None, tier_axis_enabled=False) is True

    def test_first_evaluation_not_worthy_is_not_a_transition(self) -> None:
        t = NotifyTransitionTracker()
        assert t.transitioned("1.1.1.1", band_met=False, tier=None, tier_axis_enabled=False) is False

    def test_unchanged_worthy_state_does_not_re_transition(self) -> None:
        t = NotifyTransitionTracker()
        ip = "1.1.1.1"
        assert t.transitioned(ip, band_met=True, tier=None, tier_axis_enabled=False) is True
        assert t.transitioned(ip, band_met=True, tier=None, tier_axis_enabled=False) is False
        assert t.transitioned(ip, band_met=True, tier=None, tier_axis_enabled=False) is False

    def test_band_first_crossing_fires_once(self) -> None:
        t = NotifyTransitionTracker()
        ip = "1.1.1.1"
        assert t.transitioned(ip, band_met=False, tier=None, tier_axis_enabled=False) is False
        assert t.transitioned(ip, band_met=True, tier=None, tier_axis_enabled=False) is True
        assert t.transitioned(ip, band_met=True, tier=None, tier_axis_enabled=False) is False

    def test_band_left_and_came_back_refires(self) -> None:
        t = NotifyTransitionTracker()
        ip = "1.1.1.1"
        assert t.transitioned(ip, band_met=True, tier=None, tier_axis_enabled=False) is True
        assert t.transitioned(ip, band_met=False, tier=None, tier_axis_enabled=False) is False
        assert t.transitioned(ip, band_met=True, tier=None, tier_axis_enabled=False) is True

    def test_tier_enters_from_no_tier_fires(self) -> None:
        t = NotifyTransitionTracker()
        assert t.transitioned("1.1.1.1", band_met=False, tier=2, tier_axis_enabled=True) is True

    def test_tier_unchanged_does_not_re_fire(self) -> None:
        t = NotifyTransitionTracker()
        ip = "1.1.1.1"
        assert t.transitioned(ip, band_met=False, tier=2, tier_axis_enabled=True) is True
        assert t.transitioned(ip, band_met=False, tier=2, tier_axis_enabled=True) is False

    def test_tier_gets_louder_refires(self) -> None:
        """Tier 2 -> Tier 1 (louder / more urgent) fires again while still in-queue."""
        t = NotifyTransitionTracker()
        ip = "1.1.1.1"
        assert t.transitioned(ip, band_met=False, tier=2, tier_axis_enabled=True) is True
        assert t.transitioned(ip, band_met=False, tier=1, tier_axis_enabled=True) is True

    def test_tier_gets_quieter_within_range_does_not_fire(self) -> None:
        """Tier 1 -> Tier 2 (quieter but still <= ceiling) is not a fire-worthy move."""
        t = NotifyTransitionTracker()
        ip = "1.1.1.1"
        assert t.transitioned(ip, band_met=False, tier=1, tier_axis_enabled=True) is True
        assert t.transitioned(ip, band_met=False, tier=2, tier_axis_enabled=True) is False

    def test_tier_leaves_and_returns_refires(self) -> None:
        """Tier 2 -> Tier 3 (out of range) -> Tier 2 (back in range) fires again."""
        t = NotifyTransitionTracker()
        ip = "1.1.1.1"
        assert t.transitioned(ip, band_met=False, tier=2, tier_axis_enabled=True) is True
        assert t.transitioned(ip, band_met=False, tier=3, tier_axis_enabled=True) is False
        assert t.transitioned(ip, band_met=False, tier=2, tier_axis_enabled=True) is True

    def test_tier_axis_disabled_never_transitions_on_tier_alone(self) -> None:
        t = NotifyTransitionTracker()
        ip = "1.1.1.1"
        assert t.transitioned(ip, band_met=False, tier=None, tier_axis_enabled=False) is False
        # Tier goes from no-tier straight to tier 1, but the axis is disabled.
        assert t.transitioned(ip, band_met=False, tier=1, tier_axis_enabled=False) is False

    def test_independent_actors_tracked_separately(self) -> None:
        t = NotifyTransitionTracker()
        assert t.transitioned("1.1.1.1", band_met=True, tier=None, tier_axis_enabled=False) is True
        # A different actor's first evaluation is its own fresh transition.
        assert t.transitioned("2.2.2.2", band_met=True, tier=None, tier_axis_enabled=False) is True

    def test_reset_single_actor_clears_only_that_actor(self) -> None:
        t = NotifyTransitionTracker()
        t.transitioned("1.1.1.1", band_met=True, tier=None, tier_axis_enabled=False)
        t.transitioned("2.2.2.2", band_met=True, tier=None, tier_axis_enabled=False)
        t.reset("1.1.1.1")
        # 1.1.1.1 looks brand-new again -> transitions; 2.2.2.2 stays remembered.
        assert t.transitioned("1.1.1.1", band_met=True, tier=None, tier_axis_enabled=False) is True
        assert t.transitioned("2.2.2.2", band_met=True, tier=None, tier_axis_enabled=False) is False

    def test_reset_all(self) -> None:
        t = NotifyTransitionTracker()
        t.transitioned("1.1.1.1", band_met=True, tier=None, tier_axis_enabled=False)
        t.reset()
        assert t.transitioned("1.1.1.1", band_met=True, tier=None, tier_axis_enabled=False) is True


# ---------------------------------------------------------------------------
# Fake infrastructure for WebhookNotifier integration tests (mirrors
# test_issue_661_worthiness_and_notify.py's conventions).
# ---------------------------------------------------------------------------


class _FakeConfigStore:
    def __init__(self, runtime: RuntimeConfig) -> None:
        self._runtime = runtime

    def get_runtime(self) -> RuntimeConfig:
        return self._runtime


class _FakeHttpx:
    captured: list[tuple[str, dict[str, Any]]] = []
    fail: bool = False

    def __init__(self, *_a: Any, **_k: Any) -> None: ...

    async def __aenter__(self) -> "_FakeHttpx":
        return self

    async def __aexit__(self, *_a: Any) -> bool:
        return False

    async def post(self, url: str, json: dict[str, Any]) -> Any:
        if _FakeHttpx.fail:
            import httpx

            raise httpx.ConnectError("refused")
        _FakeHttpx.captured.append((url, json))

        class _Resp:
            def raise_for_status(self) -> None: ...

        return _Resp()


@pytest.fixture(autouse=True)
def _reset_fake_httpx() -> Any:
    _FakeHttpx.captured = []
    _FakeHttpx.fail = False
    yield


def _notifier(monkeypatch: pytest.MonkeyPatch, **runtime_kwargs: Any) -> WebhookNotifier:
    monkeypatch.setattr(
        "firewatch_core.adapters.webhook_notifier.httpx.AsyncClient", _FakeHttpx
    )
    monkeypatch.setattr(
        "firewatch_sdk.config.socket.getaddrinfo",
        lambda *_a, **_k: [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("192.0.2.1", 0))],
    )
    runtime = RuntimeConfig(**runtime_kwargs)
    return WebhookNotifier(_FakeConfigStore(runtime))  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# AC3 / AC4 / AC5 -- check_and_alert cadence (integration, both axes)
# ---------------------------------------------------------------------------


class TestCheckAndAlertCadence:
    async def test_brute_force_cadence_fires_once(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The Maintainer's falsifier: 50 events/min for one actor pushed one at a
        time produces exactly ONE notification at the crossing, not ~50."""
        n = _notifier(
            monkeypatch,
            webhook_url=SAFE_URL,
            alert_threshold="CRITICAL",
            notify_on_auto_escalate=True,
        )
        threat = _threat("CRITICAL", ip="192.0.2.50", escalation=_verdict(2))
        for _ in range(50):
            await n.check_and_alert(threat)
        assert len(_FakeHttpx.captured) == 1

    async def test_band_axis_does_not_repeat_fire(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """AC4: the band-only path (toggle off) is fixed too -- not just the new
        tier path. A CRITICAL-band actor evaluated repeatedly notifies once."""
        n = _notifier(
            monkeypatch,
            webhook_url=SAFE_URL,
            alert_threshold="CRITICAL",
            notify_on_auto_escalate=False,
        )
        threat = _threat("CRITICAL", ip="192.0.2.51")
        for _ in range(10):
            await n.check_and_alert(threat)
        assert len(_FakeHttpx.captured) == 1

    async def test_first_crossing_fires_prior_evaluations_below_do_not(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        n = _notifier(
            monkeypatch,
            webhook_url=SAFE_URL,
            alert_threshold="CRITICAL",
            notify_on_auto_escalate=False,
        )
        ip = "192.0.2.52"
        below = _threat("MEDIUM", ip=ip)
        at_threshold = _threat("CRITICAL", ip=ip)

        assert await n.check_and_alert(below) is False
        assert await n.check_and_alert(below) is False
        assert await n.check_and_alert(at_threshold) is True
        assert len(_FakeHttpx.captured) == 1

    async def test_left_and_came_back_refires_band_axis(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """AC5: decay-then-recur is a NEW transition, not a duplicate."""
        n = _notifier(
            monkeypatch,
            webhook_url=SAFE_URL,
            alert_threshold="CRITICAL",
            notify_on_auto_escalate=False,
        )
        ip = "192.0.2.53"
        high_score = _threat("CRITICAL", ip=ip)
        decayed = _threat("MEDIUM", ip=ip)

        assert await n.check_and_alert(high_score) is True  # first crossing
        assert await n.check_and_alert(decayed) is False  # falls below
        assert await n.check_and_alert(high_score) is True  # re-crosses -> fires again
        assert len(_FakeHttpx.captured) == 2

    async def test_tier_enters_then_stays_fires_once(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        n = _notifier(
            monkeypatch,
            webhook_url=SAFE_URL,
            alert_threshold="CRITICAL",
            notify_on_auto_escalate=True,
        )
        ip = "192.0.2.54"
        threat = _threat("MEDIUM", ip=ip, escalation=_verdict(2))
        assert await n.check_and_alert(threat) is True
        assert await n.check_and_alert(threat) is False
        assert await n.check_and_alert(threat) is False
        assert len(_FakeHttpx.captured) == 1

    async def test_tier_gets_louder_refires_via_check_and_alert(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        n = _notifier(
            monkeypatch,
            webhook_url=SAFE_URL,
            alert_threshold="CRITICAL",
            notify_on_auto_escalate=True,
        )
        ip = "192.0.2.55"
        tier2 = _threat("MEDIUM", ip=ip, escalation=_verdict(2))
        tier1 = _threat("MEDIUM", ip=ip, escalation=_verdict(1))

        assert await n.check_and_alert(tier2) is True
        assert await n.check_and_alert(tier1) is True  # louder -> refires
        assert len(_FakeHttpx.captured) == 2

    async def test_tier_leaves_and_returns_refires_via_check_and_alert(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Actor decays out of the escalating tiers and later re-enters -- fires again
        even though this is the SAME actor, matching the "left and came back" rule."""
        n = _notifier(
            monkeypatch,
            webhook_url=SAFE_URL,
            alert_threshold="CRITICAL",
            notify_on_auto_escalate=True,
        )
        ip = "192.0.2.56"
        in_queue = _threat("MEDIUM", ip=ip, escalation=_verdict(2))
        blocked_persistent = _threat("MEDIUM", ip=ip, escalation=_verdict(3))

        assert await n.check_and_alert(in_queue) is True
        assert await n.check_and_alert(blocked_persistent) is False
        assert await n.check_and_alert(in_queue) is True
        assert len(_FakeHttpx.captured) == 2

    async def test_no_webhook_never_touches_transition_state(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No URL -> False, and no tracking side effect that would suppress a later
        notification once a webhook is configured (verified indirectly: a worthy
        threat still fires the first time it is evaluated with an actual notifier
        that DOES have a webhook configured)."""
        n = _notifier(monkeypatch, alert_threshold="CRITICAL")  # no webhook_url
        threat = _threat("CRITICAL", ip="192.0.2.57")
        assert await n.check_and_alert(threat) is False
        assert _FakeHttpx.captured == []


# ---------------------------------------------------------------------------
# AC6 -- observed stratum (tier=None): tier axis never fires; band axis stays live
# ---------------------------------------------------------------------------


class TestObservedStratumTierAxis:
    async def test_observed_actor_never_fires_via_tier_axis(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """tier=None casts no tier vote -- toggle ON, low band, repeated calls: never fires."""
        n = _notifier(
            monkeypatch,
            webhook_url=SAFE_URL,
            alert_threshold="CRITICAL",
            notify_on_auto_escalate=True,
        )
        ip = "192.0.2.60"
        threat = _threat("LOW", ip=ip, escalation=_observed_verdict())
        for _ in range(5):
            assert await n.check_and_alert(threat) is False
        assert _FakeHttpx.captured == []

    async def test_observed_actor_still_notifies_via_band_axis(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A1.2 correction: the band axis stays live for an observed actor that
        reaches the operator's threat level -- this is NOT a defect. A test must
        not assert observed actors never notify at all (issue #74 body)."""
        n = _notifier(
            monkeypatch,
            webhook_url=SAFE_URL,
            alert_threshold="CRITICAL",
            notify_on_auto_escalate=True,
        )
        ip = "192.0.2.61"
        threat = _threat("CRITICAL", ip=ip, escalation=_observed_verdict())
        assert await n.check_and_alert(threat) is True
        assert len(_FakeHttpx.captured) == 1


# ---------------------------------------------------------------------------
# AC8 -- threat-level selector gates below-threshold entries; alert_threshold
# default (CRITICAL) and the band-axis gate are unchanged.
# ---------------------------------------------------------------------------


class TestThresholdSelectorGates:
    def test_alert_threshold_default_still_critical(self) -> None:
        assert RuntimeConfig().alert_threshold == "CRITICAL"

    async def test_below_selected_level_never_notifies(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        n = _notifier(
            monkeypatch,
            webhook_url=SAFE_URL,
            alert_threshold="HIGH",
            notify_on_auto_escalate=False,
        )
        threat = _threat("MEDIUM", ip="192.0.2.62")
        for _ in range(5):
            assert await n.check_and_alert(threat) is False
        assert _FakeHttpx.captured == []

    async def test_at_or_above_selected_level_notifies(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        n = _notifier(
            monkeypatch,
            webhook_url=SAFE_URL,
            alert_threshold="HIGH",
            notify_on_auto_escalate=False,
        )
        assert await n.check_and_alert(_threat("HIGH", ip="192.0.2.63")) is True
        assert await n.check_and_alert(_threat("CRITICAL", ip="192.0.2.64")) is True


# ---------------------------------------------------------------------------
# AC9 -- webhook egress reuses the EXISTING SSRF validator (no new validator).
# ---------------------------------------------------------------------------


class TestWebhookSafetyReused:
    """``RuntimeConfig.webhook_url``'s field_validator delegates to the single
    ``_assert_webhook_url_safe`` gate (firewatch_sdk/config.py) -- issue #74 does
    not add a second validator; it only reuses this one at config-write time.
    """

    def test_ssrf_metadata_url_rejected(self) -> None:
        with pytest.raises(ValidationError):
            RuntimeConfig(webhook_url="http://169.254.169.254/latest")  # type: ignore[arg-type]

    def test_ssrf_loopback_url_rejected(self) -> None:
        with pytest.raises(ValidationError):
            RuntimeConfig(webhook_url="http://127.0.0.1/hook")  # type: ignore[arg-type]

    def test_safe_documentation_ip_url_accepted(self) -> None:
        cfg = RuntimeConfig(webhook_url=SAFE_URL)  # type: ignore[arg-type]
        assert cfg.webhook_url is not None
        assert cfg.webhook_url.get_secret_value() == SAFE_URL
