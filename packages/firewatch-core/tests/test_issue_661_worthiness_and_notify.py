"""Tests for is_alert_worthy predicate + notify_on_auto_escalate notifier gate (issue #661),
updated for issue #42 (ADR-0067 D2/D7) — the tier=None (observed) null-guard.

EARS criteria:
- WHEN notify_on_auto_escalate is OFF (default), THE SYSTEM SHALL gate notifications on the
  Notification threshold severity band only (current behaviour preserved byte-identical).
- WHEN notify_on_auto_escalate is ON, THE SYSTEM SHALL gate notifications on
  is_alert_worthy(threat, notification_threshold) (band OR escalation tier <= 2).
- THE SYSTEM SHALL NOT notify on tier 3/4 escalations when band does not meet the threshold.
- THE SYSTEM SHALL safely handle threat.escalation is None (the tier half is False).
- (ADR-0067 D2/D7, issue #42) WHEN escalation.tier is None (the observed stratum), THE SYSTEM
  SHALL evaluate the tier half as False WITHOUT raising — `None <= 2` raises TypeError in
  Python; this is the exact bug the D7 guard fixes.

Unit tests for is_alert_worthy:
- Band-only worthy (high-band threat, no escalation) → True.
- Tier <= 2 worthy when band fails → True.
- Tier 3 does NOT trigger (band fails, tier 3) → False.
- Tier 4 does NOT trigger (band fails, tier 4) → False.
- escalation=None safe (returns False for tier half, falls back to band) → False when band fails.
- escalation.tier=None (observed) safe -- does not raise, tier half is False.

Notifier integration tests:
- Toggle OFF: tier-1 MEDIUM does NOT notify (current band-only behaviour).
- Toggle ON: tier-1 MEDIUM DOES notify.
- Toggle ON: high-band CRITICAL always notifies regardless.
- Toggle ON: tier 3 MEDIUM does NOT notify.
- Toggle OFF: band still gates correctly (no regression).
- Toggle ON: an observed (tier=None) LOW actor does NOT notify (no tier vote).

RFC 5737 TEST-NET-2 (203.0.113.0/24) IPs used for SAFE_URL throughout.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

import pytest

from firewatch_sdk.config import RuntimeConfig
from firewatch_sdk.models import EscalationVerdict, ThreatScore

# ---------------------------------------------------------------------------
# Helpers shared with test_webhook_notifier.py conventions
# ---------------------------------------------------------------------------

SAFE_URL = "http://203.0.113.9/hook"


def _verdict(tier: int) -> EscalationVerdict:
    """Build a minimal EscalationVerdict at the given tier."""
    _disposition_for_tier = {
        1: "allowed_through",
        2: "block_status_unknown",
        3: "blocked_persistent",
        4: "blocked_one_off",
    }
    _block_status_for_tier = {
        1: "allowed",
        2: "unknown",
        3: "blocked",
        4: "blocked",
    }
    return EscalationVerdict(
        tier=tier,
        disposition=_disposition_for_tier[tier],  # type: ignore[arg-type]
        justification=f"[RULE] test tier {tier}",
        block_status=_block_status_for_tier[tier],  # type: ignore[arg-type]
    )


def _observed_verdict() -> EscalationVerdict:
    """Build the ADR-0067 D2 observed verdict: tier=None, disposition='observed'."""
    return EscalationVerdict(
        tier=None,
        disposition="observed",
        justification="[RULE] observed test",
        block_status="unknown",
    )


def _threat(
    level: str = "MEDIUM",
    *,
    ip: str = "192.0.2.5",
    escalation: EscalationVerdict | None = None,
) -> ThreatScore:
    return ThreatScore(
        source_ip=ip,
        threat_level=level,  # type: ignore[arg-type]
        score=40,
        total_events=3,
        blocked_events=0,
        attack_types=["SQL Injection"],
        first_seen=datetime(2024, 1, 1, tzinfo=timezone.utc),
        last_seen=datetime(2024, 1, 1, 12, tzinfo=timezone.utc),
        escalation=escalation,
    )


# ---------------------------------------------------------------------------
# Unit tests for is_alert_worthy (pure function, no I/O)
# ---------------------------------------------------------------------------


class TestIsAlertWorthy:
    """Unit tests for the shared alert-worthiness predicate (ADR-0059 D2)."""

    def test_band_worthy_no_escalation(self) -> None:
        """A CRITICAL threat with no escalation verdict is worthy at CRITICAL threshold."""
        from firewatch_core.escalation.worthiness import is_alert_worthy

        threat = _threat("CRITICAL", escalation=None)
        assert is_alert_worthy(threat, "CRITICAL") is True

    def test_band_worthy_above_threshold(self) -> None:
        """A HIGH threat is worthy at HIGH or lower threshold."""
        from firewatch_core.escalation.worthiness import is_alert_worthy

        threat = _threat("HIGH", escalation=None)
        assert is_alert_worthy(threat, "HIGH") is True
        assert is_alert_worthy(threat, "MEDIUM") is True
        assert is_alert_worthy(threat, "LOW") is True

    def test_band_not_worthy_below_threshold(self) -> None:
        """A MEDIUM threat with no escalation is NOT worthy at CRITICAL threshold."""
        from firewatch_core.escalation.worthiness import is_alert_worthy

        threat = _threat("MEDIUM", escalation=None)
        assert is_alert_worthy(threat, "CRITICAL") is False

    def test_tier1_worthy_when_band_fails(self) -> None:
        """Tier 1 escalation (allowed-through) makes a low-band threat worthy."""
        from firewatch_core.escalation.worthiness import is_alert_worthy

        threat = _threat("MEDIUM", escalation=_verdict(1))
        # MEDIUM does not meet CRITICAL threshold → band axis False
        # but tier 1 <= 2 → tier axis True → overall True
        assert is_alert_worthy(threat, "CRITICAL") is True

    def test_tier2_worthy_when_band_fails(self) -> None:
        """Tier 2 escalation (block_status_unknown) makes a low-band threat worthy."""
        from firewatch_core.escalation.worthiness import is_alert_worthy

        threat = _threat("LOW", escalation=_verdict(2))
        assert is_alert_worthy(threat, "CRITICAL") is True

    def test_tier3_not_worthy_when_band_fails(self) -> None:
        """Tier 3 escalation does NOT make a low-band threat worthy (tier > 2)."""
        from firewatch_core.escalation.worthiness import is_alert_worthy

        threat = _threat("MEDIUM", escalation=_verdict(3))
        assert is_alert_worthy(threat, "CRITICAL") is False

    def test_tier4_not_worthy_when_band_fails(self) -> None:
        """Tier 4 escalation (one-off block) does NOT make a low-band threat worthy."""
        from firewatch_core.escalation.worthiness import is_alert_worthy

        threat = _threat("MEDIUM", escalation=_verdict(4))
        assert is_alert_worthy(threat, "CRITICAL") is False

    def test_escalation_none_is_safe(self) -> None:
        """threat.escalation=None is safe; tier half evaluates to False."""
        from firewatch_core.escalation.worthiness import is_alert_worthy

        threat = _threat("LOW", escalation=None)
        # Both axes False → False
        assert is_alert_worthy(threat, "CRITICAL") is False

    # ADR-0067 D2/D7 (issue #42) — the observed stratum (tier=None) null-guard.
    def test_observed_tier_none_does_not_raise(self) -> None:
        """`None <= 2` raises TypeError in Python; is_alert_worthy must not raise."""
        from firewatch_core.escalation.worthiness import is_alert_worthy

        threat = _threat("LOW", escalation=_observed_verdict())
        try:
            result = is_alert_worthy(threat, "CRITICAL")
        except TypeError:
            pytest.fail("is_alert_worthy raised TypeError on escalation.tier=None")
        assert result is False

    def test_observed_tier_none_is_not_worthy_when_band_fails(self) -> None:
        """An observed verdict casts no tier vote — band axis alone decides."""
        from firewatch_core.escalation.worthiness import is_alert_worthy

        threat = _threat("MEDIUM", escalation=_observed_verdict())
        assert is_alert_worthy(threat, "CRITICAL") is False

    def test_observed_tier_none_still_worthy_via_band(self) -> None:
        """An observed verdict on a high-band threat is still worthy -- via the band axis."""
        from firewatch_core.escalation.worthiness import is_alert_worthy

        threat = _threat("CRITICAL", escalation=_observed_verdict())
        assert is_alert_worthy(threat, "CRITICAL") is True

    def test_tier2_plus_band_both_worthy(self) -> None:
        """When both band AND tier are true, still True (OR semantics)."""
        from firewatch_core.escalation.worthiness import is_alert_worthy

        threat = _threat("HIGH", escalation=_verdict(2))
        assert is_alert_worthy(threat, "HIGH") is True

    def test_band_meets_exact_threshold(self) -> None:
        """Exact match at threshold (equal) is worthy."""
        from firewatch_core.escalation.worthiness import is_alert_worthy

        threat = _threat("HIGH", escalation=None)
        assert is_alert_worthy(threat, "HIGH") is True

    def test_exported_from_escalation_init(self) -> None:
        """is_alert_worthy is exported from firewatch_core.escalation package."""
        from firewatch_core.escalation import is_alert_worthy  # noqa: F401


# ---------------------------------------------------------------------------
# Band-ordering helper is the single source of truth
# ---------------------------------------------------------------------------


class TestBandOrderingSingleSource:
    """The band-ordering helper must live in one place; notifier and worthiness share it."""

    def test_band_meets_helper_exported(self) -> None:
        """band_meets is importable from worthiness for direct testing."""
        from firewatch_core.escalation.worthiness import band_meets

        assert band_meets("CRITICAL", "CRITICAL") is True
        assert band_meets("HIGH", "CRITICAL") is False
        assert band_meets("CRITICAL", "LOW") is True
        assert band_meets("LOW", "LOW") is True

    def test_notifier_uses_same_ordering(self) -> None:
        """The notifier's _meets_threshold delegates to the same logic as band_meets."""
        from firewatch_core.adapters.webhook_notifier import WebhookNotifier
        from firewatch_core.escalation.worthiness import band_meets

        # They must agree on all combinations.
        for level in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            for threshold in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
                notifier_result = WebhookNotifier._meets_threshold(level, threshold)
                worthiness_result = band_meets(level, threshold)
                assert notifier_result == worthiness_result, (
                    f"Divergence for level={level!r}, threshold={threshold!r}: "
                    f"notifier={notifier_result}, worthiness={worthiness_result}"
                )


# ---------------------------------------------------------------------------
# Fake infrastructure for notifier integration tests
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

    async def __aenter__(self) -> _FakeHttpx:
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


def _notifier(
    monkeypatch: pytest.MonkeyPatch, **runtime_kwargs: Any
) -> Any:
    from firewatch_core.adapters.webhook_notifier import WebhookNotifier

    monkeypatch.setattr(
        "firewatch_core.adapters.webhook_notifier.httpx.AsyncClient", _FakeHttpx
    )
    # Patch getaddrinfo so discord/slack URL hostnames do not make real DNS calls.
    import socket
    monkeypatch.setattr(
        "firewatch_sdk.config.socket.getaddrinfo",
        lambda *_a, **_k: [
            (socket.AF_INET, socket.SOCK_STREAM, 0, "", ("192.0.2.1", 0))
        ],
    )
    runtime = RuntimeConfig(**runtime_kwargs)
    return WebhookNotifier(_FakeConfigStore(runtime))  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# Notifier integration: toggle OFF (default — band-only gate preserved)
# ---------------------------------------------------------------------------


class TestNotifyToggleOff:
    """When notify_on_auto_escalate is OFF, behaviour is byte-identical to current."""

    async def test_tier1_medium_does_not_notify_when_toggle_off(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The key regression test: tier-1 MEDIUM does NOT notify with toggle OFF."""
        n = _notifier(
            monkeypatch,
            webhook_url=SAFE_URL,
            alert_threshold="CRITICAL",
            notify_on_auto_escalate=False,
        )
        threat = _threat("MEDIUM", escalation=_verdict(1))
        sent = await n.check_and_alert(threat)
        assert sent is False
        assert _FakeHttpx.captured == []

    async def test_high_band_notifies_when_toggle_off(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A HIGH threat at HIGH threshold notifies even with toggle OFF."""
        n = _notifier(
            monkeypatch,
            webhook_url=SAFE_URL,
            alert_threshold="HIGH",
            notify_on_auto_escalate=False,
        )
        sent = await n.check_and_alert(_threat("HIGH"))
        assert sent is True
        assert len(_FakeHttpx.captured) == 1

    async def test_default_toggle_is_off(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Default (no notify_on_auto_escalate kwarg) is False — band-only gate."""
        n = _notifier(monkeypatch, webhook_url=SAFE_URL, alert_threshold="CRITICAL")
        # RuntimeConfig default is False — this notifier should behave like toggle OFF.
        threat = _threat("MEDIUM", escalation=_verdict(1))
        assert await n.check_and_alert(threat) is False

    async def test_below_band_with_no_escalation_does_not_notify(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """MEDIUM threat with no escalation at CRITICAL threshold → False."""
        n = _notifier(monkeypatch, webhook_url=SAFE_URL, alert_threshold="CRITICAL")
        assert await n.check_and_alert(_threat("MEDIUM")) is False


# ---------------------------------------------------------------------------
# Notifier integration: toggle ON (band OR tier <= 2)
# ---------------------------------------------------------------------------


class TestNotifyToggleOn:
    """When notify_on_auto_escalate is ON, tier <= 2 threats also notify."""

    async def test_tier1_medium_notifies_when_toggle_on(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The key new behaviour: tier-1 MEDIUM DOES notify with toggle ON."""
        n = _notifier(
            monkeypatch,
            webhook_url=SAFE_URL,
            alert_threshold="CRITICAL",
            notify_on_auto_escalate=True,
        )
        threat = _threat("MEDIUM", escalation=_verdict(1))
        sent = await n.check_and_alert(threat)
        assert sent is True
        assert len(_FakeHttpx.captured) == 1

    async def test_tier2_low_notifies_when_toggle_on(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Tier 2 (block_status_unknown) on a LOW threat also notifies with toggle ON."""
        n = _notifier(
            monkeypatch,
            webhook_url=SAFE_URL,
            alert_threshold="CRITICAL",
            notify_on_auto_escalate=True,
        )
        threat = _threat("LOW", escalation=_verdict(2))
        sent = await n.check_and_alert(threat)
        assert sent is True

    async def test_critical_band_always_notifies_toggle_on(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """High-band CRITICAL threat still notifies (band axis covers it)."""
        n = _notifier(
            monkeypatch,
            webhook_url=SAFE_URL,
            alert_threshold="CRITICAL",
            notify_on_auto_escalate=True,
        )
        sent = await n.check_and_alert(_threat("CRITICAL"))
        assert sent is True

    async def test_tier3_medium_does_not_notify_toggle_on(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Tier 3 (blocked_persistent) at MEDIUM does NOT notify — tier > 2."""
        n = _notifier(
            monkeypatch,
            webhook_url=SAFE_URL,
            alert_threshold="CRITICAL",
            notify_on_auto_escalate=True,
        )
        threat = _threat("MEDIUM", escalation=_verdict(3))
        assert await n.check_and_alert(threat) is False

    async def test_tier4_medium_does_not_notify_toggle_on(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Tier 4 (one-off block) at MEDIUM does NOT notify — tier > 2."""
        n = _notifier(
            monkeypatch,
            webhook_url=SAFE_URL,
            alert_threshold="CRITICAL",
            notify_on_auto_escalate=True,
        )
        threat = _threat("MEDIUM", escalation=_verdict(4))
        assert await n.check_and_alert(threat) is False

    async def test_no_webhook_returns_false_toggle_on(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No webhook URL → False even with toggle ON and tier-1 threat."""
        n = _notifier(
            monkeypatch,
            alert_threshold="CRITICAL",
            notify_on_auto_escalate=True,
        )
        threat = _threat("MEDIUM", escalation=_verdict(1))
        assert await n.check_and_alert(threat) is False
        assert _FakeHttpx.captured == []

    async def test_escalation_none_toggle_on_still_uses_band(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """toggle ON + escalation=None → only band matters; CRITICAL meets CRITICAL."""
        n = _notifier(
            monkeypatch,
            webhook_url=SAFE_URL,
            alert_threshold="CRITICAL",
            notify_on_auto_escalate=True,
        )
        threat = _threat("CRITICAL", escalation=None)
        assert await n.check_and_alert(threat) is True

    async def test_observed_low_does_not_notify_toggle_on(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """ADR-0067 D2/D7 (issue #42): an observed (tier=None) LOW actor casts no tier
        vote -- does NOT notify even with the toggle on, and must not raise."""
        n = _notifier(
            monkeypatch,
            webhook_url=SAFE_URL,
            alert_threshold="CRITICAL",
            notify_on_auto_escalate=True,
        )
        threat = _threat("LOW", escalation=_observed_verdict())
        assert await n.check_and_alert(threat) is False
        assert _FakeHttpx.captured == []


# ---------------------------------------------------------------------------
# SDK: RuntimeConfig new field defaults and round-trip
# ---------------------------------------------------------------------------


class TestRuntimeConfigNotifyField:
    def test_default_is_false(self) -> None:
        """notify_on_auto_escalate defaults to False (ADR-0059 D3 — quiet chat)."""
        cfg = RuntimeConfig()
        assert cfg.notify_on_auto_escalate is False

    def test_can_set_to_true(self) -> None:
        """The field can be set to True."""
        cfg = RuntimeConfig(notify_on_auto_escalate=True)
        assert cfg.notify_on_auto_escalate is True

    def test_serialises_in_model_dump(self) -> None:
        """The field appears in model_dump() with its value."""
        cfg = RuntimeConfig(notify_on_auto_escalate=True)
        d = cfg.model_dump()
        assert "notify_on_auto_escalate" in d
        assert d["notify_on_auto_escalate"] is True

    def test_default_serialises_as_false(self) -> None:
        cfg = RuntimeConfig()
        d = cfg.model_dump()
        assert d["notify_on_auto_escalate"] is False

    def test_unknown_field_still_rejected(self) -> None:
        """extra='forbid' is still enforced — unknown keys raise ValidationError."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            RuntimeConfig(notify_on_auto_escalate=True, bogus_field=True)  # type: ignore[call-arg]
