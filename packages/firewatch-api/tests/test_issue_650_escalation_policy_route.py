"""Tests for GET /escalation/policy (issue #650, ADR-0058 D1/D6, ADR-0059 D6).

EARS criteria -> test(s) mapping
----------------------------------
E1  THE SYSTEM SHALL return every registered detection with severity + auto_escalate.
    test_every_registered_rule_present
    test_severity_and_auto_escalate_fields

E2  THE SYSTEM SHALL return 24h hit-counts; zero for rules with no hits in the window.
    test_hit_counts_inside_window
    test_hit_counts_outside_window_are_zero
    test_zero_hit_for_registered_rule_not_triggered

E3  Empty store => all zeros, no error.
    test_empty_store_returns_all_zeros

E4  The response model is typed (Pydantic) and includes policy + hit-count fields.
    test_response_shape

Determinism regression (PR #81 security review): GET /escalation/policy must
anchor its store-cutoff and its detect() call to a SINGLE ``now`` so the same
stored events always produce the same hit_count_24h.
    test_attempt_pressure_fires_and_hit_count_is_deterministic
    test_attempt_pressure_hit_count_via_route_is_stable

SDK / config tests (triage_threshold):
S1  triage_threshold defaults to HIGH.
    test_triage_threshold_default_is_high
S2  triage_threshold round-trips through model_dump.
    test_triage_threshold_round_trips
S3  extra='forbid' still rejects unknown keys when triage_threshold is set.
    test_extra_forbid_still_enforced
S4  triage_threshold appears in GET /config/runtime response.
    test_triage_threshold_in_runtime_config_response

Security: RFC 5737 TEST-NET IPs only (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24).
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from fastapi.testclient import TestClient

from firewatch_api.app import create_app
from firewatch_api.routes import escalation
from firewatch_sdk.config import RuntimeConfig
from firewatch_sdk.models import ActionLiteral, SecurityEvent


# ---------------------------------------------------------------------------
# Helpers / fakes
# ---------------------------------------------------------------------------


class _FakeConfigStore:
    """Minimal ConfigStore stub for tests that don't exercise config writes."""

    def get_runtime(self) -> RuntimeConfig:
        return RuntimeConfig.model_validate({})

    def set_runtime(self, updates: dict[str, Any]) -> None:
        pass

    def get_source(self, source_type: str, schema: Any) -> Any:
        return schema.model_validate({})

    def set_source(self, source_type: str, schema: Any, updates: dict[str, Any]) -> None:
        pass


class _FakeStore:
    """In-memory EventStore that replays a fixed list of SecurityEvents for all IPs."""

    def __init__(self, events: list[SecurityEvent]) -> None:
        self._events = events

    async def get_all_ips(self) -> list[str]:
        return list({e.source_ip for e in self._events})

    async def get_by_ip_since(
        self, ip: str, cutoff: datetime
    ) -> list[SecurityEvent]:
        return [
            e
            for e in self._events
            if e.source_ip == ip and e.timestamp >= cutoff
        ]

    # --- stubs so create_app doesn't crash on other route probes ---
    async def get_all_ips_since(self, cutoff: datetime) -> list[str]:
        return list({
            e.source_ip for e in self._events if e.timestamp >= cutoff
        })


def _make_client(
    events: list[SecurityEvent] | None = None,
) -> TestClient:
    """Build a test client with a fake store seeded with *events*."""
    store = _FakeStore(events or [])
    app = create_app(
        registry={},
        config_store=_FakeConfigStore(),
        event_store=store,
    )
    return TestClient(app)


def _sec_event(
    ip: str,
    *,
    source_type: str = "suricata",
    category: str | None = "SSH Brute Force",
    action: ActionLiteral = "ALERT",
    ts: datetime | None = None,
) -> SecurityEvent:
    """Build a minimal SecurityEvent (RFC 5737 IPs only)."""
    return SecurityEvent(
        source_type=source_type,
        source_id="default",
        timestamp=ts or datetime.now(timezone.utc),
        source_ip=ip,
        action=action,
        category=category,
    )


# ---------------------------------------------------------------------------
# Helpers that build events to trigger each detector rule
# ---------------------------------------------------------------------------

_NOW = datetime.now(timezone.utc)

# Use RFC 5737 TEST-NET IPs throughout
_IP_A = "192.0.2.10"
_IP_B = "198.51.100.10"
_IP_C = "203.0.113.10"


def _brute_force_then_login_events(ip: str, ts: datetime) -> list[SecurityEvent]:
    """3 SSH brute-force events + 1 SSH successful login within 30 min.

    Triggers detector._brute_force_then_login (severity=critical, auto_escalate=True).
    """
    bf_events = [
        SecurityEvent(
            source_type="syslog",
            source_id="default",
            timestamp=ts + timedelta(minutes=i),
            source_ip=ip,
            action="BLOCK",
            category="SSH Brute Force",
        )
        for i in range(3)
    ]
    login_event = SecurityEvent(
        source_type="syslog",
        source_id="default",
        timestamp=ts + timedelta(minutes=20),
        source_ip=ip,
        action="ALLOW",
        category="SSH Login",  # matches detector._brute_force_then_login category check
    )
    return [*bf_events, login_event]


def _attempt_pressure_events(
    ip: str, ts: datetime, count: int = 5
) -> list[SecurityEvent]:
    """*count* simultaneous BLOCK events at the same instant for *ip*.

    ``firewatch_core.attempts`` D2: N simultaneous attempts (all ``dt=0``)
    decay-fold to exactly ``lambda_hat == N``. With ``count=5`` this exactly
    reaches ``PRESSURE_THRESHOLD`` (theta_press=5, ADR-0070 Revision 1 D5),
    firing the detector's ``attempt_pressure`` rule for *ip* — verified
    directly against ``peak_intensity``/``detect`` before writing this test.
    """
    return [
        SecurityEvent(
            source_type="suricata",
            source_id="default",
            timestamp=ts,
            source_ip=ip,
            action="BLOCK",
            category="Attempt Flood",
        )
        for _ in range(count)
    ]


def _fixed_clock(fixed: datetime) -> type[datetime]:
    """A ``datetime`` subclass whose ``.now()`` always returns *fixed*.

    Used to pin ``firewatch_api.routes.escalation``'s wall-clock read to a
    single, known instant so a test can assert exact/stable ``hit_count_24h``
    values instead of merely ">= 1" (PR #81 security review: the route
    previously read ``datetime.now()`` twice — once for the store cutoff,
    once inside ``detect()`` — letting the two anchors drift apart under
    load).
    """

    class _Clock(datetime):
        @classmethod
        def now(cls, tz: Any = None) -> datetime:  # noqa: ARG003 - matches datetime.now signature
            return fixed

    return _Clock


def _ids_then_brute_force_events(ip: str, ts: datetime) -> list[SecurityEvent]:
    """1 Suricata IDS event + 3 syslog SSH brute-force within 10 min.

    Triggers detector._ids_then_brute_force (severity=high, auto_escalate=True).
    """
    ids_event = SecurityEvent(
        source_type="suricata",
        source_id="default",
        timestamp=ts,
        source_ip=ip,
        action="ALERT",
        category=None,
    )
    bf_events = [
        SecurityEvent(
            source_type="syslog",
            source_id="default",
            timestamp=ts + timedelta(minutes=i + 1),
            source_ip=ip,
            action="BLOCK",
            category="SSH Brute Force",
        )
        for i in range(3)
    ]
    return [ids_event, *bf_events]


# ---------------------------------------------------------------------------
# SDK tests — triage_threshold field (EARS S1-S3)
# ---------------------------------------------------------------------------


class TestTriageThresholdSDK:
    """RuntimeConfig.triage_threshold field tests (ADR-0059 D1)."""

    def test_triage_threshold_default_is_high(self) -> None:
        """Default is HIGH, preserving the existing hard-coded banner band exactly."""
        cfg = RuntimeConfig()
        assert cfg.triage_threshold == "HIGH"

    def test_triage_threshold_round_trips(self) -> None:
        """The field survives model_dump() and model_validate() round-trips."""
        for level in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            cfg = RuntimeConfig(triage_threshold=level)  # type: ignore[arg-type]
            d = cfg.model_dump()
            assert d["triage_threshold"] == level
            cfg2 = RuntimeConfig.model_validate(d)
            assert cfg2.triage_threshold == level

    def test_extra_forbid_still_enforced(self) -> None:
        """extra='forbid' still rejects unknown keys when triage_threshold is set."""
        from pydantic import ValidationError

        with pytest.raises(ValidationError):
            RuntimeConfig(triage_threshold="HIGH", bogus_field=True)  # type: ignore[call-arg]

    def test_triage_threshold_appears_in_model_dump(self) -> None:
        """triage_threshold is present in model_dump() output at its default value."""
        cfg = RuntimeConfig()
        d = cfg.model_dump()
        assert "triage_threshold" in d
        assert d["triage_threshold"] == "HIGH"


# ---------------------------------------------------------------------------
# triage_threshold in GET /config/runtime (EARS S4)
# ---------------------------------------------------------------------------


class TestTriageThresholdInRuntimeConfigRoute:
    """GET /config/runtime exposes triage_threshold (additive field, flows through model_dump)."""

    def test_triage_threshold_in_runtime_config_response(self) -> None:
        """GET /config/runtime must include triage_threshold with value HIGH (default)."""
        client = _make_client()
        resp = client.get("/config/runtime")
        assert resp.status_code == 200
        body = resp.json()
        assert "triage_threshold" in body, (
            f"triage_threshold missing from /config/runtime response: {body.keys()}"
        )
        assert body["triage_threshold"] == "HIGH"

    def test_put_triage_threshold_persists(self) -> None:
        """PUT /config/runtime with triage_threshold=CRITICAL must be accepted."""
        # We need a real (in-memory) config store for this test.
        from firewatch_sdk.config import RuntimeConfig as RC

        class _TrackingStore:
            def __init__(self) -> None:
                self._cfg: dict[str, Any] = {}

            def get_runtime(self) -> RC:
                return RC.model_validate(self._cfg)

            def set_runtime(self, updates: dict[str, Any]) -> None:
                self._cfg.update(updates)

            def get_source(self, source_type: str, schema: Any) -> Any:
                return schema.model_validate({})

            def set_source(
                self, source_type: str, schema: Any, updates: dict[str, Any]
            ) -> None:
                pass

        store = _TrackingStore()
        app = create_app(registry={}, config_store=store)
        client = TestClient(app)
        resp = client.put("/config/runtime", json={"updates": {"triage_threshold": "CRITICAL"}})
        assert resp.status_code == 200
        body = resp.json()
        assert body["triage_threshold"] == "CRITICAL"


# ---------------------------------------------------------------------------
# Escalation policy endpoint: response shape (EARS E4)
# ---------------------------------------------------------------------------


class TestEscalationPolicyResponseShape:
    """GET /escalation/policy response shape tests."""

    def test_response_shape(self) -> None:
        """The response has policy (list) and generated_at (str) keys."""
        client = _make_client()
        resp = client.get("/escalation/policy")
        assert resp.status_code == 200
        body = resp.json()
        assert "policy" in body, f"'policy' key missing: {body.keys()}"
        assert "generated_at" in body, f"'generated_at' key missing: {body.keys()}"
        assert isinstance(body["policy"], list)

    def test_each_row_has_required_fields(self) -> None:
        """Each policy row has rule_name, severity, auto_escalate, hit_count_24h."""
        client = _make_client()
        resp = client.get("/escalation/policy")
        body = resp.json()
        for row in body["policy"]:
            assert "rule_name" in row, f"'rule_name' missing: {row}"
            assert "severity" in row, f"'severity' missing: {row}"
            assert "auto_escalate" in row, f"'auto_escalate' missing: {row}"
            assert "hit_count_24h" in row, f"'hit_count_24h' missing: {row}"


# ---------------------------------------------------------------------------
# Every registered detection appears (EARS E1)
# ---------------------------------------------------------------------------


class TestAllRegisteredRulesPresent:
    """GET /escalation/policy includes all rules registered in ESCALATION_POLICY."""

    def test_every_registered_rule_present(self) -> None:
        """All four detector rules appear in the response."""
        client = _make_client()
        resp = client.get("/escalation/policy")
        assert resp.status_code == 200
        body = resp.json()
        returned_names = {row["rule_name"] for row in body["policy"]}
        # The ESCALATION_POLICY registry may contain rules; at minimum the
        # four core detector rules must be present.
        expected = {
            "brute_force_then_login",
            "ids_then_brute_force",
            "multi_source_attack",
            # issue #53 (ADR-0070 Revision 1): attempt_pressure replaces the
            # retired sustained_attack in the registry.
            "attempt_pressure",
        }
        assert expected.issubset(returned_names), (
            f"Missing rules: {expected - returned_names}. Got: {returned_names}"
        )

    def test_severity_and_auto_escalate_match_registry(self) -> None:
        """severity + auto_escalate in response match the ESCALATION_POLICY registry."""
        from firewatch_core.escalation.policy import ESCALATION_POLICY

        client = _make_client()
        resp = client.get("/escalation/policy")
        body = resp.json()
        rows_by_name = {row["rule_name"]: row for row in body["policy"]}

        for rule_name, row in rows_by_name.items():
            policy = ESCALATION_POLICY.get_or_default(rule_name)
            assert row["severity"] == policy.severity, (
                f"Severity mismatch for {rule_name!r}: "
                f"got {row['severity']!r}, expected {policy.severity!r}"
            )
            assert row["auto_escalate"] == policy.auto_escalate, (
                f"auto_escalate mismatch for {rule_name!r}: "
                f"got {row['auto_escalate']!r}, expected {policy.auto_escalate!r}"
            )


# ---------------------------------------------------------------------------
# 24h hit-counts (EARS E2)
# ---------------------------------------------------------------------------


class TestHitCounts24h:
    """24h hit-count tests for GET /escalation/policy."""

    def test_empty_store_returns_all_zeros(self) -> None:
        """With no events in store, all registered rules return hit_count_24h=0."""
        client = _make_client(events=[])
        resp = client.get("/escalation/policy")
        assert resp.status_code == 200
        body = resp.json()
        for row in body["policy"]:
            assert row["hit_count_24h"] == 0, (
                f"Expected 0 hits for {row['rule_name']!r} with empty store, "
                f"got {row['hit_count_24h']!r}"
            )

    def test_zero_hit_for_rule_not_triggered(self) -> None:
        """A registered rule with no matching events returns hit_count_24h=0."""
        # Only one block event — not enough to trigger any detection.
        single_event = _sec_event(_IP_A, action="BLOCK", ts=_NOW)
        client = _make_client(events=[single_event])
        resp = client.get("/escalation/policy")
        body = resp.json()
        for row in body["policy"]:
            assert row["hit_count_24h"] == 0, (
                f"Expected 0 hits for {row['rule_name']!r}, "
                f"got {row['hit_count_24h']!r}"
            )

    def test_brute_force_then_login_counted(self) -> None:
        """Events that trigger brute_force_then_login increment its hit_count_24h."""
        events = _brute_force_then_login_events(_IP_A, _NOW)
        client = _make_client(events=events)
        resp = client.get("/escalation/policy")
        body = resp.json()
        rows_by_name = {row["rule_name"]: row for row in body["policy"]}
        assert rows_by_name["brute_force_then_login"]["hit_count_24h"] >= 1, (
            "Expected brute_force_then_login to have >= 1 hit"
        )

    def test_ids_then_brute_force_counted(self) -> None:
        """Events that trigger ids_then_brute_force increment its hit_count_24h."""
        events = _ids_then_brute_force_events(_IP_B, _NOW)
        client = _make_client(events=events)
        resp = client.get("/escalation/policy")
        body = resp.json()
        rows_by_name = {row["rule_name"]: row for row in body["policy"]}
        assert rows_by_name["ids_then_brute_force"]["hit_count_24h"] >= 1, (
            "Expected ids_then_brute_force to have >= 1 hit"
        )

    def test_events_outside_24h_not_counted(self) -> None:
        """Events older than 24h do not contribute to hit_count_24h."""
        old_ts = _NOW - timedelta(hours=25)  # 25 hours ago — outside 24h window
        events = _brute_force_then_login_events(_IP_A, old_ts)
        client = _make_client(events=events)
        resp = client.get("/escalation/policy")
        body = resp.json()
        rows_by_name = {row["rule_name"]: row for row in body["policy"]}
        # Events are outside the 24h window — hit count must be 0.
        assert rows_by_name["brute_force_then_login"]["hit_count_24h"] == 0, (
            "Events outside 24h window should not be counted"
        )

    def test_events_inside_and_outside_24h(self) -> None:
        """Only events inside the 24h window contribute; older events are ignored."""
        old_ts = _NOW - timedelta(hours=25)
        recent_ts = _NOW - timedelta(hours=1)
        # Old events for IP_A (outside window)
        old_events = _brute_force_then_login_events(_IP_A, old_ts)
        # Recent events for IP_B (inside window)
        recent_events = _brute_force_then_login_events(_IP_B, recent_ts)
        client = _make_client(events=old_events + recent_events)
        resp = client.get("/escalation/policy")
        body = resp.json()
        rows_by_name = {row["rule_name"]: row for row in body["policy"]}
        # Only IP_B's events are inside the window.
        assert rows_by_name["brute_force_then_login"]["hit_count_24h"] >= 1

    def test_two_ips_trigger_same_rule_additive(self) -> None:
        """Hit counts add across IPs: two IPs triggering the same rule = count >= 2."""
        events_a = _brute_force_then_login_events(_IP_A, _NOW - timedelta(hours=1))
        events_b = _brute_force_then_login_events(_IP_B, _NOW - timedelta(hours=2))
        client = _make_client(events=events_a + events_b)
        resp = client.get("/escalation/policy")
        body = resp.json()
        rows_by_name = {row["rule_name"]: row for row in body["policy"]}
        assert rows_by_name["brute_force_then_login"]["hit_count_24h"] >= 2, (
            "Expected 2 IPs triggering same rule to produce count >= 2"
        )


# ---------------------------------------------------------------------------
# Determinism regression: single `now` anchor for cutoff + detect() (PR #81
# security review — attempt_pressure is the rule whose hit-count depends on
# `now`, so it is the one that exposes the bug).
# ---------------------------------------------------------------------------


class TestAttemptPressureDeterminism:
    """``_count_rule_hits_24h`` must read ``datetime.now()`` exactly once and
    thread it through to both the store cutoff and ``detect(events, now=...)``.
    Reading it twice (once here, once inside ``detect()`` when ``now`` is
    omitted) lets the two anchors drift apart under load, making
    ``hit_count_24h`` for ``attempt_pressure`` non-deterministic for the same
    stored events.
    """

    def test_attempt_pressure_fires_and_hit_count_is_deterministic(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """5 simultaneous BLOCK events reach peak_intensity == PRESSURE_THRESHOLD,
        firing attempt_pressure exactly once for that IP. Two direct calls to
        ``_count_rule_hits_24h`` against the same fixed clock and the same
        stored events must return the identical, exact count.
        """
        fixed_now = _NOW
        monkeypatch.setattr(escalation, "datetime", _fixed_clock(fixed_now))

        events = _attempt_pressure_events(_IP_A, fixed_now - timedelta(minutes=5))
        store = _FakeStore(events)

        hits_1 = asyncio.run(escalation._count_rule_hits_24h(store))
        hits_2 = asyncio.run(escalation._count_rule_hits_24h(store))

        assert hits_1 == {"attempt_pressure": 1}
        assert hits_2 == {"attempt_pressure": 1}
        assert hits_1 == hits_2, (
            "hit_count_24h must be stable across repeated calls with the "
            "same fixed inputs"
        )

    def test_attempt_pressure_hit_count_via_route_is_stable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Same scenario driven end-to-end through GET /escalation/policy: two
        successive requests against the same fixed clock and stored events
        return the identical hit_count_24h for attempt_pressure.
        """
        fixed_now = _NOW
        monkeypatch.setattr(escalation, "datetime", _fixed_clock(fixed_now))

        events = _attempt_pressure_events(_IP_B, fixed_now - timedelta(minutes=5))
        client = _make_client(events=events)

        resp_1 = client.get("/escalation/policy")
        resp_2 = client.get("/escalation/policy")
        assert resp_1.status_code == 200
        assert resp_2.status_code == 200

        rows_1 = {row["rule_name"]: row for row in resp_1.json()["policy"]}
        rows_2 = {row["rule_name"]: row for row in resp_2.json()["policy"]}
        assert rows_1["attempt_pressure"]["hit_count_24h"] == 1
        assert rows_2["attempt_pressure"]["hit_count_24h"] == 1

    def test_detect_is_never_given_a_second_independent_now(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Structural regression test for the two-anchor bug itself.

        Patches ``firewatch_core.detector``'s own ``datetime`` to raise if
        ``.now()`` is ever called from inside ``detect()``. That only happens
        when ``detect()`` is invoked WITHOUT an explicit ``now`` (its
        ``if now is None: now = datetime.now(...)`` fallback) — i.e. exactly
        the shipped-bug shape where ``_count_rule_hits_24h`` read the wall
        clock once for the store cutoff and let ``detect()`` read it again,
        independently, for its own window checks. With ``now`` threaded
        through explicitly (the fix), that fallback is never reached and this
        raising clock is never called.
        """
        from firewatch_core import detector as detector_module

        class _RaisingClock(datetime):
            @classmethod
            def now(cls, tz: Any = None) -> datetime:  # noqa: ARG003
                raise AssertionError(
                    "detect() read the wall clock independently instead of "
                    "using the `now` anchored by _count_rule_hits_24h"
                )

        monkeypatch.setattr(escalation, "datetime", _fixed_clock(_NOW))
        monkeypatch.setattr(detector_module, "datetime", _RaisingClock)

        events = _attempt_pressure_events(_IP_C, _NOW - timedelta(minutes=5))
        store = _FakeStore(events)

        hits = asyncio.run(escalation._count_rule_hits_24h(store))

        assert hits == {"attempt_pressure": 1}
