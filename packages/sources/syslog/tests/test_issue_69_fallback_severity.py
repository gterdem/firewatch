"""Tests for issue #69 — syslog fallback severity recalibration (ADR-0069 D4(b)).

EARS criteria -> test mapping (from issue #69's acceptance criteria):

- WHEN a lone `Failed password`/`publickey` line is normalized, the event SHALL
  be ALERT with severity `low`; category string unchanged.
  -> covered in test_plugin.py::TestNormalizeBasic
  (test_ssh_brute_force_severity_is_low, test_ssh_brute_force_category_unchanged_by_recalibration)

- Must-NOT: an actor whose only signal is failed-login ALERTs, at any count,
  SHALL NOT reach Tier 2 via D1(b) -- routing test through the real qualify
  gate (`firewatch_core.escalation.qualify.qualify`). Queue entry for such
  actors belongs to the correlation rules alone (ADR-0070).
  -> TestFailedLoginNeverQualifiesAlone

- Sudo Failure SHALL stay `medium`; SSH Login / generic syslog SHALL stay
  `info`/LOG (asserted, not assumed).
  -> covered in test_plugin.py::TestNormalizeBasic
  (test_sudo_failure_severity_is_medium, test_ssh_login_severity_is_info,
  test_generic_syslog_severity_is_info)

This file imports ``firewatch_core`` for test-only integration verification
(precedented by the existing entry-point-loader tests in test_plugin.py) --
the plugin's own ``src/`` tree never imports ``firewatch_core`` (PLUGIN_CONTRACT.md,
verified by test_plugin.py::test_does_not_import_firewatch_core).

Fixture IPs: RFC 5737 documentation ranges only (203.0.113.0/24).
"""
from __future__ import annotations

from datetime import datetime, timezone

from firewatch_sdk import RawEvent

from firewatch_core.escalation.qualify import qualify
from firewatch_syslog.plugin import SyslogSource

_SRC_IP = "203.0.113.9"


def _raw(line: str, client_ip: str = _SRC_IP) -> RawEvent:
    return RawEvent(
        source_type="syslog",
        received_at=datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
        data={"line": line, "client_ip": client_ip, "transport": "udp"},
    )


def _bruteforce_line(port: int = 44321) -> str:
    return (
        f"<134>Jan 15 10:00:01 gateway sshd[1234]: "
        f"Failed password for root from {_SRC_IP} port {port} ssh2"
    )


class TestFailedLoginNeverQualifiesAlone:
    """Must-NOT (ADR-0069 D4(b) / ADR-0067 D1(b)): an actor whose only signal
    is failed-login ALERTs SHALL NOT reach Tier 2, at any count -- routed
    through the real ``qualify()`` gate, not a synthetic stand-in."""

    def setup_method(self) -> None:
        self.plugin = SyslogSource()

    def _normalized_bruteforce_events(self, count: int) -> list:
        return [
            self.plugin.normalize(_raw(_bruteforce_line(port=40000 + i)), source_id="pi-syslog")
            for i in range(count)
        ]

    def test_single_failed_login_does_not_qualify(self) -> None:
        events = self._normalized_bruteforce_events(1)
        result = qualify(events, [])
        assert result.qualified is False

    def test_dozens_of_failed_logins_do_not_qualify(self) -> None:
        """Volume alone must not open the gate -- that is ADR-0070's job, not
        per-event severity (ADR-0069 D1 corollary: ambient-at-volume -> <= medium)."""
        events = self._normalized_bruteforce_events(50)
        result = qualify(events, [])
        assert result.qualified is False

    def test_qualifying_event_severity_is_none_for_failed_logins_alone(self) -> None:
        events = self._normalized_bruteforce_events(5)
        result = qualify(events, [])
        assert result.qualifying_event_severity is None

    def test_control_high_severity_alert_does_qualify(self) -> None:
        """Control: the gate itself still opens for a genuine high/critical ALERT
        -- proves the previous test's False is the severity downshift, not a
        broken gate."""
        from firewatch_sdk import SecurityEvent

        high_event = SecurityEvent(
            source_type="syslog",
            source_id="pi-syslog",
            source_ip=_SRC_IP,
            action="ALERT",
            severity="high",
            timestamp=datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
        )
        result = qualify([high_event], [])
        assert result.qualified is True
