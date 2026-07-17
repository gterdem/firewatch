"""Tests for issue #69 — syslog_cef fallback severity recalibration (ADR-0069 D4(b)).

EARS criteria -> test mapping (from issue #69's acceptance criteria):

- WHEN a lone `Failed password`/`publickey` line is normalized on the fallback
  path (non-CEF RFC 5424/3164), the event SHALL be ALERT with severity `low`;
  category string unchanged.
  -> covered in test_cef_plugin.py::TestSyslogFallback
  (test_rfc5424_ssh_bruteforce_fallback_severity_is_low,
  test_rfc3164_ssh_bruteforce_fallback_severity_is_low)

- Must-NOT: an actor whose only signal is failed-login ALERTs, at any count,
  SHALL NOT reach Tier 2 via D1(b) -- routing test through the real qualify
  gate (`firewatch_core.escalation.qualify.qualify`).
  -> TestFailedLoginNeverQualifiesAlone

- The CEF numeric path SHALL be unchanged.
  -> covered in test_cef_plugin.py::TestNormalizeCEF
  (test_cef_numeric_severity_path_unchanged_by_issue_69) and
  tests/golden/test_syslog_cef_golden.py (CEF-path pins, byte-identical).

This file imports ``firewatch_core`` for test-only integration verification
(precedented by the existing entry-point-loader tests in test_cef_plugin.py) --
the plugin's own ``src/`` tree never imports ``firewatch_core`` (PLUGIN_CONTRACT.md,
verified by test_cef_plugin.py::test_no_firewatch_core_import_in_package).

Fixture IPs: RFC 5737 documentation ranges only (203.0.113.0/24).
"""
from __future__ import annotations

from datetime import datetime, timezone

from firewatch_sdk import RawEvent

from firewatch_core.escalation.qualify import qualify
from firewatch_syslog_cef.plugin import SyslogCefSource

_SRC_IP = "203.0.113.9"


def _raw(line: str, client_ip: str = _SRC_IP) -> RawEvent:
    return RawEvent(
        source_type="syslog_cef",
        received_at=datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
        data={"line": line, "client_ip": client_ip, "transport": "udp"},
    )


def _bruteforce_line(port: int = 44321) -> str:
    """Non-CEF RFC 3164 line -- exercises the fallback classifier, not CEF."""
    return (
        f"<134>Jan 15 10:00:01 gateway sshd[1234]: "
        f"Failed password for root from {_SRC_IP} port {port} ssh2"
    )


class TestFailedLoginNeverQualifiesAlone:
    """Must-NOT (ADR-0069 D4(b) / ADR-0067 D1(b)): an actor whose only signal
    is failed-login ALERTs via the syslog_cef fallback path SHALL NOT reach
    Tier 2, at any count -- routed through the real ``qualify()`` gate."""

    def setup_method(self) -> None:
        self.plugin = SyslogCefSource()

    def _normalized_bruteforce_events(self, count: int) -> list:
        return [
            self.plugin.normalize(_raw(_bruteforce_line(port=40000 + i)), source_id="fw-edge")
            for i in range(count)
        ]

    def test_single_failed_login_does_not_qualify(self) -> None:
        events = self._normalized_bruteforce_events(1)
        result = qualify(events, [])
        assert result.qualified is False

    def test_dozens_of_failed_logins_do_not_qualify(self) -> None:
        events = self._normalized_bruteforce_events(50)
        result = qualify(events, [])
        assert result.qualified is False

    def test_qualifying_event_severity_is_none_for_failed_logins_alone(self) -> None:
        events = self._normalized_bruteforce_events(5)
        result = qualify(events, [])
        assert result.qualifying_event_severity is None
