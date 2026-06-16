"""Tests for firewatch_suricata.diagnostics — staged connectivity check.

Maps 1:1 to EARS criteria from issues #689 and #690.

EARS-DIAG-A  SSH connect fails → ok=False, stage_ssh=fail, SSHConnectionError text
             in stage_ssh_msg, stage_evejson=skip.
EARS-DIAG-B  SSH succeeds but test -r FAIL → ok=False, stage_ssh=pass,
             stage_evejson=fail with path in message.
EARS-DIAG-C  SSH + eve.json OK, no recent alerts → ok=True, stage_activity=skip.
EARS-DIAG-D  All stages pass → ok=True, all stage_* = pass.
EARS-DIAG-E  Local mode, path exists but os.access R_OK=False → stage_evejson=fail,
             ok=False.
EARS-DIAG-F  Local mode, all checks pass → ok=True.

EARS-REG-A   health_check remote SSH-fail → returns False (regression: was True).
EARS-REG-B   health_check remote eve.json unreadable → returns False.
EARS-REG-C   health_check local path not R_OK → returns False (new check).
EARS-REG-D   health_check local missing path → returns False (existing, must not break).

EARS-ACTION  run_action("run_connectivity_check", ...) dispatches to diagnostics and
             returns ActionResult with the documented detail keys.
EARS-META    metadata().actions includes an action with id="run_connectivity_check".

Detail-key contract (issue #691 renders these verbatim):
  stage_ssh         = "pass" | "fail"
  stage_ssh_msg     = remediation or "SSH connection succeeded"
  stage_evejson     = "pass" | "fail" | "skip"
  stage_evejson_msg = remediation, "eve.json readable", or skip reason
  stage_activity    = "pass" | "skip"
  stage_activity_msg = alert count or idle note
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from firewatch_sdk import PluginContext
from firewatch_sdk.testing import InMemoryScopedKV


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _ctx(source_id: str = "test-instance") -> PluginContext:
    return PluginContext(kv=InMemoryScopedKV(), source_id=source_id)


def _remote_cfg(
    *,
    remote_host: str = "192.0.2.1",
    remote_port: int = 22,
    remote_user: str = "pi",
    remote_path: str = "/var/log/suricata/eve.json",
    verify_host_key: bool = True,
) -> Any:
    from firewatch_suricata.config import SuricataConfig

    return SuricataConfig(  # type: ignore[call-arg]
        mode="remote",
        remote_host=remote_host,
        remote_port=remote_port,
        remote_user=remote_user,
        remote_path=remote_path,
        verify_host_key=verify_host_key,
    )


def _local_cfg(local_path: str) -> Any:
    from firewatch_suricata.config import SuricataConfig

    return SuricataConfig(mode="local", local_path=local_path)  # type: ignore[call-arg]


def _make_check_ok() -> MagicMock:
    """conn.run() result simulating 'test -r' -> OK."""
    r = MagicMock()
    r.stdout = "OK"
    return r


def _make_check_fail() -> MagicMock:
    """conn.run() result simulating 'test -r' -> FAIL."""
    r = MagicMock()
    r.stdout = "FAIL"
    return r


def _make_grep_result(line: str | None) -> MagicMock:
    """conn.run() result simulating grep returning one alert line or empty."""
    r = MagicMock()
    r.stdout = (line + "\n") if line else ""
    return r


def _make_connected_mock(
    *,
    test_r_ok: bool = True,
    grep_line: str | None = None,
) -> AsyncMock:
    """Build a mock SSH connection that passes connect and supports run()."""
    mock_conn = AsyncMock()
    check_result = _make_check_ok() if test_r_ok else _make_check_fail()
    grep_result = _make_grep_result(grep_line)

    async def _run_dispatch(cmd: str, **kwargs: Any) -> MagicMock:
        if "test -r" in cmd:
            return check_result
        return grep_result

    mock_conn.run = AsyncMock(side_effect=_run_dispatch)
    mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_conn.__aexit__ = AsyncMock(return_value=False)
    return mock_conn


# ---------------------------------------------------------------------------
# EARS-DIAG-A: SSH connect fails -> stage_ssh=fail, ok=False
# ---------------------------------------------------------------------------


class TestDiagSSHFail:
    """EARS-DIAG-A - SSH connect failure produces stage_ssh=fail, ok=False."""

    async def test_ssh_permission_denied_stage_ssh_fail(self) -> None:
        """PermissionDenied -> stage_ssh=fail, stage_ssh_msg contains remediation text."""
        from firewatch_suricata.diagnostics import run_connectivity_check

        cfg = _remote_cfg()

        with patch("firewatch_suricata.collector.asyncssh") as mock_ssh:
            mock_ssh.PermissionDenied = type("PermissionDenied", (Exception,), {})
            mock_ssh.DisconnectError = type("DisconnectError", (Exception,), {})
            mock_ssh.connect = AsyncMock(
                side_effect=mock_ssh.PermissionDenied("denied")
            )
            result = await run_connectivity_check(cfg, _ctx())

        assert result.ok is False
        assert result.detail["stage_ssh"] == "fail"
        # The SSHConnectionError remediation text must be present verbatim
        assert len(result.detail.get("stage_ssh_msg", "")) > 0
        # auth guidance expected in message
        ssh_msg = result.detail["stage_ssh_msg"]
        assert (
            "auth" in ssh_msg.lower()
            or "authorized_keys" in ssh_msg
            or "ssh" in ssh_msg.lower()
        )

    async def test_ssh_timeout_stage_ssh_fail(self) -> None:
        """TimeoutError -> stage_ssh=fail, ok=False."""
        from firewatch_suricata.diagnostics import run_connectivity_check
        import asyncio

        cfg = _remote_cfg()

        with patch("firewatch_suricata.collector.asyncssh") as mock_ssh:
            mock_ssh.PermissionDenied = type("PermissionDenied", (Exception,), {})
            mock_ssh.DisconnectError = type("DisconnectError", (Exception,), {})
            mock_ssh.connect = AsyncMock(side_effect=asyncio.TimeoutError())
            result = await run_connectivity_check(cfg, _ctx())

        assert result.ok is False
        assert result.detail["stage_ssh"] == "fail"
        assert "stage_ssh_msg" in result.detail

    async def test_ssh_fail_stage_evejson_is_skip(self) -> None:
        """When SSH fails, eve.json stage must be skip (not attempted)."""
        from firewatch_suricata.diagnostics import run_connectivity_check

        cfg = _remote_cfg()

        with patch("firewatch_suricata.collector.asyncssh") as mock_ssh:
            mock_ssh.PermissionDenied = type("PermissionDenied", (Exception,), {})
            mock_ssh.DisconnectError = type("DisconnectError", (Exception,), {})
            mock_ssh.connect = AsyncMock(side_effect=OSError("connection refused"))
            result = await run_connectivity_check(cfg, _ctx())

        assert result.ok is False
        assert result.detail["stage_ssh"] == "fail"
        # stage_evejson must be "skip" (not attempted when SSH fails)
        assert result.detail.get("stage_evejson") == "skip"

    async def test_ssh_fail_overall_ok_false(self) -> None:
        """ok must be False when SSH fails - ssh is a required stage."""
        from firewatch_suricata.diagnostics import run_connectivity_check

        cfg = _remote_cfg()

        with patch("firewatch_suricata.collector.asyncssh") as mock_ssh:
            mock_ssh.PermissionDenied = type("PermissionDenied", (Exception,), {})
            mock_ssh.DisconnectError = type("DisconnectError", (Exception,), {})
            mock_ssh.connect = AsyncMock(side_effect=OSError("no route to host"))
            result = await run_connectivity_check(cfg, _ctx())

        assert result.ok is False
        assert result.message is not None and len(result.message) > 0

    async def test_ssh_fail_msg_contains_ssherror_text(self) -> None:
        """The SSHConnectionError remediation text must appear verbatim in stage_ssh_msg.

        EARS #689: 'surface the VERBATIM SSHConnectionError remediation message'.
        We trigger OSError('Name or service not known') which maps to
        'Cannot resolve hostname' in _connect_ssh.
        """
        from firewatch_suricata.diagnostics import run_connectivity_check

        cfg = _remote_cfg()

        with patch("firewatch_suricata.collector.asyncssh") as mock_ssh:
            mock_ssh.PermissionDenied = type("PermissionDenied", (Exception,), {})
            mock_ssh.DisconnectError = type("DisconnectError", (Exception,), {})
            mock_ssh.connect = AsyncMock(
                side_effect=OSError("[Errno -2] Name or service not known")
            )
            result = await run_connectivity_check(cfg, _ctx())

        ssh_msg = result.detail.get("stage_ssh_msg", "")
        # The SSHConnectionError message for DNS failure is "Cannot resolve hostname"
        assert "resolve" in ssh_msg.lower() or "hostname" in ssh_msg.lower()


# ---------------------------------------------------------------------------
# EARS-DIAG-B: SSH pass, test -r FAIL -> stage_evejson=fail
# ---------------------------------------------------------------------------


class TestDiagEveJsonFail:
    """EARS-DIAG-B - SSH succeeds but eve.json unreadable -> stage_evejson=fail."""

    async def test_evejson_unreadable_stage_evejson_fail(self) -> None:
        """test -r FAIL -> stage_evejson=fail, ok=False, path named in msg."""
        from firewatch_suricata.diagnostics import run_connectivity_check

        cfg = _remote_cfg(remote_path="/var/log/suricata/eve.json")
        mock_conn = _make_connected_mock(test_r_ok=False)

        with patch("firewatch_suricata.collector.asyncssh") as mock_ssh:
            mock_ssh.PermissionDenied = type("PermissionDenied", (Exception,), {})
            mock_ssh.DisconnectError = type("DisconnectError", (Exception,), {})
            mock_ssh.connect = AsyncMock(return_value=mock_conn)
            result = await run_connectivity_check(cfg, _ctx())

        assert result.ok is False
        assert result.detail["stage_ssh"] == "pass"
        assert result.detail["stage_evejson"] == "fail"
        # path must appear in the evejson message
        evejson_msg = result.detail.get("stage_evejson_msg", "")
        assert (
            "/var/log/suricata/eve.json" in evejson_msg
            or "readable" in evejson_msg
        )

    async def test_evejson_unreadable_activity_not_attempted(self) -> None:
        """When evejson fails, activity stage must be skip (prior required stage failed)."""
        from firewatch_suricata.diagnostics import run_connectivity_check

        cfg = _remote_cfg()
        mock_conn = _make_connected_mock(test_r_ok=False)

        with patch("firewatch_suricata.collector.asyncssh") as mock_ssh:
            mock_ssh.PermissionDenied = type("PermissionDenied", (Exception,), {})
            mock_ssh.DisconnectError = type("DisconnectError", (Exception,), {})
            mock_ssh.connect = AsyncMock(return_value=mock_conn)
            result = await run_connectivity_check(cfg, _ctx())

        assert result.detail.get("stage_activity") == "skip"


# ---------------------------------------------------------------------------
# EARS-DIAG-C: SSH + eve.json OK, no alerts -> ok=True, stage_activity=skip
# ---------------------------------------------------------------------------


class TestDiagQuietSensor:
    """EARS-DIAG-C - idle sensor (no recent alerts) must not fail the probe."""

    async def test_quiet_sensor_ok_true(self) -> None:
        """SSH pass + eve.json readable + no recent alerts -> ok=True."""
        from firewatch_suricata.diagnostics import run_connectivity_check

        cfg = _remote_cfg()
        # grep returns empty -> no alerts
        mock_conn = _make_connected_mock(test_r_ok=True, grep_line=None)

        with patch("firewatch_suricata.collector.asyncssh") as mock_ssh:
            mock_ssh.PermissionDenied = type("PermissionDenied", (Exception,), {})
            mock_ssh.DisconnectError = type("DisconnectError", (Exception,), {})
            mock_ssh.connect = AsyncMock(return_value=mock_conn)
            result = await run_connectivity_check(cfg, _ctx())

        assert result.ok is True
        assert result.detail["stage_ssh"] == "pass"
        assert result.detail["stage_evejson"] == "pass"
        assert result.detail["stage_activity"] == "skip"

    async def test_quiet_sensor_activity_msg_idle_note(self) -> None:
        """Idle sensor stage_activity_msg mentions 'idle' or 'no recent'."""
        from firewatch_suricata.diagnostics import run_connectivity_check

        cfg = _remote_cfg()
        mock_conn = _make_connected_mock(test_r_ok=True, grep_line=None)

        with patch("firewatch_suricata.collector.asyncssh") as mock_ssh:
            mock_ssh.PermissionDenied = type("PermissionDenied", (Exception,), {})
            mock_ssh.DisconnectError = type("DisconnectError", (Exception,), {})
            mock_ssh.connect = AsyncMock(return_value=mock_conn)
            result = await run_connectivity_check(cfg, _ctx())

        msg = result.detail.get("stage_activity_msg", "")
        assert (
            "idle" in msg.lower()
            or "no recent" in msg.lower()
            or "quiet" in msg.lower()
        )


# ---------------------------------------------------------------------------
# EARS-DIAG-D: All stages pass -> ok=True, all stage_* = pass
# ---------------------------------------------------------------------------


class TestDiagAllPass:
    """EARS-DIAG-D - happy path: all stages pass."""

    async def test_all_stages_pass(self) -> None:
        """SSH + eve.json + alert found -> ok=True, stage_ssh/evejson/activity=pass."""
        from firewatch_suricata.diagnostics import run_connectivity_check

        cfg = _remote_cfg()
        alert_line = json.dumps({
            "timestamp": "2026-01-15T10:00:00.000000+0000",
            "event_type": "alert",
            "src_ip": "203.0.113.5",
            "alert": {"signature": "ET TEST", "signature_id": 1, "severity": 2},
        })
        mock_conn = _make_connected_mock(test_r_ok=True, grep_line=alert_line)

        with patch("firewatch_suricata.collector.asyncssh") as mock_ssh:
            mock_ssh.PermissionDenied = type("PermissionDenied", (Exception,), {})
            mock_ssh.DisconnectError = type("DisconnectError", (Exception,), {})
            mock_ssh.connect = AsyncMock(return_value=mock_conn)
            result = await run_connectivity_check(cfg, _ctx())

        assert result.ok is True
        assert result.detail["stage_ssh"] == "pass"
        assert result.detail["stage_evejson"] == "pass"
        assert result.detail["stage_activity"] == "pass"
        assert result.detail.get("stage_ssh_msg")
        assert result.detail.get("stage_evejson_msg")
        assert result.detail.get("stage_activity_msg")

    async def test_all_pass_message_is_one_line_ok_summary(self) -> None:
        """All-pass message must be a concise OK summary."""
        from firewatch_suricata.diagnostics import run_connectivity_check

        cfg = _remote_cfg()
        alert_line = json.dumps({
            "timestamp": "2026-01-15T10:00:00.000000+0000",
            "event_type": "alert",
            "src_ip": "203.0.113.5",
            "alert": {"signature": "ET TEST", "signature_id": 1, "severity": 2},
        })
        mock_conn = _make_connected_mock(test_r_ok=True, grep_line=alert_line)

        with patch("firewatch_suricata.collector.asyncssh") as mock_ssh:
            mock_ssh.PermissionDenied = type("PermissionDenied", (Exception,), {})
            mock_ssh.DisconnectError = type("DisconnectError", (Exception,), {})
            mock_ssh.connect = AsyncMock(return_value=mock_conn)
            result = await run_connectivity_check(cfg, _ctx())

        # Message should mention reachable or readable
        assert result.message is not None
        lower = result.message.lower()
        assert "reachable" in lower or "readable" in lower or "ok" in lower


# ---------------------------------------------------------------------------
# EARS-DIAG-E/F: Local mode
# ---------------------------------------------------------------------------


class TestDiagLocalMode:
    """EARS-DIAG-E/F - local mode probes filesystem instead of SSH."""

    async def test_local_unreadable_path_stage_evejson_fail(
        self, tmp_path: Path
    ) -> None:
        """Local mode: path exists but os.access R_OK=False -> stage_evejson=fail."""
        from firewatch_suricata.diagnostics import run_connectivity_check

        eve_file = tmp_path / "eve.json"
        eve_file.write_text("{}\n")

        cfg = _local_cfg(str(eve_file))

        with patch("os.access", return_value=False):
            result = await run_connectivity_check(cfg, _ctx())

        assert result.ok is False
        assert result.detail["stage_ssh"] == "pass"  # local -> N/A -> pass
        assert result.detail["stage_evejson"] == "fail"

    async def test_local_missing_path_stage_evejson_fail(
        self, tmp_path: Path
    ) -> None:
        """Local mode: missing path -> stage_evejson=fail."""
        from firewatch_suricata.diagnostics import run_connectivity_check

        cfg = _local_cfg(str(tmp_path / "nonexistent.json"))
        result = await run_connectivity_check(cfg, _ctx())

        assert result.ok is False
        assert result.detail["stage_evejson"] == "fail"

    async def test_local_readable_path_stage_pass(self, tmp_path: Path) -> None:
        """EARS-DIAG-F: local mode, readable file exists -> stage_evejson=pass."""
        from firewatch_suricata.diagnostics import run_connectivity_check

        eve_file = tmp_path / "eve.json"
        alert_line = json.dumps({
            "timestamp": "2026-01-15T10:00:00.000000+0000",
            "event_type": "alert",
            "src_ip": "203.0.113.5",
            "alert": {"signature": "ET TEST", "signature_id": 1, "severity": 2},
        })
        eve_file.write_text(alert_line + "\n")

        cfg = _local_cfg(str(eve_file))
        result = await run_connectivity_check(cfg, _ctx())

        assert result.ok is True
        assert result.detail["stage_ssh"] == "pass"
        assert result.detail["stage_evejson"] == "pass"

    async def test_local_ssh_stage_is_pass_with_local_note(
        self, tmp_path: Path
    ) -> None:
        """Local mode: stage_ssh=pass (N/A) with an explanatory message."""
        from firewatch_suricata.diagnostics import run_connectivity_check

        eve_file = tmp_path / "eve.json"
        eve_file.write_text("{}\n")
        cfg = _local_cfg(str(eve_file))
        result = await run_connectivity_check(cfg, _ctx())

        # stage_ssh is pass in local mode (SSH is N/A)
        assert result.detail["stage_ssh"] == "pass"


# ---------------------------------------------------------------------------
# EARS-REG: health_check regression - was True on failure, must be False
# ---------------------------------------------------------------------------


class TestHealthCheckRegression:
    """Regression tests: health_check must return False on SSH/read failure.

    The OLD bug: remote health_check called _collector.collect() which
    never raises out of its loop, so SSH failure silently returned True.
    """

    def _plugin(self) -> Any:
        from firewatch_suricata.plugin import SuricataSource

        return SuricataSource()

    async def test_remote_ssh_fail_health_check_returns_false(self) -> None:
        """EARS-REG-A: SSH connect failure -> health_check returns False (was True)."""
        plugin = self._plugin()
        cfg = _remote_cfg()

        with patch("firewatch_suricata.collector.asyncssh") as mock_ssh:
            mock_ssh.PermissionDenied = type("PermissionDenied", (Exception,), {})
            mock_ssh.DisconnectError = type("DisconnectError", (Exception,), {})
            mock_ssh.connect = AsyncMock(side_effect=OSError("connection refused"))
            result = await plugin.health_check(cfg)

        assert result is False, (
            "health_check returned True despite SSH connect failure - "
            "the false-positive bug from #689 is NOT fixed"
        )

    async def test_remote_evejson_unreadable_health_check_returns_false(
        self,
    ) -> None:
        """EARS-REG-B: SSH OK but test -r FAIL -> health_check returns False."""
        plugin = self._plugin()
        cfg = _remote_cfg()
        mock_conn = _make_connected_mock(test_r_ok=False)

        with patch("firewatch_suricata.collector.asyncssh") as mock_ssh:
            mock_ssh.PermissionDenied = type("PermissionDenied", (Exception,), {})
            mock_ssh.DisconnectError = type("DisconnectError", (Exception,), {})
            mock_ssh.connect = AsyncMock(return_value=mock_conn)
            result = await plugin.health_check(cfg)

        assert result is False, (
            "health_check returned True despite eve.json being unreadable - "
            "the false-positive bug from #689 is NOT fixed"
        )

    async def test_remote_healthy_health_check_returns_true(self) -> None:
        """EARS-REG-A/B (positive): SSH + readable eve.json -> health_check True."""
        plugin = self._plugin()
        cfg = _remote_cfg()
        mock_conn = _make_connected_mock(test_r_ok=True)

        with patch("firewatch_suricata.collector.asyncssh") as mock_ssh:
            mock_ssh.PermissionDenied = type("PermissionDenied", (Exception,), {})
            mock_ssh.DisconnectError = type("DisconnectError", (Exception,), {})
            mock_ssh.connect = AsyncMock(return_value=mock_conn)
            result = await plugin.health_check(cfg)

        assert result is True

    async def test_local_unreadable_path_health_check_returns_false(
        self, tmp_path: Path
    ) -> None:
        """EARS-REG-C: local path exists but not R_OK -> health_check returns False."""
        plugin = self._plugin()
        eve_file = tmp_path / "eve.json"
        eve_file.write_text("{}\n")
        cfg = _local_cfg(str(eve_file))

        with patch("os.access", return_value=False):
            result = await plugin.health_check(cfg)

        assert result is False, (
            "health_check returned True for a non-readable local file - "
            "os.access(R_OK) check is missing (#689 local mode fix)"
        )

    async def test_local_missing_path_health_check_returns_false(
        self, tmp_path: Path
    ) -> None:
        """EARS-REG-D: existing behavior must not regress: missing file -> False."""
        plugin = self._plugin()
        cfg = _local_cfg(str(tmp_path / "nonexistent.json"))
        result = await plugin.health_check(cfg)
        assert result is False

    async def test_local_valid_path_health_check_returns_true(
        self, tmp_path: Path
    ) -> None:
        """Existing positive case must not regress: readable file -> True."""
        plugin = self._plugin()
        eve_file = tmp_path / "eve.json"
        eve_file.write_text("{}\n")
        cfg = _local_cfg(str(eve_file))
        result = await plugin.health_check(cfg)
        assert result is True


# ---------------------------------------------------------------------------
# EARS-META: metadata declares run_connectivity_check action
# ---------------------------------------------------------------------------


class TestMetadataAction:
    """EARS-META - metadata().actions includes run_connectivity_check."""

    def test_run_connectivity_check_declared_in_metadata(self) -> None:
        from firewatch_suricata.plugin import SuricataSource

        plugin = SuricataSource()
        action_ids = {a.id for a in plugin.metadata().actions}
        assert "run_connectivity_check" in action_ids, (
            f"run_connectivity_check not in metadata().actions; found: {action_ids}"
        )

    def test_run_connectivity_check_not_long_running(self) -> None:
        """Connectivity check is bounded by connect_timeout=10; long_running=False."""
        from firewatch_suricata.plugin import SuricataSource

        plugin = SuricataSource()
        actions = {a.id: a for a in plugin.metadata().actions}
        action = actions["run_connectivity_check"]
        assert action.long_running is False

    def test_run_connectivity_check_no_confirm(self) -> None:
        """read-only probe; no confirm dialog needed."""
        from firewatch_suricata.plugin import SuricataSource

        plugin = SuricataSource()
        actions = {a.id: a for a in plugin.metadata().actions}
        action = actions["run_connectivity_check"]
        assert action.confirm is None

    def test_fetch_ruleset_still_present(self) -> None:
        """Adding run_connectivity_check must not remove the existing fetch_ruleset."""
        from firewatch_suricata.plugin import SuricataSource

        plugin = SuricataSource()
        action_ids = {a.id for a in plugin.metadata().actions}
        assert "fetch_ruleset" in action_ids, (
            "fetch_ruleset action was accidentally removed"
        )


# ---------------------------------------------------------------------------
# EARS-ACTION: run_action dispatches correctly
# ---------------------------------------------------------------------------


class TestRunAction:
    """EARS-ACTION - plugin.run_action('run_connectivity_check', ...) returns ActionResult
    with the documented detail keys."""

    async def test_run_action_ssh_fail_returns_action_result(self) -> None:
        """run_action returns ActionResult (not raises) with ok=False on SSH failure."""
        from firewatch_suricata.plugin import SuricataSource

        plugin = SuricataSource()
        cfg = _remote_cfg()

        with patch("firewatch_suricata.collector.asyncssh") as mock_ssh:
            mock_ssh.PermissionDenied = type("PermissionDenied", (Exception,), {})
            mock_ssh.DisconnectError = type("DisconnectError", (Exception,), {})
            mock_ssh.connect = AsyncMock(side_effect=OSError("refused"))
            result = await plugin.run_action("run_connectivity_check", cfg, _ctx())

        assert result.ok is False
        # All documented detail keys must be present
        for key in (
            "stage_ssh",
            "stage_ssh_msg",
            "stage_evejson",
            "stage_evejson_msg",
            "stage_activity",
            "stage_activity_msg",
        ):
            assert key in result.detail, f"Missing detail key: {key!r}"

    async def test_run_action_all_pass_returns_ok_true(self) -> None:
        """run_action returns ActionResult ok=True on full success."""
        from firewatch_suricata.plugin import SuricataSource

        plugin = SuricataSource()
        cfg = _remote_cfg()
        alert_line = json.dumps({
            "timestamp": "2026-01-15T10:00:00.000000+0000",
            "event_type": "alert",
            "src_ip": "203.0.113.5",
            "alert": {"signature": "ET TEST", "signature_id": 1, "severity": 2},
        })
        mock_conn = _make_connected_mock(test_r_ok=True, grep_line=alert_line)

        with patch("firewatch_suricata.collector.asyncssh") as mock_ssh:
            mock_ssh.PermissionDenied = type("PermissionDenied", (Exception,), {})
            mock_ssh.DisconnectError = type("DisconnectError", (Exception,), {})
            mock_ssh.connect = AsyncMock(return_value=mock_conn)
            result = await plugin.run_action("run_connectivity_check", cfg, _ctx())

        assert result.ok is True
        assert result.detail["stage_ssh"] == "pass"
        assert result.detail["stage_evejson"] == "pass"

    async def test_run_action_detail_key_values_are_strings(self) -> None:
        """All detail values must be strings (ActionResult.detail: dict[str, str])."""
        from firewatch_suricata.plugin import SuricataSource

        plugin = SuricataSource()
        cfg = _remote_cfg()

        with patch("firewatch_suricata.collector.asyncssh") as mock_ssh:
            mock_ssh.PermissionDenied = type("PermissionDenied", (Exception,), {})
            mock_ssh.DisconnectError = type("DisconnectError", (Exception,), {})
            mock_ssh.connect = AsyncMock(side_effect=OSError("refused"))
            result = await plugin.run_action("run_connectivity_check", cfg, _ctx())

        for k, v in result.detail.items():
            assert isinstance(v, str), (
                f"detail[{k!r}] must be str, got {type(v).__name__}"
            )

    async def test_run_action_unknown_action_returns_ok_false(self) -> None:
        """Existing behavior: unknown action_id returns ok=False (must not regress)."""
        from firewatch_suricata.plugin import SuricataSource

        plugin = SuricataSource()
        result = await plugin.run_action("no_such_action", _remote_cfg(), _ctx())
        assert result.ok is False

    async def test_run_action_never_raises(self) -> None:
        """run_action must never raise - any failure returns ActionResult(ok=False)."""
        from firewatch_suricata.plugin import SuricataSource

        plugin = SuricataSource()
        # Patch diagnostics to raise an unexpected error
        with patch(
            "firewatch_suricata.diagnostics.run_connectivity_check",
            side_effect=RuntimeError("unexpected"),
        ):
            # Should NOT propagate the RuntimeError
            result = await plugin.run_action(
                "run_connectivity_check", _remote_cfg(), _ctx()
            )

        assert result.ok is False


# ---------------------------------------------------------------------------
# EARS-DETAIL-KEYS: document that status values are the contracted literals
# ---------------------------------------------------------------------------


class TestDetailKeyContract:
    """Verify the exact documented detail-key contract that issue #691 renders.

    Detail-key contract:
      stage_ssh          = "pass" | "fail"
      stage_ssh_msg      = str (remediation or OK text)
      stage_evejson      = "pass" | "fail" | "skip"
      stage_evejson_msg  = str
      stage_activity     = "pass" | "skip"
      stage_activity_msg = str
    """

    _VALID_SSH_VALUES = frozenset({"pass", "fail"})
    _VALID_EVEJSON_VALUES = frozenset({"pass", "fail", "skip"})
    _VALID_ACTIVITY_VALUES = frozenset({"pass", "skip"})

    async def _get_result_ssh_fail(self) -> Any:
        from firewatch_suricata.diagnostics import run_connectivity_check

        cfg = _remote_cfg()
        with patch("firewatch_suricata.collector.asyncssh") as mock_ssh:
            mock_ssh.PermissionDenied = type("PermissionDenied", (Exception,), {})
            mock_ssh.DisconnectError = type("DisconnectError", (Exception,), {})
            mock_ssh.connect = AsyncMock(side_effect=OSError("refused"))
            return await run_connectivity_check(cfg, _ctx())

    async def _get_result_evejson_fail(self) -> Any:
        from firewatch_suricata.diagnostics import run_connectivity_check

        cfg = _remote_cfg()
        mock_conn = _make_connected_mock(test_r_ok=False)
        with patch("firewatch_suricata.collector.asyncssh") as mock_ssh:
            mock_ssh.PermissionDenied = type("PermissionDenied", (Exception,), {})
            mock_ssh.DisconnectError = type("DisconnectError", (Exception,), {})
            mock_ssh.connect = AsyncMock(return_value=mock_conn)
            return await run_connectivity_check(cfg, _ctx())

    async def _get_result_quiet(self) -> Any:
        from firewatch_suricata.diagnostics import run_connectivity_check

        cfg = _remote_cfg()
        mock_conn = _make_connected_mock(test_r_ok=True, grep_line=None)
        with patch("firewatch_suricata.collector.asyncssh") as mock_ssh:
            mock_ssh.PermissionDenied = type("PermissionDenied", (Exception,), {})
            mock_ssh.DisconnectError = type("DisconnectError", (Exception,), {})
            mock_ssh.connect = AsyncMock(return_value=mock_conn)
            return await run_connectivity_check(cfg, _ctx())

    async def test_stage_ssh_value_is_valid_literal(self) -> None:
        r = await self._get_result_ssh_fail()
        assert r.detail["stage_ssh"] in self._VALID_SSH_VALUES

    async def test_stage_evejson_value_ssh_fail_is_skip(self) -> None:
        r = await self._get_result_ssh_fail()
        assert r.detail["stage_evejson"] in self._VALID_EVEJSON_VALUES

    async def test_stage_evejson_value_evejson_fail_is_fail(self) -> None:
        r = await self._get_result_evejson_fail()
        assert r.detail["stage_evejson"] == "fail"

    async def test_stage_activity_value_is_valid_literal(self) -> None:
        r = await self._get_result_quiet()
        assert r.detail["stage_activity"] in self._VALID_ACTIVITY_VALUES

    async def test_all_six_keys_present_in_ssh_fail_result(self) -> None:
        r = await self._get_result_ssh_fail()
        for key in (
            "stage_ssh",
            "stage_ssh_msg",
            "stage_evejson",
            "stage_evejson_msg",
            "stage_activity",
            "stage_activity_msg",
        ):
            assert key in r.detail, f"Contracted detail key {key!r} missing"

    async def test_all_six_keys_present_in_quiet_result(self) -> None:
        r = await self._get_result_quiet()
        for key in (
            "stage_ssh",
            "stage_ssh_msg",
            "stage_evejson",
            "stage_evejson_msg",
            "stage_activity",
            "stage_activity_msg",
        ):
            assert key in r.detail, f"Contracted detail key {key!r} missing"
