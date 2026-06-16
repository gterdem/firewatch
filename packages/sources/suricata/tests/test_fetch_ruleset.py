"""Tests for issue #168 — fetch_ruleset maintenance action.

EARS criteria → test mapping
=============================

EARS-168-1 (ubiquitous — action declared):
  metadata().actions SHALL declare exactly fetch_ruleset with long_running=True,
  a confirm text stating ~40-60 MB, and provides=("rule_descriptions",).
  -> TestActionDeclaration.test_metadata_declares_fetch_ruleset
  -> TestActionDeclaration.test_fetch_ruleset_long_running
  -> TestActionDeclaration.test_fetch_ruleset_confirm_mentions_size
  -> TestActionDeclaration.test_fetch_ruleset_provides_rule_descriptions
  -> TestActionDeclaration.test_suricata_source_satisfies_action_capable

EARS-168-2 (event-driven — remote run):
  WHEN run_action("fetch_ruleset") in remote mode, streams rules over SSH,
  parses SID→msg, writes to ctx.kv namespace "rule_descriptions", computes
  SHA-256 streaming, writes ruleset_meta (pulled_at, size_bytes, sha256,
  path, remote mtime/size).
  -> TestRunActionRemote.test_remote_run_writes_rule_descriptions
  -> TestRunActionRemote.test_remote_run_writes_ruleset_meta
  -> TestRunActionRemote.test_remote_run_sha256_in_meta
  -> TestRunActionRemote.test_remote_run_returns_ok_result
  -> TestRunActionRemote.test_remote_run_result_has_rule_count

EARS-168-3 (event-driven — local run):
  WHEN run_action("fetch_ruleset") in local mode, reads local path,
  parses SID→msg, writes to ctx.kv, writes ruleset_meta.
  -> TestRunActionLocal.test_local_run_writes_rule_descriptions
  -> TestRunActionLocal.test_local_run_writes_ruleset_meta

EARS-168-4 (seam — declared->run->KV end-to-end):
  Declared action -> run_action -> KV -> entries visible.
  -> TestSeamEndToEnd.test_declared_action_runs_and_kv_visible

EARS-168-5 (event-driven — per-cycle stat in remote mode):
  WHEN collect() runs in remote mode, the plugin records a cheap remote stat
  (mtime/size ONLY) into ruleset_meta; action_status reads it and may report stale.
  -> TestPerCycleStat.test_collect_remote_records_remote_stat

EARS-168-6 (state-driven — action_status stale detection):
  WHILE recorded remote stat differs from last-download stat, action_status
  returns stale=True with a message carrying both dates.
  WHILE no download has ever run, stale=None.
  action_status MUST NOT open SSH.
  -> TestActionStatus.test_status_stale_when_remote_stat_newer
  -> TestActionStatus.test_status_not_stale_when_stats_match
  -> TestActionStatus.test_status_stale_none_when_no_download
  -> TestActionStatus.test_status_reads_kv_only_no_ssh

EARS-168-7 (unwanted — no auto-download):
  collect() MUST NOT invoke the SSH transfer path.
  -> TestNoAutoDownload.test_collect_does_not_call_run_action
  -> TestNoAutoDownload.test_collect_remote_does_not_transfer_ruleset

EARS-168-8 (unwanted — no-download graceful degradation):
  IF no download has ever been performed, collect/normalize still work.
  -> TestGracefulDegradation.test_no_download_collect_still_yields_events

EARS-168-9 (unwanted — mid-stream failure safety):
  IF SSH transfer fails mid-stream, previously stored rule_descriptions and
  ruleset_meta MUST remain intact; ActionResult MUST be ok=False.
  -> TestFailureSafety.test_mid_stream_ssh_failure_preserves_existing_meta
  -> TestFailureSafety.test_failure_returns_ok_false
  -> TestFailureSafety.test_failure_message_does_not_leak_credentials

EARS-168-10 (unwanted — no unhandled exceptions):
  run_action MUST NOT raise, even on total SSH failure.
  -> TestNoRaise.test_run_action_never_raises_on_connect_error
  -> TestNoRaise.test_run_action_never_raises_on_unexpected_error

EARS-168-11 (producer rework):
  collect() in remote mode MUST NOT parse rules_path as a local file.
  -> TestProducerRework.test_remote_collect_does_not_parse_local_rules_path

EARS-168-12 (msg truncation — security review NB from PR #186):
  rules.py extraction MUST truncate msg values at _MAX_MSG_LEN=512 chars.
  -> TestMsgTruncation.test_overlong_msg_truncated_at_512
  -> TestMsgTruncation.test_normal_msg_not_truncated

All fixtures use RFC 5737 documentation IPs only (192.0.2.x, 198.51.100.x,
203.0.113.x) and RFC1918 / loopback for internal addresses.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from firewatch_sdk import ActionCapable, PluginContext
from firewatch_sdk.testing import InMemoryScopedKV

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_RULE_DESC_NS = "rule_descriptions"
_META_NS = "ruleset_meta"


def _make_ctx(source_id: str = "test-pi") -> PluginContext:
    return PluginContext(kv=InMemoryScopedKV(), source_id=source_id)


def _make_remote_cfg(**overrides: Any) -> Any:
    from firewatch_suricata.config import SuricataConfig

    defaults: dict[str, Any] = {
        "mode": "remote",
        "remote_host": "192.0.2.10",
        "remote_port": 22,
        "remote_user": "pi",
        "rules_path": "/etc/suricata/rules/emerging-all.rules",
        "remote_path": "/var/log/suricata/eve.json",
    }
    defaults.update(overrides)
    return SuricataConfig(**defaults)  # type: ignore[call-arg]


def _make_local_cfg(rules_path: str, local_path: str = "/dev/null") -> Any:
    from firewatch_suricata.config import SuricataConfig

    return SuricataConfig(  # type: ignore[call-arg]
        mode="local",
        local_path=local_path,
        rules_path=rules_path,
    )


def _write_rules_file(path: Path, rules: dict[str, str]) -> None:
    lines = [
        f'alert tcp any any -> any any (msg:"{msg}"; sid:{sid}; rev:1;)'
        for sid, msg in rules.items()
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _make_rules_bytes(rules: dict[str, str]) -> bytes:
    lines = [
        f'alert tcp any any -> any any (msg:"{msg}"; sid:{sid}; rev:1;)'
        for sid, msg in rules.items()
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def _make_ssh_conn_for_ruleset(
    rules_content: bytes,
    *,
    stat_mtime: float = 1_700_000_000.0,
    stat_size: int | None = None,
    check_ok: bool = True,
) -> MagicMock:
    """Build a mock SSH connection that streams rules_content for the ruleset cat command
    and returns stat output for the stat command.
    """
    if stat_size is None:
        stat_size = len(rules_content)

    lines = rules_content.decode("utf-8", errors="replace").splitlines(keepends=True)

    async def _aiter(self_iter: Any) -> Any:  # type: ignore[misc]
        for ln in lines:
            yield ln

    mock_stdout = MagicMock()
    mock_stdout.__aiter__ = _aiter
    mock_process = MagicMock()
    mock_process.stdout = mock_stdout

    mock_acm = AsyncMock()
    mock_acm.__aenter__ = AsyncMock(return_value=mock_process)
    mock_acm.__aexit__ = AsyncMock(return_value=False)

    check_result = MagicMock()
    check_result.stdout = "OK" if check_ok else "FAIL"
    check_result.returncode = 0

    stat_result = MagicMock()
    stat_result.stdout = f"{stat_mtime}\n{stat_size}\n"
    stat_result.returncode = 0

    mock_conn = AsyncMock()
    mock_conn.create_process = MagicMock(return_value=mock_acm)
    mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_conn.__aexit__ = AsyncMock(return_value=False)
    # run() calls: (1) file-check, (2) stat
    mock_conn.run = AsyncMock(side_effect=[check_result, stat_result])

    return mock_conn


def _make_ssh_conn_for_collect_stat(
    *,
    stat_mtime: float = 1_700_000_000.0,
    stat_size: int = 1024,
    eve_lines: list[str] | None = None,
    check_ok: bool = True,
) -> MagicMock:
    """Build a mock SSH connection for a collect cycle that also performs a remote stat."""
    if eve_lines is None:
        eve_lines = []

    async def _aiter(self_iter: Any) -> Any:  # type: ignore[misc]
        for ln in eve_lines:
            yield ln

    mock_stdout = MagicMock()
    mock_stdout.__aiter__ = _aiter
    mock_process = MagicMock()
    mock_process.stdout = mock_stdout

    mock_acm = AsyncMock()
    mock_acm.__aenter__ = AsyncMock(return_value=mock_process)
    mock_acm.__aexit__ = AsyncMock(return_value=False)

    check_result = MagicMock()
    check_result.stdout = "OK" if check_ok else "FAIL"
    check_result.returncode = 0

    stat_result = MagicMock()
    stat_result.stdout = f"{stat_mtime}\n{stat_size}\n"
    stat_result.returncode = 0

    mock_conn = AsyncMock()
    mock_conn.create_process = MagicMock(return_value=mock_acm)
    mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_conn.__aexit__ = AsyncMock(return_value=False)
    # run() calls: (1) file-check for eve.json, (2) stat for rules_path
    mock_conn.run = AsyncMock(side_effect=[check_result, stat_result])

    return mock_conn


# ===========================================================================
# EARS-168-1: Action declaration
# ===========================================================================


class TestActionDeclaration:
    """EARS-168-1 — metadata().actions declares exactly fetch_ruleset."""

    def _plugin(self) -> Any:
        from firewatch_suricata.plugin import SuricataSource
        return SuricataSource()

    def test_metadata_declares_fetch_ruleset(self) -> None:
        plugin = self._plugin()
        action_ids = {a.id for a in plugin.metadata().actions}
        assert "fetch_ruleset" in action_ids, (
            f"fetch_ruleset not declared in metadata().actions; got {action_ids}"
        )

    def test_fetch_ruleset_long_running(self) -> None:
        plugin = self._plugin()
        action = next(a for a in plugin.metadata().actions if a.id == "fetch_ruleset")
        assert action.long_running is True

    def test_fetch_ruleset_confirm_mentions_size(self) -> None:
        """confirm text must mention the approximate download size (~40-60 MB)."""
        plugin = self._plugin()
        action = next(a for a in plugin.metadata().actions if a.id == "fetch_ruleset")
        assert action.confirm is not None, "fetch_ruleset must have a confirm prompt"
        confirm_lower = action.confirm.lower()
        assert "mb" in confirm_lower or "megabyte" in confirm_lower, (
            f"confirm text must mention approximate download size (MB); "
            f"got: {action.confirm!r}"
        )

    def test_fetch_ruleset_provides_rule_descriptions(self) -> None:
        plugin = self._plugin()
        action = next(a for a in plugin.metadata().actions if a.id == "fetch_ruleset")
        assert "rule_descriptions" in action.provides

    def test_suricata_source_satisfies_action_capable(self) -> None:
        plugin = self._plugin()
        assert isinstance(plugin, ActionCapable), (
            "SuricataSource declares actions but does not satisfy ActionCapable protocol"
        )


# ===========================================================================
# EARS-168-2: Remote run_action
# ===========================================================================


class TestRunActionRemote:
    """EARS-168-2 — run_action("fetch_ruleset") in remote mode."""

    @pytest.fixture
    def rules(self) -> dict[str, str]:
        return {
            "2001001": "ET SCAN Potential VNC Scan",
            "2001002": "ET SQL Injection Test",
        }

    async def test_remote_run_writes_rule_descriptions(
        self, rules: dict[str, str]
    ) -> None:
        from firewatch_suricata.plugin import SuricataSource

        content = _make_rules_bytes(rules)
        mock_conn = _make_ssh_conn_for_ruleset(content)
        ctx = _make_ctx()
        cfg = _make_remote_cfg()
        plugin = SuricataSource()

        with patch("firewatch_suricata.ruleset.asyncssh") as mock_ssh:
            mock_ssh.connect = AsyncMock(return_value=mock_conn)
            result = await plugin.run_action("fetch_ruleset", cfg, ctx)

        assert result.ok, f"Expected ok=True; got message={result.message!r}"
        desc1 = await ctx.kv.get(_RULE_DESC_NS, "2001001")
        desc2 = await ctx.kv.get(_RULE_DESC_NS, "2001002")
        assert desc1 == "ET SCAN Potential VNC Scan"
        assert desc2 == "ET SQL Injection Test"

    async def test_remote_run_writes_ruleset_meta(
        self, rules: dict[str, str]
    ) -> None:
        from firewatch_suricata.plugin import SuricataSource

        content = _make_rules_bytes(rules)
        mock_conn = _make_ssh_conn_for_ruleset(
            content, stat_mtime=1_700_000_000.0, stat_size=len(content)
        )
        ctx = _make_ctx()
        cfg = _make_remote_cfg()
        plugin = SuricataSource()

        with patch("firewatch_suricata.ruleset.asyncssh") as mock_ssh:
            mock_ssh.connect = AsyncMock(return_value=mock_conn)
            await plugin.run_action("fetch_ruleset", cfg, ctx)

        pulled_at = await ctx.kv.get(_META_NS, "pulled_at")
        size_bytes = await ctx.kv.get(_META_NS, "size_bytes")
        rule_count = await ctx.kv.get(_META_NS, "rule_count")
        source_path = await ctx.kv.get(_META_NS, "source_path")

        assert pulled_at is not None, "ruleset_meta must have pulled_at"
        assert size_bytes is not None, "ruleset_meta must have size_bytes"
        assert rule_count == str(len(rules)), (
            f"rule_count should be {len(rules)}; got {rule_count!r}"
        )
        assert source_path is not None, "ruleset_meta must have source_path"

    async def test_remote_run_sha256_in_meta(
        self, rules: dict[str, str]
    ) -> None:
        from firewatch_suricata.plugin import SuricataSource

        content = _make_rules_bytes(rules)
        expected_sha = hashlib.sha256(content).hexdigest()

        mock_conn = _make_ssh_conn_for_ruleset(content)
        ctx = _make_ctx()
        cfg = _make_remote_cfg()
        plugin = SuricataSource()

        with patch("firewatch_suricata.ruleset.asyncssh") as mock_ssh:
            mock_ssh.connect = AsyncMock(return_value=mock_conn)
            await plugin.run_action("fetch_ruleset", cfg, ctx)

        sha256 = await ctx.kv.get(_META_NS, "sha256")
        assert sha256 == expected_sha, (
            f"SHA-256 mismatch: expected {expected_sha!r}; got {sha256!r}"
        )

    async def test_remote_run_returns_ok_result(
        self, rules: dict[str, str]
    ) -> None:
        from firewatch_suricata.plugin import SuricataSource

        content = _make_rules_bytes(rules)
        mock_conn = _make_ssh_conn_for_ruleset(content)
        ctx = _make_ctx()
        cfg = _make_remote_cfg()
        plugin = SuricataSource()

        with patch("firewatch_suricata.ruleset.asyncssh") as mock_ssh:
            mock_ssh.connect = AsyncMock(return_value=mock_conn)
            result = await plugin.run_action("fetch_ruleset", cfg, ctx)

        assert result.ok is True

    async def test_remote_run_result_has_rule_count(
        self, rules: dict[str, str]
    ) -> None:
        from firewatch_suricata.plugin import SuricataSource

        content = _make_rules_bytes(rules)
        mock_conn = _make_ssh_conn_for_ruleset(content)
        ctx = _make_ctx()
        cfg = _make_remote_cfg()
        plugin = SuricataSource()

        with patch("firewatch_suricata.ruleset.asyncssh") as mock_ssh:
            mock_ssh.connect = AsyncMock(return_value=mock_conn)
            result = await plugin.run_action("fetch_ruleset", cfg, ctx)

        count_str = str(len(rules))
        assert count_str in result.message or count_str in str(result.detail), (
            f"Rule count ({count_str}) must be visible in result; "
            f"message={result.message!r}, detail={result.detail!r}"
        )


# ===========================================================================
# EARS-168-3: Local run_action
# ===========================================================================


class TestRunActionLocal:
    """EARS-168-3 — run_action("fetch_ruleset") in local mode."""

    async def test_local_run_writes_rule_descriptions(self, tmp_path: Path) -> None:
        from firewatch_suricata.plugin import SuricataSource

        rules = {"2003001": "ET MALWARE Local Test", "2003002": "ET SCAN Local Test"}
        rules_file = tmp_path / "test.rules"
        _write_rules_file(rules_file, rules)

        cfg = _make_local_cfg(rules_path=str(rules_file))
        ctx = _make_ctx()
        plugin = SuricataSource()

        result = await plugin.run_action("fetch_ruleset", cfg, ctx)

        assert result.ok, f"Expected ok=True; got {result.message!r}"
        desc1 = await ctx.kv.get(_RULE_DESC_NS, "2003001")
        desc2 = await ctx.kv.get(_RULE_DESC_NS, "2003002")
        assert desc1 == "ET MALWARE Local Test"
        assert desc2 == "ET SCAN Local Test"

    async def test_local_run_writes_ruleset_meta(self, tmp_path: Path) -> None:
        from firewatch_suricata.plugin import SuricataSource

        rules = {"2003001": "ET MALWARE Local Test"}
        rules_file = tmp_path / "test.rules"
        _write_rules_file(rules_file, rules)

        cfg = _make_local_cfg(rules_path=str(rules_file))
        ctx = _make_ctx()
        plugin = SuricataSource()

        await plugin.run_action("fetch_ruleset", cfg, ctx)

        pulled_at = await ctx.kv.get(_META_NS, "pulled_at")
        sha256 = await ctx.kv.get(_META_NS, "sha256")
        size_bytes = await ctx.kv.get(_META_NS, "size_bytes")
        rule_count = await ctx.kv.get(_META_NS, "rule_count")

        assert pulled_at is not None
        assert sha256 is not None and len(sha256) == 64, (
            "SHA-256 must be a 64-char hex string"
        )
        assert size_bytes is not None
        assert rule_count == "1"


# ===========================================================================
# EARS-168-4: Seam end-to-end
# ===========================================================================


class TestSeamEndToEnd:
    """EARS-168-4 — declared action -> run_action -> KV entries visible."""

    async def test_declared_action_runs_and_kv_visible(self, tmp_path: Path) -> None:
        """The declared fetch_ruleset action, when invoked, produces KV entries."""
        from firewatch_suricata.plugin import SuricataSource

        rules = {"9001001": "ET SEAM End-to-End Test"}
        rules_file = tmp_path / "seam.rules"
        _write_rules_file(rules_file, rules)

        plugin = SuricataSource()
        action_ids = {a.id for a in plugin.metadata().actions}
        assert "fetch_ruleset" in action_ids

        cfg = _make_local_cfg(rules_path=str(rules_file))
        ctx = _make_ctx()

        result = await plugin.run_action("fetch_ruleset", cfg, ctx)
        assert result.ok

        all_descs = await ctx.kv.get_all(_RULE_DESC_NS)
        assert "9001001" in all_descs
        assert all_descs["9001001"] == "ET SEAM End-to-End Test"

        pulled_at = await ctx.kv.get(_META_NS, "pulled_at")
        assert pulled_at is not None


# ===========================================================================
# EARS-168-5: Per-cycle remote stat
# ===========================================================================


class TestPerCycleStat:
    """EARS-168-5 — collect() in remote mode records cheap remote stat."""

    async def test_collect_remote_records_remote_stat(self) -> None:
        """A remote collect cycle writes remote mtime/size into ruleset_meta KV."""
        from firewatch_suricata.plugin import SuricataSource

        mock_conn = _make_ssh_conn_for_collect_stat(
            stat_mtime=1_700_100_000.0,
            stat_size=2048,
            eve_lines=[],
        )
        ctx = _make_ctx()
        cfg = _make_remote_cfg()
        plugin = SuricataSource()

        with patch("firewatch_suricata.collector.asyncssh") as mock_ssh:
            mock_ssh.connect = AsyncMock(return_value=mock_conn)
            _ = [ev async for ev in plugin.collect(cfg, since=None, ctx=ctx)]

        remote_mtime = await ctx.kv.get(_META_NS, "remote_mtime")
        remote_size = await ctx.kv.get(_META_NS, "remote_size")

        assert remote_mtime is not None, (
            "collect() in remote mode must record remote_mtime in ruleset_meta"
        )
        assert remote_size is not None, (
            "collect() in remote mode must record remote_size in ruleset_meta"
        )
        assert remote_mtime == str(1_700_100_000.0)
        assert remote_size == str(2048)


# ===========================================================================
# EARS-168-6: action_status stale detection
# ===========================================================================


class TestActionStatus:
    """EARS-168-6 — action_status reads KV, detects staleness, never opens SSH."""

    async def _seed_meta(
        self,
        ctx: PluginContext,
        *,
        pulled_mtime: float,
        pulled_size: int,
        pulled_at: str = "2026-06-01T00:00:00",
    ) -> None:
        """Write a baseline ruleset_meta as if a prior download completed."""
        await ctx.kv.put(_META_NS, "pulled_at", pulled_at)
        await ctx.kv.put(_META_NS, "download_mtime", str(pulled_mtime))
        await ctx.kv.put(_META_NS, "download_size", str(pulled_size))
        await ctx.kv.put(_META_NS, "sha256", "a" * 64)
        await ctx.kv.put(_META_NS, "size_bytes", str(pulled_size))
        await ctx.kv.put(_META_NS, "rule_count", "100")

    async def test_status_stale_when_remote_stat_newer(self) -> None:
        """stale=True when remote_mtime > download_mtime (sensor file changed)."""
        from firewatch_suricata.plugin import SuricataSource

        ctx = _make_ctx()
        await self._seed_meta(ctx, pulled_mtime=1_000.0, pulled_size=1024)
        await ctx.kv.put(_META_NS, "remote_mtime", str(2_000.0))
        await ctx.kv.put(_META_NS, "remote_size", str(2048))

        cfg = _make_remote_cfg()
        plugin = SuricataSource()
        status = await plugin.action_status("fetch_ruleset", cfg, ctx)

        assert status.stale is True, (
            f"Expected stale=True when remote_mtime > download_mtime; "
            f"got {status.stale!r}"
        )

    async def test_status_not_stale_when_stats_match(self) -> None:
        """stale=False when remote stat matches download stat."""
        from firewatch_suricata.plugin import SuricataSource

        ctx = _make_ctx()
        await self._seed_meta(ctx, pulled_mtime=1_000.0, pulled_size=1024)
        await ctx.kv.put(_META_NS, "remote_mtime", str(1_000.0))
        await ctx.kv.put(_META_NS, "remote_size", str(1024))

        cfg = _make_remote_cfg()
        plugin = SuricataSource()
        status = await plugin.action_status("fetch_ruleset", cfg, ctx)

        assert status.stale is False, (
            f"Expected stale=False when remote stat matches; got {status.stale!r}"
        )

    async def test_status_stale_none_when_no_download(self) -> None:
        """stale=None when no download has ever been performed."""
        from firewatch_suricata.plugin import SuricataSource

        ctx = _make_ctx()
        cfg = _make_remote_cfg()
        plugin = SuricataSource()
        status = await plugin.action_status("fetch_ruleset", cfg, ctx)

        assert status.stale is None, (
            f"Expected stale=None when no download recorded; got {status.stale!r}"
        )

    async def test_status_reads_kv_only_no_ssh(self) -> None:
        """action_status must not open SSH connections."""
        from firewatch_suricata.plugin import SuricataSource

        ctx = _make_ctx()
        cfg = _make_remote_cfg()
        plugin = SuricataSource()

        with patch("firewatch_suricata.ruleset.asyncssh") as mock_ruleset_ssh:
            mock_ruleset_ssh.connect = AsyncMock(
                side_effect=RuntimeError("action_status must not open SSH")
            )
            with patch("firewatch_suricata.collector.asyncssh") as mock_collector_ssh:
                mock_collector_ssh.connect = AsyncMock(
                    side_effect=RuntimeError("action_status must not open SSH")
                )
                status = await plugin.action_status("fetch_ruleset", cfg, ctx)

        assert status is not None


# ===========================================================================
# EARS-168-7: No auto-download
# ===========================================================================


class TestNoAutoDownload:
    """EARS-168-7 — collect() MUST NOT invoke the SSH ruleset transfer path."""

    async def test_collect_does_not_call_run_action(self, tmp_path: Path) -> None:
        """collect() must not call run_action internally."""
        from firewatch_suricata.plugin import SuricataSource

        eve_file = tmp_path / "eve.json"
        eve_file.write_text(
            json.dumps({
                "timestamp": "2026-06-01T10:00:00.000000+0000",
                "event_type": "alert",
                "src_ip": "192.0.2.5",
                "src_port": 44321,
                "dest_ip": "10.0.0.1",
                "dest_port": 80,
                "proto": "TCP",
                "alert": {
                    "action": "allowed",
                    "category": "Test",
                    "signature": "ET TEST",
                    "signature_id": 9999,
                    "severity": 3,
                },
                "flow_id": 1001,
            }) + "\n",
            encoding="utf-8",
        )

        cfg = _make_local_cfg(
            rules_path=str(tmp_path / "fake.rules"),
            local_path=str(eve_file),
        )
        ctx = _make_ctx()
        plugin = SuricataSource()

        called: list[str] = []
        original_run = plugin.run_action

        async def _spy_run_action(
            action_id: str, cfg: Any, ctx: PluginContext
        ) -> Any:
            called.append(action_id)
            return await original_run(action_id, cfg, ctx)

        plugin.run_action = _spy_run_action  # type: ignore[method-assign]
        _ = [ev async for ev in plugin.collect(cfg, since=None, ctx=ctx)]

        assert called == [], (
            f"collect() must not invoke run_action; invoked with: {called}"
        )

    async def test_collect_remote_does_not_transfer_ruleset(self) -> None:
        """Remote collect() must not stream the ruleset file (no ruleset cat command)."""
        from firewatch_suricata.plugin import SuricataSource

        mock_conn = _make_ssh_conn_for_collect_stat(
            stat_mtime=1_700_000_000.0,
            stat_size=1024,
            eve_lines=[],
        )
        ctx = _make_ctx()
        cfg = _make_remote_cfg()
        plugin = SuricataSource()

        with patch("firewatch_suricata.collector.asyncssh") as mock_ssh:
            mock_ssh.connect = AsyncMock(return_value=mock_conn)
            _ = [ev async for ev in plugin.collect(cfg, since=None, ctx=ctx)]

        # create_process is called once for the grep command (eve.json streaming).
        # Check no call is a "cat" of a non-eve-json path.
        call_args_list = mock_conn.create_process.call_args_list
        for c in call_args_list:
            cmd = c.args[0] if c.args else ""
            assert "/etc/suricata" not in cmd, (
                f"collect() must not stream the ruleset via cat; command was: {cmd!r}"
            )


# ===========================================================================
# EARS-168-8: Graceful degradation when no download
# ===========================================================================


class TestGracefulDegradation:
    """EARS-168-8 — no download ever performed -> collect/normalize still work."""

    async def test_no_download_collect_still_yields_events(
        self, tmp_path: Path
    ) -> None:
        """With an empty ruleset_meta, collect() still yields events normally."""
        from firewatch_suricata.plugin import SuricataSource

        eve_file = tmp_path / "eve.json"
        eve_file.write_text(
            json.dumps({
                "timestamp": "2026-06-01T10:00:00.000000+0000",
                "event_type": "alert",
                "src_ip": "198.51.100.5",
                "src_port": 44321,
                "dest_ip": "10.0.0.1",
                "dest_port": 80,
                "proto": "TCP",
                "alert": {
                    "action": "allowed",
                    "category": "Test",
                    "signature": "ET DEGRADE Test",
                    "signature_id": 8888,
                    "severity": 3,
                },
                "flow_id": 1002,
            }) + "\n",
            encoding="utf-8",
        )

        cfg = _make_local_cfg(
            rules_path="",
            local_path=str(eve_file),
        )
        ctx = _make_ctx()
        plugin = SuricataSource()

        events = [ev async for ev in plugin.collect(cfg, since=None, ctx=ctx)]
        assert len(events) == 1, (
            f"Expected 1 event with no download; got {len(events)}"
        )
        event = plugin.normalize(events[0], source_id="test-pi")
        assert event.rule_id == "8888"
        assert event.rule_name is not None


# ===========================================================================
# EARS-168-9: Mid-stream failure safety
# ===========================================================================


class TestFailureSafety:
    """EARS-168-9 — mid-stream SSH failure preserves prior KV state."""

    async def _seed_prior_state(self, ctx: PluginContext) -> None:
        await ctx.kv.put(_RULE_DESC_NS, "1000001", "Prior Good Rule")
        await ctx.kv.put(_META_NS, "pulled_at", "2026-05-01T00:00:00")
        await ctx.kv.put(_META_NS, "sha256", "b" * 64)
        await ctx.kv.put(_META_NS, "size_bytes", "1024")
        await ctx.kv.put(_META_NS, "rule_count", "1")

    async def test_mid_stream_ssh_failure_preserves_existing_meta(self) -> None:
        """If SSH transfer fails, prior ruleset_meta must remain intact."""
        from firewatch_suricata.plugin import SuricataSource

        ctx = _make_ctx()
        await self._seed_prior_state(ctx)

        cfg = _make_remote_cfg()
        plugin = SuricataSource()

        with patch("firewatch_suricata.ruleset.asyncssh") as mock_ssh:
            mock_ssh.connect = AsyncMock(side_effect=OSError("connection refused"))
            mock_ssh.PermissionDenied = Exception
            mock_ssh.DisconnectError = Exception
            result = await plugin.run_action("fetch_ruleset", cfg, ctx)

        assert result.ok is False

        prior_desc = await ctx.kv.get(_RULE_DESC_NS, "1000001")
        prior_pulled_at = await ctx.kv.get(_META_NS, "pulled_at")
        assert prior_desc == "Prior Good Rule", (
            "Prior rule_descriptions must not be overwritten on SSH failure"
        )
        assert prior_pulled_at == "2026-05-01T00:00:00", (
            "Prior pulled_at must not be overwritten on SSH failure"
        )

    async def test_failure_returns_ok_false(self) -> None:
        """Any SSH failure must return ActionResult(ok=False, ...)."""
        from firewatch_suricata.plugin import SuricataSource

        ctx = _make_ctx()
        cfg = _make_remote_cfg()
        plugin = SuricataSource()

        with patch("firewatch_suricata.ruleset.asyncssh") as mock_ssh:
            mock_ssh.connect = AsyncMock(side_effect=OSError("network unreachable"))
            mock_ssh.PermissionDenied = Exception
            mock_ssh.DisconnectError = Exception
            result = await plugin.run_action("fetch_ruleset", cfg, ctx)

        assert result.ok is False

    async def test_failure_message_does_not_leak_credentials(self) -> None:
        """ActionResult message on failure must not contain host/user/key details."""
        from firewatch_suricata.plugin import SuricataSource

        ctx = _make_ctx()
        cfg = _make_remote_cfg(remote_host="192.0.2.99", remote_user="secret_user")
        plugin = SuricataSource()

        with patch("firewatch_suricata.ruleset.asyncssh") as mock_ssh:
            mock_ssh.connect = AsyncMock(
                side_effect=Exception("auth failed for secret_user@192.0.2.99")
            )
            mock_ssh.PermissionDenied = Exception
            mock_ssh.DisconnectError = Exception
            result = await plugin.run_action("fetch_ruleset", cfg, ctx)

        assert result.ok is False
        assert "secret_user" not in result.message, (
            f"Message must not leak credential: {result.message!r}"
        )
        assert "192.0.2.99" not in result.message, (
            f"Message must not leak host IP: {result.message!r}"
        )


# ===========================================================================
# EARS-168-10: run_action MUST NOT raise
# ===========================================================================


class TestNoRaise:
    """EARS-168-10 — run_action never raises, even on total failure."""

    async def test_run_action_never_raises_on_connect_error(self) -> None:
        from firewatch_suricata.plugin import SuricataSource

        ctx = _make_ctx()
        cfg = _make_remote_cfg()
        plugin = SuricataSource()

        with patch("firewatch_suricata.ruleset.asyncssh") as mock_ssh:
            mock_ssh.connect = AsyncMock(side_effect=Exception("total failure"))
            mock_ssh.PermissionDenied = Exception
            mock_ssh.DisconnectError = Exception
            result = await plugin.run_action("fetch_ruleset", cfg, ctx)

        assert isinstance(result.ok, bool)

    async def test_run_action_never_raises_on_unexpected_error(self) -> None:
        from firewatch_suricata.plugin import SuricataSource

        ctx = _make_ctx()
        cfg = _make_remote_cfg()
        plugin = SuricataSource()

        with patch("firewatch_suricata.actions.fetch_ruleset_run") as mock_fetch:
            mock_fetch.side_effect = RuntimeError("unexpected internal error")
            result = await plugin.run_action("fetch_ruleset", cfg, ctx)

        assert isinstance(result.ok, bool)
        assert result.ok is False


# ===========================================================================
# EARS-168-11: Producer rework — remote collect does not parse local rules
# ===========================================================================


class TestProducerRework:
    """EARS-168-11 — remote collect() must not attempt local file parse for rules_path."""

    async def test_remote_collect_does_not_parse_local_rules_path(self) -> None:
        """In remote mode, rules_path is a sensor path, not a local file.

        collect() must not attempt to open it as a local file even if it coincidentally
        exists on the FireWatch host.
        """
        from firewatch_suricata.plugin import SuricataSource

        mock_conn = _make_ssh_conn_for_collect_stat(
            stat_mtime=1_700_000_000.0,
            stat_size=1024,
            eve_lines=[],
        )
        ctx = _make_ctx()
        cfg = _make_remote_cfg(rules_path="/etc/suricata/rules/emerging-all.rules")
        plugin = SuricataSource()

        parse_calls: list[str] = []

        def _spy_parse_file(path: Any) -> dict[str, str]:
            parse_calls.append(f"file:{path}")
            return {}

        def _spy_parse_dir(path: Any) -> dict[str, str]:
            parse_calls.append(f"dir:{path}")
            return {}

        with patch(
            "firewatch_suricata.plugin.parse_rules_file",
            side_effect=_spy_parse_file,
        ):
            with patch(
                "firewatch_suricata.plugin.parse_rules_dir",
                side_effect=_spy_parse_dir,
            ):
                with patch("firewatch_suricata.collector.asyncssh") as mock_ssh:
                    mock_ssh.connect = AsyncMock(return_value=mock_conn)
                    _ = [ev async for ev in plugin.collect(cfg, since=None, ctx=ctx)]

        assert parse_calls == [], (
            f"collect() in remote mode must not call local parse; called: {parse_calls}"
        )


# ===========================================================================
# EARS-168-12: msg truncation at 512 chars
# ===========================================================================


class TestMsgTruncation:
    """EARS-168-12 — rules.py must truncate msg values at _MAX_MSG_LEN=512."""

    def test_overlong_msg_truncated_at_512(self, tmp_path: Path) -> None:
        """A msg: field longer than 512 chars is stored truncated."""
        from firewatch_suricata.rules import _MAX_MSG_LEN, parse_rules_file

        long_msg = "A" * 600
        rules_file = tmp_path / "long.rules"
        rules_file.write_text(
            f'alert tcp any any -> any any (msg:"{long_msg}"; sid:7777; rev:1;)\n',
            encoding="utf-8",
        )

        result = parse_rules_file(rules_file)
        assert "7777" in result
        stored_msg = result["7777"]
        assert len(stored_msg) <= _MAX_MSG_LEN, (
            f"msg must be truncated to {_MAX_MSG_LEN}; got {len(stored_msg)}"
        )

    def test_normal_msg_not_truncated(self, tmp_path: Path) -> None:
        """A msg shorter than 512 chars is stored as-is."""
        from firewatch_suricata.rules import parse_rules_file

        normal_msg = "ET SCAN Potential VNC Scan 2099-01"
        rules_file = tmp_path / "normal.rules"
        rules_file.write_text(
            f'alert tcp any any -> any any (msg:"{normal_msg}"; sid:7778; rev:1;)\n',
            encoding="utf-8",
        )

        result = parse_rules_file(rules_file)
        assert result.get("7778") == normal_msg, (
            f"Normal msg must not be changed; got {result.get('7778')!r}"
        )


# ===========================================================================
# Security review follow-ups (B-1, B-2, NB-1, NB-4, NB-5)
# ===========================================================================


class TestByteCapRemote:
    """B-1 — stream_remote_rules MUST abort when cumulative bytes exceed _MAX_RULES_BYTES.

    Also validates that the full file content is never accumulated in memory: the
    implementation must NOT keep a growing list of chunks across the loop.
    """

    async def test_oversized_stream_returns_ok_false(self) -> None:
        """A mocked stream that exceeds _MAX_RULES_BYTES causes ok=False ActionResult."""
        from firewatch_suricata.plugin import SuricataSource
        from firewatch_suricata.rules import _MAX_RULES_BYTES

        # Build a content block just over the cap so the FIRST line triggers the cap
        # without needing to iterate thousands of tiny lines.
        # Use a single oversized line so the test stays fast.
        oversized_line = "A" * (_MAX_RULES_BYTES + 1)
        # Wrap in a fake rule so it is parseable — the cap should fire first.
        content = oversized_line.encode("utf-8")

        lines = [content.decode("utf-8", errors="replace")]

        async def _aiter(self_iter: Any) -> Any:  # type: ignore[misc]
            for ln in lines:
                yield ln

        mock_stdout = MagicMock()
        mock_stdout.__aiter__ = _aiter
        mock_process = MagicMock()
        mock_process.stdout = mock_stdout

        mock_acm = AsyncMock()
        mock_acm.__aenter__ = AsyncMock(return_value=mock_process)
        mock_acm.__aexit__ = AsyncMock(return_value=False)

        check_result = MagicMock()
        check_result.stdout = "OK"
        check_result.returncode = 0

        stat_result = MagicMock()
        stat_result.stdout = "1700000000\n100\n"
        stat_result.returncode = 0

        mock_conn = AsyncMock()
        mock_conn.create_process = MagicMock(return_value=mock_acm)
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock(return_value=False)
        mock_conn.run = AsyncMock(side_effect=[check_result, stat_result])

        ctx = _make_ctx()
        cfg = _make_remote_cfg()
        plugin = SuricataSource()

        with patch("firewatch_suricata.ruleset.asyncssh") as mock_ssh:
            mock_ssh.connect = AsyncMock(return_value=mock_conn)
            result = await plugin.run_action("fetch_ruleset", cfg, ctx)

        assert result.ok is False, (
            "Expected ok=False when stream exceeds byte cap; "
            f"got ok={result.ok!r} message={result.message!r}"
        )

    async def test_oversized_stream_preserves_prior_kv(self) -> None:
        """When the byte cap is hit, prior KV state must be preserved (no partial write)."""
        from firewatch_suricata.plugin import SuricataSource
        from firewatch_suricata.rules import _MAX_RULES_BYTES

        oversized_line = "B" * (_MAX_RULES_BYTES + 1)
        content = oversized_line.encode("utf-8")
        lines = [content.decode("utf-8", errors="replace")]

        async def _aiter(self_iter: Any) -> Any:  # type: ignore[misc]
            for ln in lines:
                yield ln

        mock_stdout = MagicMock()
        mock_stdout.__aiter__ = _aiter
        mock_process = MagicMock()
        mock_process.stdout = mock_stdout

        mock_acm = AsyncMock()
        mock_acm.__aenter__ = AsyncMock(return_value=mock_process)
        mock_acm.__aexit__ = AsyncMock(return_value=False)

        check_result = MagicMock()
        check_result.stdout = "OK"
        check_result.returncode = 0

        stat_result = MagicMock()
        stat_result.stdout = "1700000000\n100\n"
        stat_result.returncode = 0

        mock_conn = AsyncMock()
        mock_conn.create_process = MagicMock(return_value=mock_acm)
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock(return_value=False)
        mock_conn.run = AsyncMock(side_effect=[check_result, stat_result])

        ctx = _make_ctx()
        # Seed prior state.
        await ctx.kv.put(_META_NS, "pulled_at", "2026-01-01T00:00:00")
        await ctx.kv.put(_META_NS, "sha256", "c" * 64)
        await ctx.kv.put(_RULE_DESC_NS, "9999999", "Prior Rule")

        cfg = _make_remote_cfg()
        plugin = SuricataSource()

        with patch("firewatch_suricata.ruleset.asyncssh") as mock_ssh:
            mock_ssh.connect = AsyncMock(return_value=mock_conn)
            result = await plugin.run_action("fetch_ruleset", cfg, ctx)

        assert result.ok is False
        # Prior KV must be intact.
        assert await ctx.kv.get(_META_NS, "pulled_at") == "2026-01-01T00:00:00"
        assert await ctx.kv.get(_META_NS, "sha256") == "c" * 64
        assert await ctx.kv.get(_RULE_DESC_NS, "9999999") == "Prior Rule"


class TestNoSourceHostInMeta:
    """B-2 — source_host (sensor IP) MUST NOT appear in ruleset_meta KV.

    The ruleset_meta namespace flows to the UI via the actions API (#169).
    Storing the sensor IP would be infrastructure disclosure (MC.1 N1).
    """

    async def test_remote_run_meta_excludes_source_host(self) -> None:
        """After a successful remote fetch, source_host must not be in ruleset_meta."""
        from firewatch_suricata.plugin import SuricataSource

        rules = {"2001001": "ET SCAN Potential VNC Scan"}
        content = _make_rules_bytes(rules)
        mock_conn = _make_ssh_conn_for_ruleset(content)
        ctx = _make_ctx()
        cfg = _make_remote_cfg(remote_host="192.0.2.55")
        plugin = SuricataSource()

        with patch("firewatch_suricata.ruleset.asyncssh") as mock_ssh:
            mock_ssh.connect = AsyncMock(return_value=mock_conn)
            result = await plugin.run_action("fetch_ruleset", cfg, ctx)

        assert result.ok is True
        meta = await ctx.kv.get_all(_META_NS)
        assert "source_host" not in meta, (
            f"source_host must not be stored in ruleset_meta; "
            f"found keys: {list(meta.keys())}"
        )
        # Ensure the sensor IP does not appear anywhere in the stored values either.
        for key, val in meta.items():
            assert "192.0.2.55" not in val, (
                f"Sensor IP leaked into ruleset_meta key {key!r}: {val!r}"
            )

    async def test_local_run_meta_excludes_source_host(self, tmp_path: Path) -> None:
        """After a local fetch, source_host must not be in ruleset_meta."""
        from firewatch_suricata.plugin import SuricataSource

        rules = {"2003001": "ET MALWARE Local Test"}
        rules_file = tmp_path / "test.rules"
        _write_rules_file(rules_file, rules)

        cfg = _make_local_cfg(rules_path=str(rules_file))
        ctx = _make_ctx()
        plugin = SuricataSource()

        result = await plugin.run_action("fetch_ruleset", cfg, ctx)
        assert result.ok is True

        meta = await ctx.kv.get_all(_META_NS)
        assert "source_host" not in meta, (
            f"source_host must not be in ruleset_meta for local mode; "
            f"found keys: {list(meta.keys())}"
        )


class TestNB1SuccessMessageBasename:
    """NB-1 — success message MUST use basename, not full rules_path."""

    async def test_success_message_uses_basename(self, tmp_path: Path) -> None:
        """ActionResult message on success shows filename, not the full sensor path."""
        from firewatch_suricata.plugin import SuricataSource

        rules = {"2003001": "ET MALWARE Local Test"}
        rules_file = tmp_path / "emerging-all.rules"
        _write_rules_file(rules_file, rules)

        cfg = _make_local_cfg(rules_path=str(rules_file))
        ctx = _make_ctx()
        plugin = SuricataSource()

        result = await plugin.run_action("fetch_ruleset", cfg, ctx)
        assert result.ok is True
        # basename must appear
        assert "emerging-all.rules" in result.message, (
            f"Expected basename in message; got: {result.message!r}"
        )
        # full tmp path must NOT appear
        assert str(tmp_path) not in result.message, (
            f"Full path must not appear in message; got: {result.message!r}"
        )


class TestNB4DownloadStatNormalised:
    """NB-4 — download_mtime and download_size stored as normalised float/int strings."""

    async def test_download_stat_values_are_normalised(self) -> None:
        """download_mtime and download_size must be float/int re-serialised strings."""
        from firewatch_suricata.plugin import SuricataSource

        rules = {"2001001": "ET SCAN Test"}
        content = _make_rules_bytes(rules)
        # Give the mock stat output with trailing whitespace to test normalisation.
        mock_conn = _make_ssh_conn_for_ruleset(
            content, stat_mtime=1_700_000_000.0, stat_size=len(content)
        )
        ctx = _make_ctx()
        cfg = _make_remote_cfg()
        plugin = SuricataSource()

        with patch("firewatch_suricata.ruleset.asyncssh") as mock_ssh:
            mock_ssh.connect = AsyncMock(return_value=mock_conn)
            result = await plugin.run_action("fetch_ruleset", cfg, ctx)

        assert result.ok is True
        download_mtime = await ctx.kv.get(_META_NS, "download_mtime")
        download_size = await ctx.kv.get(_META_NS, "download_size")
        assert download_mtime is not None
        assert download_size is not None
        # Must be parseable as float and int respectively.
        assert float(download_mtime) == 1_700_000_000.0, (
            f"download_mtime must be a normalised float string; got {download_mtime!r}"
        )
        assert int(download_size) == len(content), (
            f"download_size must be a normalised int string; got {download_size!r}"
        )


class TestNB5LocalDirByteCap:
    """NB-5 — read_local_rules directory case MUST enforce cumulative byte cap."""

    def test_local_dir_over_cap_raises_transfer_error(self, tmp_path: Path) -> None:
        """A rules dir whose total size exceeds _MAX_RULES_BYTES raises RulesetTransferError."""
        from unittest.mock import patch as _patch

        from firewatch_suricata.ruleset import RulesetTransferError, read_local_rules

        # Create a small rules file that is valid.
        rules_file = tmp_path / "test.rules"
        rules_file.write_text(
            'alert tcp any any -> any any (msg:"Test"; sid:1; rev:1;)\n',
            encoding="utf-8",
        )

        cfg_mock = MagicMock()
        cfg_mock.rules_path = str(tmp_path)

        # _MAX_RULES_BYTES is imported from firewatch_suricata.rules inside
        # read_local_rules at call time.  Patch the source module so the cap
        # fires on any non-empty file.
        with _patch("firewatch_suricata.rules._MAX_RULES_BYTES", 0):
            with pytest.raises(RulesetTransferError, match="size cap"):
                read_local_rules(cfg_mock)
