"""Tests for firewatch_suricata — EARS criteria mapped 1:1.

EARS-1  Entry-point registration and zero-core-edit discovery.
EARS-2  config_schema: fields, SecretStr, JSON Schema if/then/else.
EARS-3  Config env > file > default precedence (ADR-0006).
EARS-4a collect() local mode: yields RawEvents, watermark filtering.
EARS-4b collect() remote/SSH mode: mocked SSH, yields RawEvents.
EARS-4c collect() cancellable: CancelledError propagates.
EARS-4d collect() never raises out of loop: bad JSON / missing file.
EARS-5a normalize() basic: source_type="suricata" constant, source_id passed through,
        action=ALERT for IDS detection, category/severity/rule fields.
EARS-5b normalize() action=BLOCK when alert.action=="blocked".
EARS-5c normalize() MITRE: attack_technique/attack_tactic from mitre_* ET Open tags.
EARS-6  No forbidden imports (no firewatch_core, no legacy).
EARS-7  config_schema descriptions are operator-facing copy — no developer notes (issue #95).

Security fix-up (PR #14):
B1   SSH host-key verification secure-by-default; explicit opt-out logs warning.
B2   Remote mode streams via create_process(); cap applied during iteration.
NB-2 Key path in logger only; user-facing SSHConnectionError is generic.
NB-4 String severity ("critical") falls back to 3 without raising.
NB-5 SECURITY NOTE comment on local_path in config.py (no behavior change).
"""
from __future__ import annotations

import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import SecretStr

from firewatch_sdk import PluginContext, RawEvent
from firewatch_sdk.testing import InMemoryScopedKV

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_eve_alert(
    *,
    ts: str = "2026-01-15T10:00:00.000000+0000",
    src_ip: str = "203.0.113.5",
    src_port: int = 44321,
    dest_ip: str = "10.0.0.1",
    dest_port: int = 80,
    proto: str = "TCP",
    action: str = "allowed",
    category: str = "Web Application Attack",
    signature: str = "ET WEB_SERVER SQL Injection Attempt",
    signature_id: int = 2012345,
    severity: int = 2,
    mitre_technique_id: str | None = None,
    mitre_technique_name: str | None = None,
    mitre_tactic: str | None = None,
    flow_id: int = 999001,
    http_url: str | None = None,
    http_hostname: str | None = None,
) -> dict[str, Any]:
    """Build a minimal Suricata EVE alert JSON dict."""
    alert: dict[str, Any] = {
        "action": action,
        "category": category,
        "signature": signature,
        "signature_id": signature_id,
        "severity": severity,
    }
    if mitre_technique_id:
        alert["metadata"] = {
            "mitre_technique_id": [mitre_technique_id],
            "mitre_technique_name": [mitre_technique_name or ""],
        }
    if mitre_tactic:
        alert.setdefault("metadata", {})["mitre_tactic_id"] = [mitre_tactic]

    eve: dict[str, Any] = {
        "timestamp": ts,
        "event_type": "alert",
        "src_ip": src_ip,
        "src_port": src_port,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "proto": proto,
        "flow_id": flow_id,
        "alert": alert,
    }
    if http_url:
        eve["http"] = {"url": http_url, "hostname": http_hostname or ""}
    return eve


def _raw(data: dict[str, Any]) -> RawEvent:
    return RawEvent(
        source_type="suricata",
        received_at=datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc),
        data=data,
    )


def _ctx(source_id: str = "test-instance") -> PluginContext:
    """Build a throwaway PluginContext for testing (ADR-0027 §2 / InMemoryScopedKV)."""
    return PluginContext(kv=InMemoryScopedKV(), source_id=source_id)


# ---------------------------------------------------------------------------
# EARS-1: Entry-point discovery (modularity proof)
# ---------------------------------------------------------------------------

class TestEntryPointDiscovery:
    """EARS-1 — the package registers SuricataSource under firewatch.sources and is
    discoverable with ZERO edits to firewatch-core."""

    def test_entry_point_is_registered(self) -> None:
        """After `uv pip install -e`, the entry point group lists 'suricata'."""
        from importlib.metadata import entry_points

        eps = entry_points(group="firewatch.sources")
        names = {ep.name for ep in eps}
        assert "suricata" in names, (
            f"'suricata' not found in firewatch.sources entry points. Found: {names}"
        )

    def test_entry_point_loads_to_suricata_source_class(self) -> None:
        """Loading the entry point yields a class whose instance satisfies SourcePlugin."""
        from importlib.metadata import entry_points
        from firewatch_sdk import SourcePlugin

        eps = {ep.name: ep for ep in entry_points(group="firewatch.sources")}
        ep = eps["suricata"]
        cls = ep.load()
        plugin = cls()
        assert isinstance(plugin, SourcePlugin)

    def test_metadata_type_key_is_suricata(self) -> None:
        """metadata().type_key must be exactly 'suricata' — the canonical constant."""
        from firewatch_suricata.plugin import SuricataSource

        plugin = SuricataSource()
        assert plugin.metadata().type_key == "suricata"
        assert plugin.metadata().flavor == "pull"

    def test_zero_core_edits_via_loader(self) -> None:
        """The core loader discovers suricata without any patch — the real test of modularity."""
        from firewatch_core.loader import load_source_plugins

        registry = load_source_plugins()
        assert "suricata" in registry, (
            f"Loader did not find 'suricata'. Registry: {set(registry)}"
        )


# ---------------------------------------------------------------------------
# EARS-2: config_schema — fields, SecretStr, JSON Schema if/then/else
# ---------------------------------------------------------------------------

class TestConfigSchema:
    """EARS-2 — config_schema returns a Pydantic model with the right shape."""

    def setup_method(self) -> None:
        from firewatch_suricata.plugin import SuricataSource
        self.plugin = SuricataSource()
        self.schema_cls = self.plugin.config_schema()

    def test_returns_pydantic_model_class(self) -> None:
        from pydantic import BaseModel
        assert issubclass(self.schema_cls, BaseModel)

    def test_has_mode_field(self) -> None:
        m = self.schema_cls.model_fields
        assert "mode" in m

    def test_local_path_field_exists(self) -> None:
        m = self.schema_cls.model_fields
        assert "local_path" in m

    def test_remote_fields_exist(self) -> None:
        m = self.schema_cls.model_fields
        for field in ("remote_host", "remote_port", "remote_user", "remote_path"):
            assert field in m, f"Missing field: {field}"

    def test_ssh_key_is_secret_str(self) -> None:
        """SSH key field must be SecretStr, never plain str (PLUGIN_CONTRACT.md)."""
        m = self.schema_cls.model_fields
        assert "remote_key" in m
        ann = m["remote_key"].annotation
        # SecretStr or Optional[SecretStr]
        import typing
        args = typing.get_args(ann)
        types_in_ann = {ann} | set(args)
        assert SecretStr in types_in_ann, (
            f"remote_key must be SecretStr; annotation={ann}"
        )

    def test_json_schema_has_if_then_else(self) -> None:
        """JSON Schema must include if/then/else for the local/remote mode toggle (ADR-0019)."""
        schema = self.schema_cls.model_json_schema()
        schema_str = json.dumps(schema)
        # rjsf consumes if/then/else; both keys must be present
        assert "if" in schema or '"if"' in schema_str, "JSON Schema missing 'if'"
        assert "then" in schema or '"then"' in schema_str, "JSON Schema missing 'then'"
        assert "else" in schema or '"else"' in schema_str, "JSON Schema missing 'else'"

    def test_mode_default_is_local(self) -> None:
        cfg = self.schema_cls()
        assert cfg.mode == "local"  # type: ignore[attr-defined]

    def test_remote_port_default_is_22(self) -> None:
        cfg = self.schema_cls()
        assert cfg.remote_port == 22  # type: ignore[attr-defined]

    # ---- D5 reveal-not-require regression tests (issue #49, ADR-0028 D5) ----

    _REMOTE_ONLY_FIELDS = frozenset({
        "remote_host", "remote_port", "remote_user",
        "remote_key", "remote_path", "verify_host_key",
    })

    def test_d5_remote_fields_absent_from_top_level_properties(self) -> None:
        """ADR-0028 D5: remote-only fields must NOT appear in top-level schema properties.

        Regression for issue #49: Pydantic auto-emits all model fields into top-level
        properties; _build_if_then_else must pop them out so rjsf hides them in local mode.
        """
        schema = self.schema_cls.model_json_schema()
        top_level_props = set(schema.get("properties", {}).keys())
        for field in self._REMOTE_ONLY_FIELDS:
            assert field not in top_level_props, (
                f"D5 violation: '{field}' is in top-level schema properties — "
                "rjsf will render it unconditionally in both local and remote mode. "
                "It must only appear in the 'then' branch. (ADR-0028 D5 / issue #49)"
            )

    def test_d5_local_path_absent_from_top_level_properties(self) -> None:
        """ADR-0028 D5: local_path must NOT appear in top-level schema properties.

        It should only appear in the 'else' branch (local mode).
        """
        schema = self.schema_cls.model_json_schema()
        top_level_props = set(schema.get("properties", {}).keys())
        assert "local_path" not in top_level_props, (
            "D5 violation: 'local_path' is in top-level schema properties — "
            "rjsf will render it in remote mode too. "
            "It must only appear in the 'else' branch. (ADR-0028 D5 / issue #49)"
        )

    def test_d5_mode_present_in_top_level_properties(self) -> None:
        """ADR-0028 D5: 'mode' must remain in top-level schema properties (always-shown)."""
        schema = self.schema_cls.model_json_schema()
        top_level_props = set(schema.get("properties", {}).keys())
        assert "mode" in top_level_props, (
            "'mode' must remain at top level — it is the toggle field shown in both modes."
        )

    def test_d5_remote_fields_in_then_branch_with_real_subschemas(self) -> None:
        """ADR-0028 D5: remote-only fields must appear in then.properties with real sub-schemas.

        The sub-schemas must be non-empty dicts (not `{}`), so rjsf renders proper widgets
        when remote mode is revealed.
        """
        schema = self.schema_cls.model_json_schema()
        then_props = schema.get("then", {}).get("properties", {})
        for field in self._REMOTE_ONLY_FIELDS:
            assert field in then_props, (
                f"D5: '{field}' must be in then.properties to be revealed in remote mode."
            )
            sub = then_props[field]
            assert isinstance(sub, dict) and sub, (
                f"D5: then.properties['{field}'] must be a non-empty dict (real sub-schema), "
                f"not empty {{}}. rjsf needs the sub-schema to render the correct widget. "
                f"Got: {sub!r}"
            )

    def test_d5_local_path_in_else_branch_with_real_subschema(self) -> None:
        """ADR-0028 D5: local_path must appear in else.properties with a real sub-schema."""
        schema = self.schema_cls.model_json_schema()
        else_props = schema.get("else", {}).get("properties", {})
        assert "local_path" in else_props, (
            "D5: 'local_path' must be in else.properties to be revealed in local mode."
        )
        sub = else_props["local_path"]
        assert isinstance(sub, dict) and sub, (
            f"D5: else.properties['local_path'] must be a non-empty dict, not empty {{}}. "
            f"Got: {sub!r}"
        )

    def test_d5_then_required_contains_remote_host(self) -> None:
        """ADR-0028 D5: then branch must require remote_host."""
        schema = self.schema_cls.model_json_schema()
        then_required = schema.get("then", {}).get("required", [])
        assert "remote_host" in then_required, (
            "D5: then.required must contain 'remote_host' (issue #49)."
        )

    def test_d5_else_required_contains_local_path(self) -> None:
        """ADR-0028 D5: else branch must require local_path."""
        schema = self.schema_cls.model_json_schema()
        else_required = schema.get("else", {}).get("required", [])
        assert "local_path" in else_required, (
            "D5: else.required must contain 'local_path' (issue #49)."
        )

    # ---- Server-side validation unchanged (schema-emission-only change) ----

    def test_model_validate_local_config_unaffected(self) -> None:
        """Server-side validation for local config must be unaffected by the schema change."""
        cfg = self.schema_cls.model_validate({
            "mode": "local",
            "local_path": "/var/log/suricata/eve.json",
        })
        assert cfg.mode == "local"  # type: ignore[attr-defined]
        assert cfg.local_path == "/var/log/suricata/eve.json"  # type: ignore[attr-defined]

    def test_model_validate_remote_config_unaffected(self) -> None:
        """Server-side validation for remote config must be unaffected by the schema change."""
        cfg = self.schema_cls.model_validate({
            "mode": "remote",
            "remote_host": "192.0.2.1",
            "remote_port": 2222,
        })
        assert cfg.mode == "remote"  # type: ignore[attr-defined]
        assert cfg.remote_host == "192.0.2.1"  # type: ignore[attr-defined]
        assert cfg.remote_port == 2222  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# EARS-3: env > file > default precedence (ADR-0006)
# ---------------------------------------------------------------------------

class TestConfigPrecedence:
    """EARS-3 — env vars override file values which override hardcoded defaults."""

    def test_env_var_overrides_default(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """FIREWATCH_SURICATA_MODE env var overrides the 'local' default."""
        monkeypatch.setenv("FIREWATCH_SURICATA_MODE", "remote")
        # Re-build config from env; the config module must read env at build-time.
        from firewatch_suricata.config import build_config
        cfg = build_config(config_file=None)
        assert cfg.mode == "remote"  # type: ignore[attr-defined]

    def test_file_overrides_default(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """firewatch_config.json 'suricata' section overrides defaults when no env set."""
        monkeypatch.delenv("FIREWATCH_SURICATA_MODE", raising=False)
        monkeypatch.delenv("FIREWATCH_SURICATA_REMOTE_HOST", raising=False)
        config_file = tmp_path / "firewatch_config.json"
        config_file.write_text(json.dumps({"suricata": {"mode": "remote", "remote_host": "pi.local"}}))
        from firewatch_suricata.config import build_config
        cfg = build_config(config_file=config_file)
        assert cfg.mode == "remote"  # type: ignore[attr-defined]
        assert cfg.remote_host == "pi.local"  # type: ignore[attr-defined]

    def test_env_overrides_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Env var wins even when config file says something different."""
        monkeypatch.setenv("FIREWATCH_SURICATA_MODE", "local")
        config_file = tmp_path / "firewatch_config.json"
        config_file.write_text(json.dumps({"suricata": {"mode": "remote"}}))
        from firewatch_suricata.config import build_config
        cfg = build_config(config_file=config_file)
        assert cfg.mode == "local"  # type: ignore[attr-defined]

    def test_missing_config_file_falls_back_to_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """No env, no file → pure defaults."""
        for var in (
            "FIREWATCH_SURICATA_MODE", "FIREWATCH_SURICATA_EVE_PATH",
            "FIREWATCH_SURICATA_REMOTE_HOST", "FIREWATCH_SURICATA_REMOTE_PORT",
            "FIREWATCH_SURICATA_REMOTE_USER", "FIREWATCH_SURICATA_REMOTE_KEY",
            "FIREWATCH_SURICATA_REMOTE_PATH",
        ):
            monkeypatch.delenv(var, raising=False)
        from firewatch_suricata.config import build_config
        cfg = build_config(config_file=None)
        assert cfg.mode == "local"  # type: ignore[attr-defined]
        assert cfg.remote_port == 22  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# EARS-4a: collect() — local mode
# ---------------------------------------------------------------------------

class TestCollectLocal:
    """EARS-4a — local mode reads EVE JSON file, filters by watermark, caps at MAX."""

    def _make_plugin(self) -> Any:
        from firewatch_suricata.plugin import SuricataSource
        return SuricataSource()

    async def test_collect_yields_raw_events_from_file(self, tmp_path: Path) -> None:
        """All alert events in the file are yielded as RawEvents."""
        eve_file = tmp_path / "eve.json"
        alert = _make_eve_alert()
        eve_file.write_text(json.dumps(alert) + "\n")

        plugin = self._make_plugin()
        from firewatch_suricata.config import SuricataConfig
        cfg = SuricataConfig(mode="local", local_path=str(eve_file))  # type: ignore[call-arg]
        events = [ev async for ev in plugin.collect(cfg, since=None, ctx=_ctx())]
        assert len(events) == 1
        assert events[0].source_type == "suricata"
        assert events[0].data["event_type"] == "alert"

    async def test_collect_skips_non_alert_lines(self, tmp_path: Path) -> None:
        """Only event_type=alert lines are yielded; dns/flow/etc. are skipped."""
        eve_file = tmp_path / "eve.json"
        dns_event = {"timestamp": "2026-01-15T10:00:00.000000+0000", "event_type": "dns"}
        alert = _make_eve_alert()
        eve_file.write_text(
            json.dumps(dns_event) + "\n" + json.dumps(alert) + "\n"
        )

        plugin = self._make_plugin()
        from firewatch_suricata.config import SuricataConfig
        cfg = SuricataConfig(mode="local", local_path=str(eve_file))  # type: ignore[call-arg]
        events = [ev async for ev in plugin.collect(cfg, since=None, ctx=_ctx())]
        assert len(events) == 1

    async def test_collect_filters_by_watermark(self, tmp_path: Path) -> None:
        """Events with timestamp <= since are skipped."""
        eve_file = tmp_path / "eve.json"
        old_alert = _make_eve_alert(ts="2026-01-14T09:00:00.000000+0000")
        new_alert = _make_eve_alert(ts="2026-01-15T11:00:00.000000+0000")
        eve_file.write_text(
            json.dumps(old_alert) + "\n" + json.dumps(new_alert) + "\n"
        )

        plugin = self._make_plugin()
        from firewatch_suricata.config import SuricataConfig
        cfg = SuricataConfig(mode="local", local_path=str(eve_file))  # type: ignore[call-arg]
        since = "2026-01-15T10:00:00+00:00"
        events = [ev async for ev in plugin.collect(cfg, since=since, ctx=_ctx())]
        assert len(events) == 1
        assert events[0].data["timestamp"] == "2026-01-15T11:00:00.000000+0000"

    async def test_collect_missing_file_yields_nothing(self, tmp_path: Path) -> None:
        """EARS-4d: missing local file must not raise — yields nothing."""
        plugin = self._make_plugin()
        from firewatch_suricata.config import SuricataConfig
        cfg = SuricataConfig(mode="local", local_path=str(tmp_path / "nonexistent.json"))  # type: ignore[call-arg]
        events = [ev async for ev in plugin.collect(cfg, since=None, ctx=_ctx())]
        assert events == []

    async def test_collect_bad_json_skipped_without_raise(self, tmp_path: Path) -> None:
        """EARS-4d: corrupt lines must be skipped, valid ones still yielded."""
        eve_file = tmp_path / "eve.json"
        alert = _make_eve_alert()
        eve_file.write_text("NOT JSON\n" + json.dumps(alert) + "\n")

        plugin = self._make_plugin()
        from firewatch_suricata.config import SuricataConfig
        cfg = SuricataConfig(mode="local", local_path=str(eve_file))  # type: ignore[call-arg]
        events = [ev async for ev in plugin.collect(cfg, since=None, ctx=_ctx())]
        assert len(events) == 1


# ---------------------------------------------------------------------------
# EARS-4b: collect() — remote/SSH mode (mocked)
# ---------------------------------------------------------------------------

class TestCollectRemote:
    """EARS-4b — remote SSH mode uses mocked asyncssh; no real network.

    After B2, remote mode streams via conn.create_process() so mocks supply
    an async-iterable stdout instead of the previous conn.run() result object.
    """

    def _make_plugin(self) -> Any:
        from firewatch_suricata.plugin import SuricataSource
        return SuricataSource()

    def _make_remote_cfg(self, *, verify_host_key: bool = True) -> Any:
        from firewatch_suricata.config import SuricataConfig
        return SuricataConfig(  # type: ignore[call-arg]
            mode="remote",
            remote_host="192.0.2.1",
            remote_port=22,
            remote_user="pi",
            remote_path="/var/log/suricata/eve.json",
            verify_host_key=verify_host_key,
        )

    @staticmethod
    def _make_process_mock(lines: list[str]) -> MagicMock:
        """Build a mock for conn.create_process() whose stdout is an async iterator.

        asyncssh.create_process uses @async_context_manager so it returns an async
        context manager *object* (not a coroutine) — hence we use MagicMock (not
        AsyncMock) for the outer mock so the async-with block works correctly.
        """

        async def _aiter(self_iter: Any) -> Any:  # type: ignore[misc]
            for ln in lines:
                yield ln

        mock_stdout = MagicMock()
        mock_stdout.__aiter__ = _aiter

        # The process is the value yielded by __aenter__
        mock_process = MagicMock()
        mock_process.stdout = mock_stdout

        # create_process() itself (the @async_context_manager wrapper) is a sync
        # callable that returns an async-cm; mock it accordingly.
        mock_acm = AsyncMock()
        mock_acm.__aenter__ = AsyncMock(return_value=mock_process)
        mock_acm.__aexit__ = AsyncMock(return_value=False)
        return mock_acm

    async def test_collect_remote_yields_raw_events(self) -> None:
        """With mocked SSH, remote collect yields parsed alert RawEvents."""
        alert = _make_eve_alert()
        lines = [json.dumps(alert) + "\n"]

        mock_check_result = MagicMock()
        mock_check_result.stdout = "OK"

        mock_conn = AsyncMock()
        mock_conn.run = AsyncMock(return_value=mock_check_result)
        mock_conn.create_process = MagicMock(return_value=self._make_process_mock(lines))
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock(return_value=False)

        with patch("firewatch_suricata.collector.asyncssh") as mock_asyncssh:
            mock_asyncssh.connect = AsyncMock(return_value=mock_conn)
            plugin = self._make_plugin()
            cfg = self._make_remote_cfg()
            events = [ev async for ev in plugin.collect(cfg, since=None, ctx=_ctx())]

        assert len(events) == 1
        assert events[0].source_type == "suricata"
        assert events[0].data["src_ip"] == "203.0.113.5"

    async def test_collect_remote_ssh_error_yields_nothing_no_raise(self) -> None:
        """EARS-4d: SSH failure must not raise out of the loop — yields nothing."""
        with patch("firewatch_suricata.collector.asyncssh") as mock_asyncssh:
            mock_asyncssh.connect = AsyncMock(side_effect=OSError("connection refused"))
            mock_asyncssh.PermissionDenied = Exception
            mock_asyncssh.DisconnectError = Exception
            plugin = self._make_plugin()
            cfg = self._make_remote_cfg()
            events = [ev async for ev in plugin.collect(cfg, since=None, ctx=_ctx())]

        assert events == []

    async def test_collect_remote_filters_by_watermark(self) -> None:
        """Remote mode respects the since watermark the same as local."""
        old_alert = _make_eve_alert(ts="2026-01-14T09:00:00.000000+0000")
        new_alert = _make_eve_alert(ts="2026-01-15T11:00:00.000000+0000")
        lines = [json.dumps(old_alert) + "\n", json.dumps(new_alert) + "\n"]

        mock_check_result = MagicMock()
        mock_check_result.stdout = "OK"

        mock_conn = AsyncMock()
        mock_conn.run = AsyncMock(return_value=mock_check_result)
        mock_conn.create_process = MagicMock(return_value=self._make_process_mock(lines))
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock(return_value=False)

        with patch("firewatch_suricata.collector.asyncssh") as mock_asyncssh:
            mock_asyncssh.connect = AsyncMock(return_value=mock_conn)
            plugin = self._make_plugin()
            cfg = self._make_remote_cfg()
            events = [ev async for ev in plugin.collect(cfg, since="2026-01-15T10:00:00+00:00", ctx=_ctx())]

        assert len(events) == 1
        assert events[0].data["timestamp"] == "2026-01-15T11:00:00.000000+0000"

    async def test_collect_remote_no_alerts_yields_nothing(self) -> None:
        """Empty remote stdout (no matching lines) yields nothing."""
        mock_check_result = MagicMock()
        mock_check_result.stdout = "OK"

        mock_conn = AsyncMock()
        mock_conn.run = AsyncMock(return_value=mock_check_result)
        mock_conn.create_process = MagicMock(return_value=self._make_process_mock([]))
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock(return_value=False)

        with patch("firewatch_suricata.collector.asyncssh") as mock_asyncssh:
            mock_asyncssh.connect = AsyncMock(return_value=mock_conn)
            plugin = self._make_plugin()
            cfg = self._make_remote_cfg()
            events = [ev async for ev in plugin.collect(cfg, since=None, ctx=_ctx())]

        assert events == []



# ---------------------------------------------------------------------------
# EARS-4c: collect() is cancellable
# ---------------------------------------------------------------------------

class TestCollectCancellable:
    """EARS-4c — asyncio.CancelledError propagates cleanly from collect()."""

    async def test_cancellation_propagates(self, tmp_path: Path) -> None:
        """CancelledError is not swallowed inside collect()."""
        # Write many lines so the generator has work to do
        eve_file = tmp_path / "eve.json"
        alert = _make_eve_alert()
        lines = "\n".join(json.dumps(alert) for _ in range(100)) + "\n"
        eve_file.write_text(lines)

        from firewatch_suricata.plugin import SuricataSource
        from firewatch_suricata.config import SuricataConfig
        plugin = SuricataSource()
        cfg = SuricataConfig(mode="local", local_path=str(eve_file))  # type: ignore[call-arg]

        async def _consumer() -> list[RawEvent]:
            results: list[RawEvent] = []
            async for ev in plugin.collect(cfg, since=None, ctx=_ctx()):
                results.append(ev)
                if len(results) >= 2:
                    raise asyncio.CancelledError()
            return results

        task = asyncio.create_task(_consumer())
        with pytest.raises(asyncio.CancelledError):
            await task


# ---------------------------------------------------------------------------
# EARS-5a: normalize() — basic fields
# ---------------------------------------------------------------------------

class TestNormalizeBasic:
    """EARS-5a — normalize sets source_type="suricata" as a constant, passes
    source_id through, sets action=ALERT for IDS, populates required fields."""

    def setup_method(self) -> None:
        from firewatch_suricata.plugin import SuricataSource
        self.plugin = SuricataSource()

    def test_source_type_is_constant_suricata(self) -> None:
        """source_type must always be 'suricata' regardless of source_id (Flag B)."""
        raw = _raw(_make_eve_alert())
        event = self.plugin.normalize(raw, source_id="pi-home")
        assert event.source_type == "suricata"

    def test_source_id_passed_through(self) -> None:
        """source_id is the user's instance name; passed through, not invented."""
        raw = _raw(_make_eve_alert())
        event = self.plugin.normalize(raw, source_id="pi-home")
        assert event.source_id == "pi-home"

    def test_source_id_different_instance(self) -> None:
        """source_type stays 'suricata' regardless of source_id value (no branching)."""
        raw = _raw(_make_eve_alert())
        event = self.plugin.normalize(raw, source_id="azure-lab")
        assert event.source_type == "suricata"
        assert event.source_id == "azure-lab"

    def test_action_is_alert_for_ids_detection(self) -> None:
        """IDS detection with alert.action='allowed' → SecurityEvent.action=ALERT (ADR-0012)."""
        raw = _raw(_make_eve_alert(action="allowed"))
        event = self.plugin.normalize(raw, source_id="pi-home")
        assert event.action == "ALERT"

    def test_severity_mapping_critical(self) -> None:
        """Suricata severity=1 → critical."""
        raw = _raw(_make_eve_alert(severity=1))
        event = self.plugin.normalize(raw, source_id="pi-home")
        assert event.severity == "critical"

    def test_severity_mapping_high(self) -> None:
        raw = _raw(_make_eve_alert(severity=2))
        event = self.plugin.normalize(raw, source_id="pi-home")
        assert event.severity == "high"

    def test_severity_mapping_medium(self) -> None:
        raw = _raw(_make_eve_alert(severity=3))
        event = self.plugin.normalize(raw, source_id="pi-home")
        assert event.severity == "medium"

    def test_severity_mapping_low(self) -> None:
        raw = _raw(_make_eve_alert(severity=4))
        event = self.plugin.normalize(raw, source_id="pi-home")
        assert event.severity == "low"

    def test_rule_id_from_signature_id(self) -> None:
        raw = _raw(_make_eve_alert(signature_id=2012345))
        event = self.plugin.normalize(raw, source_id="pi-home")
        assert event.rule_id == "2012345"

    def test_rule_name_from_signature(self) -> None:
        raw = _raw(_make_eve_alert(signature="ET WEB_SERVER SQL Injection Attempt"))
        event = self.plugin.normalize(raw, source_id="pi-home")
        assert event.rule_name == "ET WEB_SERVER SQL Injection Attempt"

    def test_category_from_alert_category(self) -> None:
        raw = _raw(_make_eve_alert(category="Web Application Attack"))
        event = self.plugin.normalize(raw, source_id="pi-home")
        assert event.category == "Web Attack (IDS)"

    def test_unknown_category_falls_back_to_ids_alert(self) -> None:
        raw = _raw(_make_eve_alert(category="Something Completely New"))
        event = self.plugin.normalize(raw, source_id="pi-home")
        assert event.category == "IDS Alert"

    def test_source_ip_and_destination_ip_populated(self) -> None:
        raw = _raw(_make_eve_alert(src_ip="203.0.113.5", dest_ip="10.0.0.1"))
        event = self.plugin.normalize(raw, source_id="pi-home")
        assert event.source_ip == "203.0.113.5"
        assert event.destination_ip == "10.0.0.1"

    def test_ports_populated(self) -> None:
        raw = _raw(_make_eve_alert(src_port=44321, dest_port=80))
        event = self.plugin.normalize(raw, source_id="pi-home")
        assert event.source_port == 44321
        assert event.destination_port == 80

    def test_protocol_populated(self) -> None:
        raw = _raw(_make_eve_alert(proto="TCP"))
        event = self.plugin.normalize(raw, source_id="pi-home")
        assert event.protocol == "TCP"

    def test_source_event_id_from_flow_id(self) -> None:
        raw = _raw(_make_eve_alert(flow_id=999001))
        event = self.plugin.normalize(raw, source_id="pi-home")
        assert event.source_event_id == "999001"

    def test_http_payload_snippet(self) -> None:
        raw = _raw(_make_eve_alert(http_url="/admin?id=1 OR 1=1", http_hostname="10.0.0.1"))
        event = self.plugin.normalize(raw, source_id="pi-home")
        assert event.payload_snippet is not None
        assert "/admin" in event.payload_snippet

    def test_payload_snippet_truncated_to_500(self) -> None:
        long_url = "/path?" + "a" * 600
        raw = _raw(_make_eve_alert(http_url=long_url))
        event = self.plugin.normalize(raw, source_id="pi-home")
        assert event.payload_snippet is not None
        assert len(event.payload_snippet) <= 500

    def test_timestamp_from_eve_json(self) -> None:
        raw = _raw(_make_eve_alert(ts="2026-01-15T10:30:00.000000+0000"))
        event = self.plugin.normalize(raw, source_id="pi-home")
        assert event.timestamp.year == 2026
        assert event.timestamp.month == 1
        assert event.timestamp.day == 15

    def test_raw_log_preserved(self) -> None:
        """The original EVE dict is stored in raw_log for drill-down."""
        data = _make_eve_alert()
        raw = _raw(data)
        event = self.plugin.normalize(raw, source_id="pi-home")
        assert event.raw_log is not None
        assert event.raw_log.get("event_type") == "alert"


# ---------------------------------------------------------------------------
# EARS-5b: normalize() — action=BLOCK for blocked
# ---------------------------------------------------------------------------

class TestNormalizeActionBlock:
    """EARS-5b — IPS mode: alert.action='blocked' → SecurityEvent.action=BLOCK."""

    def test_action_block_when_suricata_blocked(self) -> None:
        from firewatch_suricata.plugin import SuricataSource
        plugin = SuricataSource()
        raw = _raw(_make_eve_alert(action="blocked"))
        event = plugin.normalize(raw, source_id="pi-home")
        assert event.action == "BLOCK"

    def test_action_alert_for_any_non_blocked(self) -> None:
        """Any action other than 'blocked' (e.g. 'allowed', '') → ALERT."""
        from firewatch_suricata.plugin import SuricataSource
        plugin = SuricataSource()
        for action_str in ("allowed", "", "unknown"):
            raw = _raw(_make_eve_alert(action=action_str))
            event = plugin.normalize(raw, source_id="pi-home")
            assert event.action == "ALERT", f"Expected ALERT for action={action_str!r}"


# ---------------------------------------------------------------------------
# EARS-5c: normalize() — MITRE ATT&CK from ET Open mitre_* tags (ADR-0014)
# ---------------------------------------------------------------------------

class TestNormalizeMitre:
    """EARS-5c — attack_technique/attack_tactic populated from ET Open metadata."""

    def setup_method(self) -> None:
        from firewatch_suricata.plugin import SuricataSource
        self.plugin = SuricataSource()

    def test_attack_technique_from_mitre_technique_id(self) -> None:
        """alert.metadata.mitre_technique_id → SecurityEvent.attack_technique."""
        raw = _raw(_make_eve_alert(mitre_technique_id="T1190"))
        event = self.plugin.normalize(raw, source_id="pi-home")
        assert event.attack_technique == "T1190"

    def test_attack_tactic_from_mitre_tactic_id(self) -> None:
        """alert.metadata.mitre_tactic_id → SecurityEvent.attack_tactic."""
        data = _make_eve_alert(mitre_technique_id="T1190", mitre_tactic="TA0001")
        raw = _raw(data)
        event = self.plugin.normalize(raw, source_id="pi-home")
        assert event.attack_tactic == "TA0001"

    def test_no_mitre_tags_leaves_fields_none(self) -> None:
        """When ET Open provides no MITRE metadata, fields are None — no error."""
        raw = _raw(_make_eve_alert())  # no mitre_technique_id
        event = self.plugin.normalize(raw, source_id="pi-home")
        assert event.attack_technique is None
        assert event.attack_tactic is None

    def test_mitre_technique_list_takes_first(self) -> None:
        """ET Open sometimes emits multiple technique IDs; take the first."""
        data = _make_eve_alert()
        data["alert"]["metadata"] = {
            "mitre_technique_id": ["T1059", "T1190"],
        }
        raw = _raw(data)
        event = self.plugin.normalize(raw, source_id="pi-home")
        assert event.attack_technique == "T1059"


# ---------------------------------------------------------------------------
# EARS-6: no forbidden imports
# ---------------------------------------------------------------------------

class TestNoForbiddenImports:
    """EARS-6 — firewatch_suricata must depend only on firewatch_sdk; never core or legacy."""

    def _get_suricata_modules(self) -> list[str]:
        return [
            name for name in sys.modules
            if name.startswith("firewatch_suricata")
        ]

    def test_does_not_import_firewatch_core(self) -> None:
        """After importing the full plugin package, firewatch_core must not be loaded."""
        # Re-import to ensure all submodules are loaded
        import firewatch_suricata.plugin  # noqa: F401
        import firewatch_suricata.collector  # noqa: F401
        import firewatch_suricata.normalize  # noqa: F401
        import firewatch_suricata.config  # noqa: F401

        # firewatch_core may have been imported by other tests (e.g. loader test).
        # We check that suricata modules don't *directly* depend on core by
        # verifying none of the suricata source files contain "firewatch_core".
        suricata_src = Path(__file__).parent.parent / "src" / "firewatch_suricata"
        for py_file in suricata_src.glob("*.py"):
            content = py_file.read_text()
            assert "firewatch_core" not in content, (
                f"{py_file.name} imports firewatch_core — forbidden (PLUGIN_CONTRACT.md)"
            )

    def test_does_not_import_legacy(self) -> None:
        """No suricata source file may import legacy/."""
        import re
        # Match actual import statements only (not docstrings referencing legacy/ paths).
        # Patterns: "import legacy" or "from legacy" on their own import line.
        import_re = re.compile(r"^\s*(from legacy|import legacy)\b", re.MULTILINE)
        suricata_src = Path(__file__).parent.parent / "src" / "firewatch_suricata"
        for py_file in suricata_src.glob("*.py"):
            content = py_file.read_text()
            match = import_re.search(content)
            assert match is None, (
                f"{py_file.name} imports legacy — forbidden (PLUGIN_CONTRACT.md): {match.group()!r}"
            )

    def test_only_firewatch_sdk_from_firewatch_namespace(self) -> None:
        """Imports from firewatch_* namespace must be firewatch_sdk only."""
        suricata_src = Path(__file__).parent.parent / "src" / "firewatch_suricata"
        for py_file in suricata_src.glob("*.py"):
            content = py_file.read_text()
            # Allow firewatch_sdk and firewatch_suricata itself; disallow others.
            for line in content.splitlines():
                stripped = line.strip()
                if stripped.startswith("from firewatch_") or stripped.startswith("import firewatch_"):
                    assert "firewatch_sdk" in stripped or "firewatch_suricata" in stripped, (
                        f"{py_file.name}: forbidden import line: {stripped!r}"
                    )

# ---------------------------------------------------------------------------
# B1: SSH host-key verification secure-by-default
# ---------------------------------------------------------------------------


class TestSSHHostKeyVerification:
    """B1 — host-key verification is ON by default; opt-out logs a warning."""

    def _make_remote_cfg(self, *, verify_host_key: bool = True) -> Any:
        from firewatch_suricata.config import SuricataConfig
        return SuricataConfig(  # type: ignore[call-arg]
            mode="remote",
            remote_host="192.0.2.1",
            verify_host_key=verify_host_key,
        )

    def test_verify_host_key_default_is_true(self) -> None:
        """SuricataConfig must default verify_host_key to True (secure-by-default)."""
        from firewatch_suricata.config import SuricataConfig
        cfg = SuricataConfig(mode="remote", remote_host="192.0.2.1")  # type: ignore[call-arg]
        assert cfg.verify_host_key is True  # type: ignore[attr-defined]

    def test_verify_host_key_schema_field_exists(self) -> None:
        """verify_host_key must be a declared field with a security-oriented description."""
        from firewatch_suricata.config import SuricataConfig
        fields = SuricataConfig.model_fields
        assert "verify_host_key" in fields
        desc = fields["verify_host_key"].description or ""
        assert "MITM" in desc or "known_hosts" in desc, (
            "verify_host_key description should mention MITM risk or known_hosts"
        )

    async def test_secure_default_does_not_pass_known_hosts_none(self) -> None:
        """When verify_host_key=True, known_hosts=None must NOT be passed to asyncssh."""
        connect_kwargs: dict[str, Any] = {}

        async def _capture_connect(**kw: Any) -> Any:
            connect_kwargs.update(kw)
            raise OSError("test sentinel")  # abort the connection

        with patch("firewatch_suricata.collector.asyncssh") as mock_asyncssh:
            mock_asyncssh.connect = _capture_connect
            mock_asyncssh.PermissionDenied = Exception
            mock_asyncssh.DisconnectError = Exception

            from firewatch_suricata.plugin import SuricataSource
            plugin = SuricataSource()
            cfg = self._make_remote_cfg(verify_host_key=True)
            _ = [ev async for ev in plugin.collect(cfg, since=None, ctx=_ctx())]

        # known_hosts=None is the insecure override; it must be absent
        assert "known_hosts" not in connect_kwargs, (
            "known_hosts kwarg was passed to asyncssh.connect — that disables "
            "host-key verification and is only allowed when verify_host_key=False"
        )

    async def test_opt_out_sets_known_hosts_none_and_logs_warning(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        """When verify_host_key=False, known_hosts=None is set and a warning is logged."""
        connect_kwargs: dict[str, Any] = {}

        async def _capture_connect(**kw: Any) -> Any:
            connect_kwargs.update(kw)
            raise OSError("test sentinel")

        import logging
        with caplog.at_level(logging.WARNING, logger="firewatch.suricata.collector"):
            with patch("firewatch_suricata.collector.asyncssh") as mock_asyncssh:
                mock_asyncssh.connect = _capture_connect
                mock_asyncssh.PermissionDenied = Exception
                mock_asyncssh.DisconnectError = Exception

                from firewatch_suricata.plugin import SuricataSource
                plugin = SuricataSource()
                cfg = self._make_remote_cfg(verify_host_key=False)
                _ = [ev async for ev in plugin.collect(cfg, since=None, ctx=_ctx())]

        assert connect_kwargs.get("known_hosts") is None, (
            "known_hosts=None must be passed to asyncssh.connect when verify_host_key=False"
        )
        warning_text = " ".join(caplog.messages)
        assert "MITM" in warning_text or "host-key" in warning_text or "disabled" in warning_text, (
            "A warning about disabled host-key verification must be logged"
        )

    def test_no_ssh_strict_host_keys_env_var(self) -> None:
        """FIREWATCH_SSH_STRICT_HOST_KEYS must NOT be used — it was an inverted insecure default."""
        # Check the collector module source, not the test
        collector_path = (
            __import__("pathlib").Path(__file__).parent.parent
            / "src" / "firewatch_suricata" / "collector.py"
        )
        collector_content = collector_path.read_text()
        # The old env var must not appear in the implementation
        assert "FIREWATCH_SSH_STRICT_HOST_KEYS" not in collector_content, (
            "FIREWATCH_SSH_STRICT_HOST_KEYS env var found in collector.py — it was "
            "removed as part of B1 (inverted insecure default). Use verify_host_key config."
        )


# ---------------------------------------------------------------------------
# B2: Remote mode streaming — memory bounded by MAX_EVENTS_PER_COLLECT
# ---------------------------------------------------------------------------


class TestRemoteStreamingCap:
    """B2 — remote mode uses create_process() and caps during iteration."""

    @staticmethod
    def _make_process_mock(lines: list[str]) -> MagicMock:
        """Build a mock for conn.create_process() whose stdout is an async iterator.

        Returns the async-context-manager object (what @async_context_manager wraps
        create_process into) whose __aenter__ yields the process with a streaming stdout.
        """

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
        return mock_acm

    async def test_remote_cap_applied_during_iteration(self) -> None:
        """B2: when the remote stream has more lines than MAX_EVENTS_PER_COLLECT,
        at most MAX_EVENTS_PER_COLLECT events are yielded."""
        from firewatch_suricata.collector import MAX_EVENTS_PER_COLLECT

        # Build a stream with cap+10 alert lines
        over_cap = MAX_EVENTS_PER_COLLECT + 10
        lines = [json.dumps(_make_eve_alert(ts="2026-01-15T12:00:00.000000+0000")) + "\n"
                 for _ in range(over_cap)]

        mock_check_result = MagicMock()
        mock_check_result.stdout = "OK"

        mock_conn = AsyncMock()
        mock_conn.run = AsyncMock(return_value=mock_check_result)

        lines_consumed: list[int] = [0]

        async def _tracking_aiter(self_iter: Any) -> Any:  # type: ignore[misc]
            for ln in lines:
                lines_consumed[0] += 1
                yield ln

        mock_stdout = MagicMock()
        mock_stdout.__aiter__ = _tracking_aiter
        mock_process = MagicMock()
        mock_process.stdout = mock_stdout
        mock_acm = AsyncMock()
        mock_acm.__aenter__ = AsyncMock(return_value=mock_process)
        mock_acm.__aexit__ = AsyncMock(return_value=False)
        mock_conn.create_process = MagicMock(return_value=mock_acm)
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock(return_value=False)

        with patch("firewatch_suricata.collector.asyncssh") as mock_asyncssh:
            mock_asyncssh.connect = AsyncMock(return_value=mock_conn)
            from firewatch_suricata.plugin import SuricataSource
            from firewatch_suricata.config import SuricataConfig
            plugin = SuricataSource()
            cfg = SuricataConfig(  # type: ignore[call-arg]
                mode="remote",
                remote_host="192.0.2.1",
                remote_path="/var/log/suricata/eve.json",
            )
            events = [ev async for ev in plugin.collect(cfg, since=None, ctx=_ctx())]

        assert len(events) == MAX_EVENTS_PER_COLLECT, (
            f"Expected exactly {MAX_EVENTS_PER_COLLECT} events; got {len(events)}"
        )
        # Iteration must stop early: we should NOT have consumed all over_cap lines
        assert lines_consumed[0] <= MAX_EVENTS_PER_COLLECT + 1, (
            f"Iteration did not stop early: consumed {lines_consumed[0]} lines "
            f"from a stream of {over_cap} (cap={MAX_EVENTS_PER_COLLECT}). "
            "Memory is not bounded — the full stream was iterated."
        )

    async def test_remote_uses_create_process_not_run_for_grep(self) -> None:
        """B2: the grep command is issued via create_process(), not conn.run()."""
        alert = _make_eve_alert()
        lines = [json.dumps(alert) + "\n"]

        mock_check_result = MagicMock()
        mock_check_result.stdout = "OK"

        mock_conn = AsyncMock()
        mock_conn.run = AsyncMock(return_value=mock_check_result)

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
        mock_conn.create_process = MagicMock(return_value=mock_acm)
        mock_conn.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_conn.__aexit__ = AsyncMock(return_value=False)

        with patch("firewatch_suricata.collector.asyncssh") as mock_asyncssh:
            mock_asyncssh.connect = AsyncMock(return_value=mock_conn)
            from firewatch_suricata.plugin import SuricataSource
            from firewatch_suricata.config import SuricataConfig
            plugin = SuricataSource()
            cfg = SuricataConfig(  # type: ignore[call-arg]
                mode="remote",
                remote_host="192.0.2.1",
                remote_path="/var/log/suricata/eve.json",
            )
            events = [ev async for ev in plugin.collect(cfg, since=None, ctx=_ctx())]

        # create_process must have been called (for the grep command)
        mock_conn.create_process.assert_called_once()
        # run() is called by the collect connection (file-check) AND by the
        # per-cycle stat connection (ADR-0034 §D.3, issue #168). Both reuse the
        # same mock_conn, so the expected count is 2: file-check + remote stat.
        assert mock_conn.run.call_count == 2, (
            f"conn.run was called {mock_conn.run.call_count} times; "
            "expected 2 (file-check + per-cycle stat). "
            "The grep must use create_process, not run."
        )
        assert len(events) == 1


# ---------------------------------------------------------------------------
# NB-2: SSH key path stays in logger; user-facing error is generic
# ---------------------------------------------------------------------------


class TestSSHKeyErrorMessages:
    """NB-2 — SSHConnectionError messages shown in dashboard do not echo the key path."""

    async def _get_key_not_found_error(self, key_path: str) -> str:
        """Trigger the key-not-found SSHConnectionError and return its message."""
        from firewatch_suricata.collector import _connect_ssh
        from firewatch_suricata.config import SuricataConfig
        from pydantic import SecretStr

        cfg = SuricataConfig(  # type: ignore[call-arg]
            mode="remote",
            remote_host="192.0.2.1",
            remote_key=SecretStr(key_path),
        )
        with patch("firewatch_suricata.collector.asyncssh") as mock_asyncssh:
            mock_asyncssh.connect = AsyncMock()
            mock_asyncssh.PermissionDenied = Exception
            mock_asyncssh.DisconnectError = Exception
            try:
                await _connect_ssh(cfg)
            except Exception as exc:
                return str(exc)
        return ""

    async def test_key_not_found_error_does_not_echo_absolute_path(
        self, tmp_path: Path
    ) -> None:
        """SSHConnectionError for missing key must not expose the full filesystem path."""
        key_path = str(tmp_path / "nonexistent_key")
        error_msg = await self._get_key_not_found_error(key_path)
        # The user-facing message must NOT contain the absolute path
        assert key_path not in error_msg, (
            f"User-facing error echoes key path {key_path!r}. "
            "Key paths must stay in logger lines only (NB-2)."
        )
        # But it should still be informative
        assert len(error_msg) > 0, "Expected a non-empty error message"

    async def test_key_not_found_error_is_actionable(self, tmp_path: Path) -> None:
        """SSHConnectionError for missing key must still contain actionable guidance."""
        key_path = str(tmp_path / "nonexistent_key")
        error_msg = await self._get_key_not_found_error(key_path)
        # Should still mention what to do — e.g. "key" or "ssh-keygen"
        lower = error_msg.lower()
        assert "key" in lower or "ssh" in lower, (
            f"Error message is not actionable: {error_msg!r}"
        )


# ---------------------------------------------------------------------------
# NB-4: String severity falls back to medium without raising
# ---------------------------------------------------------------------------


class TestStringSeverityFallback:
    """NB-4 — non-integer severity values do not raise ValueError; fall back to 3 (medium)."""

    def _normalize_with_severity(self, severity: Any) -> Any:
        from firewatch_suricata.plugin import SuricataSource
        data = _make_eve_alert()
        data["alert"]["severity"] = severity
        raw = _raw(data)
        plugin = SuricataSource()
        return plugin.normalize(raw, source_id="test")

    def test_string_severity_critical_does_not_raise(self) -> None:
        """severity='critical' (string) must not raise ValueError."""
        event = self._normalize_with_severity("critical")
        # Falls back to default medium
        assert event.severity == "medium"

    def test_string_severity_falls_back_to_medium(self) -> None:
        """Any non-integer severity string falls back to the medium severity (sev_int=3)."""
        for bad_val in ("critical", "HIGH", "unknown", "3.5"):
            event = self._normalize_with_severity(bad_val)
            assert event.severity == "medium", (
                f"Expected 'medium' fallback for severity={bad_val!r}; got {event.severity!r}"
            )

    def test_none_severity_falls_back_to_medium(self) -> None:
        """severity=None (missing or null) uses fallback 3 → medium."""
        event = self._normalize_with_severity(None)
        assert event.severity == "medium"

    def test_integer_severity_still_maps_correctly(self) -> None:
        """Regression: normal integer severities must still map correctly after the fix."""
        for sev, expected in [(1, "critical"), (2, "high"), (3, "medium"), (4, "low")]:
            event = self._normalize_with_severity(sev)
            assert event.severity == expected, (
                f"Integer severity {sev} should map to {expected!r}; got {event.severity!r}"
            )


# ---------------------------------------------------------------------------
# EARS-7: config_schema descriptions are operator-facing — no developer notes
# ---------------------------------------------------------------------------


class TestConfigSchemaOperatorCopy:
    """EARS-7 — user-facing schema strings contain no developer notes (issue #95).

    The Settings card renders field descriptions verbatim; they must be plain
    operator language with no internal ticket tags, implementation details, or
    backtick-fenced type references.
    """

    def _collect_user_facing_strings(self) -> list[str]:
        """Gather all description/title strings from model_json_schema(), including branches."""
        from firewatch_suricata.config import SuricataConfig

        schema = SuricataConfig.model_json_schema()
        strings: list[str] = []

        def _harvest(node: object) -> None:
            if not isinstance(node, dict):
                return
            if "description" in node:
                strings.append(node["description"])
            if "title" in node:
                strings.append(node["title"])
            # Walk properties, if/then/else branches.
            for key in ("properties", "if", "then", "else"):
                if key in node:
                    _harvest(node[key])
            # Walk nested property schemas.
            if "properties" in node:
                for field_schema in node["properties"].values():
                    _harvest(field_schema)

        _harvest(schema)
        return strings

    def test_no_ticket_tags_in_schema(self) -> None:
        """Ticket tags (BLOCKING-*, NB-*) must not appear in user-facing schema strings."""
        strings = self._collect_user_facing_strings()
        combined = "\n".join(strings)
        for pattern in ("BLOCKING-1", "BLOCKING-2", "NB-5", "NB-4"):
            assert pattern not in combined, (
                f"Developer ticket tag {pattern!r} found in user-facing schema string. "
                "Move it to a code comment."
            )

    def test_no_plugin_contract_refs_in_schema(self) -> None:
        """PLUGIN_CONTRACT.md references must not appear in user-facing schema strings."""
        strings = self._collect_user_facing_strings()
        combined = "\n".join(strings)
        assert "PLUGIN_CONTRACT" not in combined, (
            "PLUGIN_CONTRACT.md reference found in user-facing schema string. "
            "Move it to a code comment."
        )

    def test_no_backtick_fences_in_schema(self) -> None:
        """reStructuredText double-backtick fences (``foo``) must not appear in schema strings."""
        strings = self._collect_user_facing_strings()
        combined = "\n".join(strings)
        assert "``" not in combined, (
            "reStructuredText backtick fence (`` ``) found in user-facing schema string. "
            "Use plain text instead."
        )

    def test_no_model_json_schema_refs_in_schema(self) -> None:
        """Implementation detail 'model_json_schema' must not appear in schema strings."""
        strings = self._collect_user_facing_strings()
        combined = "\n".join(strings)
        assert "model_json_schema" not in combined, (
            "'model_json_schema' found in user-facing schema string. "
            "Move implementation details to code comments."
        )

    def test_no_if_then_else_refs_in_schema(self) -> None:
        """Implementation detail 'if/then/else' must not appear in user-facing schema strings."""
        strings = self._collect_user_facing_strings()
        combined = "\n".join(strings)
        assert "if/then/else" not in combined, (
            "'if/then/else' JSON Schema implementation detail found in user-facing string. "
            "Move it to a code comment."
        )
