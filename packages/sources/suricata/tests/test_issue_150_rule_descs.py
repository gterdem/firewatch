"""Tests for issue #150 — Suricata plugin writes rule descriptions to ctx.kv.

EARS criteria covered (issue #150 / Suricata side):

S1  When collect() is called with a valid rules_path pointing to a .rules file,
    rule SID→description mappings are written to ctx.kv under the
    "rule_descriptions" namespace before any events are yielded.

S2  When collect() is called with a valid rules_path pointing to a directory,
    all .rules files in that directory are parsed and written to ctx.kv.

S3  When rules_path is blank/empty, collect() skips rule-description loading
    and yields events normally (no crash).

S4  When rules_path points to a non-existent path, collect() skips gracefully
    (no crash, no kv writes) and continues yielding events.

S5  Rule-description loading failure (e.g. bad file) must not abort event
    collection — events are still yielded (ADR-0003 fail-safe).

NOTE: RFC 5737 doc IPs used exclusively for source_ip fixtures.
"""
from __future__ import annotations

import json
from pathlib import Path

from firewatch_sdk import PluginContext
from firewatch_sdk.testing import InMemoryScopedKV


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_RULE_DESC_NAMESPACE = "rule_descriptions"


def _make_ctx() -> PluginContext:
    kv = InMemoryScopedKV()
    return PluginContext(kv=kv, source_id="pi-home")


def _make_eve_alert(
    src_ip: str = "192.0.2.10",
    signature_id: int = 2001001,
    signature: str = "ET SCAN Test",
) -> str:
    return json.dumps({
        "timestamp": "2026-06-03T12:00:00.000000+0000",
        "event_type": "alert",
        "src_ip": src_ip,
        "src_port": 44321,
        "dest_ip": "10.0.0.1",
        "dest_port": 80,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "category": "Attempted Information Leak",
            "signature": signature,
            "signature_id": signature_id,
            "severity": 2,
        },
        "flow_id": 1001,
    })


def _write_eve(path: Path, src_ip: str = "192.0.2.10") -> None:
    path.write_text(_make_eve_alert(src_ip=src_ip) + "\n", encoding="utf-8")


def _write_rules_file(path: Path, rules: dict[str, str]) -> None:
    """Write a minimal .rules file with the given {sid: msg} pairs."""
    lines = []
    for sid, msg in rules.items():
        lines.append(
            f'alert tcp any any -> any any (msg:"{msg}"; sid:{sid}; rev:1;)'
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# S1 — rules_path pointing to a .rules file writes kv entries
# ---------------------------------------------------------------------------


class TestRulesFilePopulatesKv:
    """S1 — a valid .rules file causes ctx.kv to be populated."""

    async def test_rule_descs_written_to_kv_from_rules_file(self, tmp_path: Path) -> None:
        """collect() writes SID→msg to ctx.kv when rules_path is a .rules file."""
        from firewatch_suricata.plugin import SuricataSource
        from firewatch_suricata.config import SuricataConfig

        # Create eve.json and .rules file in tmp_path
        eve_file = tmp_path / "eve.json"
        _write_eve(eve_file)

        rules_file = tmp_path / "test.rules"
        _write_rules_file(rules_file, {
            "2001001": "ET SCAN Potential VNC Scan",
            "2001002": "ET SQL Injection Probe",
        })

        cfg = SuricataConfig(
            mode="local",
            local_path=str(eve_file),
            rules_path=str(rules_file),
        )
        ctx = _make_ctx()
        plugin = SuricataSource()

        events = []
        async for raw in plugin.collect(cfg, since=None, ctx=ctx):
            events.append(raw)

        # kv should have both rule descriptions
        desc_1 = await ctx.kv.get(_RULE_DESC_NAMESPACE, "2001001")
        desc_2 = await ctx.kv.get(_RULE_DESC_NAMESPACE, "2001002")

        assert desc_1 == "ET SCAN Potential VNC Scan", (
            f"Expected 'ET SCAN Potential VNC Scan'; got {desc_1!r}"
        )
        assert desc_2 == "ET SQL Injection Probe"

    async def test_events_still_yielded_when_rules_loaded(self, tmp_path: Path) -> None:
        """collect() yields events normally even when rule descriptions are loaded."""
        from firewatch_suricata.plugin import SuricataSource
        from firewatch_suricata.config import SuricataConfig

        eve_file = tmp_path / "eve.json"
        _write_eve(eve_file, src_ip="192.0.2.11")

        rules_file = tmp_path / "test.rules"
        _write_rules_file(rules_file, {"2001001": "ET SCAN Test"})

        cfg = SuricataConfig(
            mode="local",
            local_path=str(eve_file),
            rules_path=str(rules_file),
        )
        ctx = _make_ctx()
        plugin = SuricataSource()

        events = []
        async for raw in plugin.collect(cfg, since=None, ctx=ctx):
            events.append(raw)

        assert len(events) == 1
        assert events[0].data["src_ip"] == "192.0.2.11"


# ---------------------------------------------------------------------------
# S2 — rules_path pointing to a directory aggregates all .rules files
# ---------------------------------------------------------------------------


class TestRulesDirPopulatesKv:
    """S2 — a directory of .rules files is parsed and all SIDs written to kv."""

    async def test_rules_dir_writes_all_sids_to_kv(self, tmp_path: Path) -> None:
        """collect() with a rules directory aggregates all .rules files."""
        from firewatch_suricata.plugin import SuricataSource
        from firewatch_suricata.config import SuricataConfig

        eve_file = tmp_path / "eve.json"
        _write_eve(eve_file)

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        _write_rules_file(rules_dir / "emerging-scan.rules", {
            "2001001": "ET SCAN VNC",
        })
        _write_rules_file(rules_dir / "emerging-malware.rules", {
            "2002000": "ET MALWARE Generic",
        })

        cfg = SuricataConfig(
            mode="local",
            local_path=str(eve_file),
            rules_path=str(rules_dir),
        )
        ctx = _make_ctx()
        plugin = SuricataSource()

        async for _ in plugin.collect(cfg, since=None, ctx=ctx):
            pass

        d1 = await ctx.kv.get(_RULE_DESC_NAMESPACE, "2001001")
        d2 = await ctx.kv.get(_RULE_DESC_NAMESPACE, "2002000")
        assert d1 == "ET SCAN VNC"
        assert d2 == "ET MALWARE Generic"


# ---------------------------------------------------------------------------
# S3 — blank rules_path skips gracefully
# ---------------------------------------------------------------------------


class TestBlankRulesPath:
    """S3 — blank/empty rules_path means no rule-description loading."""

    async def test_blank_rules_path_no_kv_writes(self, tmp_path: Path) -> None:
        """collect() with rules_path='' writes nothing to kv and yields events normally."""
        from firewatch_suricata.plugin import SuricataSource
        from firewatch_suricata.config import SuricataConfig

        eve_file = tmp_path / "eve.json"
        _write_eve(eve_file)

        cfg = SuricataConfig(
            mode="local",
            local_path=str(eve_file),
            rules_path="",  # blank — skip rule loading
        )
        ctx = _make_ctx()
        plugin = SuricataSource()

        events = []
        async for raw in plugin.collect(cfg, since=None, ctx=ctx):
            events.append(raw)

        all_descs = await ctx.kv.get_all(_RULE_DESC_NAMESPACE)
        assert all_descs == {}, (
            "No rule descriptions should be written when rules_path is blank"
        )
        assert len(events) == 1, "Events must still be yielded when rules_path is blank"


# ---------------------------------------------------------------------------
# S4 — non-existent rules_path skips gracefully
# ---------------------------------------------------------------------------


class TestNonExistentRulesPath:
    """S4 — a rules_path that doesn't exist skips without crashing."""

    async def test_nonexistent_rules_path_no_crash(self, tmp_path: Path) -> None:
        """collect() with a non-existent rules_path does not crash."""
        from firewatch_suricata.plugin import SuricataSource
        from firewatch_suricata.config import SuricataConfig

        eve_file = tmp_path / "eve.json"
        _write_eve(eve_file)

        cfg = SuricataConfig(
            mode="local",
            local_path=str(eve_file),
            rules_path=str(tmp_path / "nonexistent" / "rules"),
        )
        ctx = _make_ctx()
        plugin = SuricataSource()

        events = []
        # Must not raise
        async for raw in plugin.collect(cfg, since=None, ctx=ctx):
            events.append(raw)

        assert len(events) == 1
        all_descs = await ctx.kv.get_all(_RULE_DESC_NAMESPACE)
        assert all_descs == {}


# ---------------------------------------------------------------------------
# S5 — rule-description loading failure does not abort event collection
# ---------------------------------------------------------------------------


class TestRuleDescLoadFailureSafe:
    """S5 — any exception during rule-description loading must not abort collect()."""

    async def test_rules_parse_exception_events_still_yielded(self, tmp_path: Path) -> None:
        """If _write_rule_descriptions raises, collect() still yields events."""
        from firewatch_suricata.plugin import SuricataSource
        from firewatch_suricata.config import SuricataConfig

        eve_file = tmp_path / "eve.json"
        _write_eve(eve_file)

        rules_file = tmp_path / "test.rules"
        _write_rules_file(rules_file, {"2001001": "ET SCAN Test"})

        cfg = SuricataConfig(
            mode="local",
            local_path=str(eve_file),
            rules_path=str(rules_file),
        )
        ctx = _make_ctx()
        plugin = SuricataSource()

        # Simulate a kv.put failure for all writes
        async def _failing_put(ns: str, key: str, value: str) -> None:
            raise RuntimeError("kv exploded")

        ctx.kv.put = _failing_put  # type: ignore[method-assign]

        events = []
        # Must not raise — fail-safe (ADR-0003)
        async for raw in plugin.collect(cfg, since=None, ctx=ctx):
            events.append(raw)

        assert len(events) == 1, (
            "Events must be yielded even when rule-description kv.put raises"
        )
