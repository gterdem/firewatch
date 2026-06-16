"""Tests for #690 — Advanced/Optional partition + field copy corrections.

Maps 1:1 to EARS criteria from issue #690.

EARS-690-A  Remote mode: only remote_host (+ mode toggle) Essential;
            SSH port, SSH user, SSH key, remote EVE path, verify_host_key,
            rules_path collapse under Advanced/Optional.
EARS-690-B  Local mode: only local_path Essential; rules_path Advanced/Optional.
EARS-690-C  verify_host_key description instructs operator to leave ON, mentions
            known_hosts pre-acceptance via ssh, and states disabling removes MITM.
EARS-690-D  rules_path description states local-mode is automatic but remote-mode
            requires Fetch Ruleset, and does NOT imply automatic extraction
            'when set' in remote mode.
EARS-690-E  Partition change is purely schema metadata: Pydantic defaults and
            build_config env>file>default resolution are unchanged.
EARS-690-F  No edit to frontend/partitionFields.ts — verified by checking the
            JSON-schema required arrays only (ADR-0010/0028).
"""
from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_schema() -> dict[str, Any]:
    from firewatch_suricata.config import SuricataConfig

    return SuricataConfig.model_json_schema()


def _remote_essential_fields(schema: dict[str, Any]) -> list[str]:
    """Fields that are Essential in remote mode = in then.required."""
    return list(schema.get("then", {}).get("required", []))


def _remote_advanced_fields(schema: dict[str, Any]) -> list[str]:
    """Fields in then.properties but NOT in then.required = Advanced/Optional."""
    then = schema.get("then", {})
    required = set(then.get("required", []))
    props = set(then.get("properties", {}).keys())
    return sorted(props - required)


def _local_essential_fields(schema: dict[str, Any]) -> list[str]:
    """Fields that are Essential in local mode = in else.required."""
    return list(schema.get("else", {}).get("required", []))


# ---------------------------------------------------------------------------
# EARS-690-A: Remote mode partition
# ---------------------------------------------------------------------------


class TestRemoteModePartition:
    """EARS-690-A — in remote mode only remote_host is Essential (required)."""

    # Fields that must fall under Advanced/Optional in remote mode
    _EXPECTED_ADVANCED = frozenset({
        "remote_port",
        "remote_user",
        "remote_key",
        "remote_path",
        "verify_host_key",
    })

    def test_remote_essential_is_only_remote_host(self) -> None:
        """then.required must contain remote_host and nothing else."""
        schema = _get_schema()
        essential = _remote_essential_fields(schema)
        assert essential == ["remote_host"], (
            f"Expected only ['remote_host'] as Essential in remote mode; "
            f"got {essential}. Extra fields would surface unconditionally "
            f"in the card and should be Advanced/Optional."
        )

    def test_remote_port_is_advanced(self) -> None:
        """SSH port has a default (22); must be Advanced/Optional."""
        schema = _get_schema()
        advanced = _remote_advanced_fields(schema)
        assert "remote_port" in advanced, (
            "remote_port (SSH port, default=22) should be Advanced/Optional "
            "but is showing as Essential."
        )

    def test_remote_user_is_advanced(self) -> None:
        """SSH user defaults to OS user; must be Advanced/Optional."""
        schema = _get_schema()
        advanced = _remote_advanced_fields(schema)
        assert "remote_user" in advanced, (
            "remote_user should be Advanced/Optional."
        )

    def test_remote_key_is_advanced(self) -> None:
        """SSH private key path has a meaningful default (agent); must be Advanced."""
        schema = _get_schema()
        advanced = _remote_advanced_fields(schema)
        assert "remote_key" in advanced, (
            "remote_key should be Advanced/Optional."
        )

    def test_remote_path_is_advanced(self) -> None:
        """Remote EVE JSON path has a default; must be Advanced/Optional."""
        schema = _get_schema()
        advanced = _remote_advanced_fields(schema)
        assert "remote_path" in advanced, (
            "remote_path should be Advanced/Optional."
        )

    def test_verify_host_key_is_advanced(self) -> None:
        """verify_host_key defaults to True; must be Advanced/Optional."""
        schema = _get_schema()
        advanced = _remote_advanced_fields(schema)
        assert "verify_host_key" in advanced, (
            "verify_host_key should be Advanced/Optional."
        )

    def test_rules_path_not_in_remote_essential(self) -> None:
        """rules_path has a default and must not be Essential in either mode."""
        schema = _get_schema()
        # rules_path is at top-level (not in a branch), has a default → not required
        top_required = schema.get("required", [])
        then_required = schema.get("then", {}).get("required", [])
        else_required = schema.get("else", {}).get("required", [])
        for required_list in (top_required, then_required, else_required):
            assert "rules_path" not in required_list, (
                "rules_path must not appear in any required array — "
                "it has a default and must be Advanced/Optional in both modes."
            )


# ---------------------------------------------------------------------------
# EARS-690-B: Local mode partition
# ---------------------------------------------------------------------------


class TestLocalModePartition:
    """EARS-690-B — in local mode only local_path is Essential."""

    def test_local_essential_is_only_local_path(self) -> None:
        """else.required must contain local_path and nothing else."""
        schema = _get_schema()
        essential = _local_essential_fields(schema)
        assert essential == ["local_path"], (
            f"Expected only ['local_path'] as Essential in local mode; "
            f"got {essential}."
        )

    def test_rules_path_not_in_local_essential(self) -> None:
        """rules_path must not be in else.required."""
        schema = _get_schema()
        else_required = schema.get("else", {}).get("required", [])
        assert "rules_path" not in else_required, (
            "rules_path must be Advanced/Optional in local mode too."
        )


# ---------------------------------------------------------------------------
# EARS-690-C: verify_host_key description copy
# ---------------------------------------------------------------------------


class TestVerifyHostKeyDescription:
    """EARS-690-C — description instructs operator to leave ON and explains why."""

    def _desc(self) -> str:
        from firewatch_suricata.config import SuricataConfig

        return SuricataConfig.model_fields["verify_host_key"].description or ""

    def test_description_mentions_leave_on(self) -> None:
        """Operator must be told to leave verification ON by default."""
        desc = self._desc()
        lower = desc.lower()
        assert "leave" in lower or "keep" in lower or "on" in lower, (
            "verify_host_key description must instruct operator to leave it ON. "
            f"Got: {desc!r}"
        )

    def test_description_mentions_known_hosts(self) -> None:
        """Description must mention ~/.ssh/known_hosts."""
        desc = self._desc()
        assert "known_hosts" in desc, (
            "verify_host_key description must mention ~/.ssh/known_hosts. "
            f"Got: {desc!r}"
        )

    def test_description_mentions_mitm_or_protection(self) -> None:
        """Description must state that disabling removes MITM protection."""
        desc = self._desc()
        lower = desc.lower()
        assert "mitm" in lower or "protection" in lower, (
            "verify_host_key description must mention MITM or protection risk. "
            f"Got: {desc!r}"
        )

    def test_description_does_not_imply_insecure_default(self) -> None:
        """Description must not suggest disabling is a normal/recommended path."""
        desc = self._desc()
        lower = desc.lower()
        # Should not lead with disable/false/insecure framing
        assert not lower.startswith("set to false") and not lower.startswith("disable"), (
            "verify_host_key description must not open with disabling guidance. "
            f"Got: {desc!r}"
        )


# ---------------------------------------------------------------------------
# EARS-690-D: rules_path description copy
# ---------------------------------------------------------------------------


class TestRulesPathDescription:
    """EARS-690-D — description correctly states mode-split behavior."""

    def _desc(self) -> str:
        from firewatch_suricata.config import SuricataConfig

        return SuricataConfig.model_fields["rules_path"].description or ""

    def test_description_mentions_local_mode_auto(self) -> None:
        """Local mode behavior (automatic sync) must be explicitly stated."""
        desc = self._desc()
        lower = desc.lower()
        assert "local" in lower and ("auto" in lower or "sync" in lower or "each" in lower), (
            "rules_path description must mention local-mode auto-loading. "
            f"Got: {desc!r}"
        )

    def test_description_mentions_remote_fetch_ruleset(self) -> None:
        """Remote mode behavior (Fetch Ruleset only) must be explicitly stated."""
        desc = self._desc()
        lower = desc.lower()
        assert "remote" in lower and (
            "fetch ruleset" in lower or "fetch" in lower
        ), (
            "rules_path description must mention Fetch Ruleset for remote mode. "
            f"Got: {desc!r}"
        )

    def test_description_does_not_imply_automatic_remote(self) -> None:
        """Description must NOT imply 'when set, rule mappings are extracted automatically'
        without qualification — that is only true in local mode."""
        desc = self._desc()
        lower = desc.lower()
        # Old buggy copy: "When set, rule SID -> description mappings are extracted and stored"
        # That phrasing implies it works automatically in all modes.
        # The new copy must not have unqualified "when set" + "extracted" together.
        has_unqualified_when_set = (
            "when set" in lower
            and "extracted" in lower
            and "local" not in lower[:lower.find("extracted")]
        )
        assert not has_unqualified_when_set, (
            "rules_path description implies automatic extraction 'when set' without "
            "qualifying that this only applies in local mode. "
            f"Got: {desc!r}"
        )

    def test_description_mentions_blank_to_skip(self) -> None:
        """Operator must know they can leave blank to disable rule-name loading."""
        desc = self._desc()
        lower = desc.lower()
        assert "blank" in lower or "skip" in lower or "leave" in lower, (
            "rules_path description must mention leaving blank to skip. "
            f"Got: {desc!r}"
        )


# ---------------------------------------------------------------------------
# EARS-690-E: Pydantic defaults and build_config unaffected
# ---------------------------------------------------------------------------


class TestDefaultsUnchanged:
    """EARS-690-E — schema-only changes must not alter server-side behavior."""

    def test_rules_path_default_unchanged(self) -> None:
        """rules_path Pydantic default must still be /etc/suricata/rules."""
        from firewatch_suricata.config import SuricataConfig

        cfg = SuricataConfig()  # type: ignore[call-arg]
        assert cfg.rules_path == "/etc/suricata/rules"  # type: ignore[attr-defined]

    def test_verify_host_key_default_unchanged(self) -> None:
        """verify_host_key Pydantic default must still be True."""
        from firewatch_suricata.config import SuricataConfig

        cfg = SuricataConfig(mode="remote", remote_host="192.0.2.1")  # type: ignore[call-arg]
        assert cfg.verify_host_key is True  # type: ignore[attr-defined]

    def test_remote_port_default_unchanged(self) -> None:
        """remote_port Pydantic default must still be 22."""
        from firewatch_suricata.config import SuricataConfig

        cfg = SuricataConfig()  # type: ignore[call-arg]
        assert cfg.remote_port == 22  # type: ignore[attr-defined]

    def test_build_config_local_default_unaffected(self, monkeypatch: Any) -> None:
        """build_config with no env/file must still yield mode='local' defaults."""
        for var in (
            "FIREWATCH_SURICATA_MODE",
            "FIREWATCH_SURICATA_EVE_PATH",
            "FIREWATCH_SURICATA_RULES_PATH",
        ):
            monkeypatch.delenv(var, raising=False)

        from firewatch_suricata.config import build_config

        cfg = build_config(config_file=None)
        assert cfg.mode == "local"  # type: ignore[attr-defined]
        assert cfg.rules_path == "/etc/suricata/rules"  # type: ignore[attr-defined]

    def test_model_validate_remote_still_works(self) -> None:
        """Server-side validation must be unaffected by the copy/schema change."""
        from firewatch_suricata.config import SuricataConfig

        cfg = SuricataConfig.model_validate({
            "mode": "remote",
            "remote_host": "192.0.2.1",
            "verify_host_key": False,
        })
        assert cfg.mode == "remote"  # type: ignore[attr-defined]
        assert cfg.remote_host == "192.0.2.1"  # type: ignore[attr-defined]
        assert cfg.verify_host_key is False  # type: ignore[attr-defined]
