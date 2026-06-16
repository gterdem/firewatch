"""Tests for the Suricata .rules parser — issue #20 EARS criterion G5 (plugin side).

EARS criteria covered:
  R1  parse_rules_file() extracts rule_id and msg: description from a .rules file.
  R2  parse_rules_file() skips comment lines (lines starting with #).
  R3  parse_rules_file() skips rules that have no sid: field (incomplete rules).
  R4  parse_rules_file() skips rules that have no msg: field.
  R5  parse_rules_file() returns {} for a missing/unreadable file (no crash).
  R6  parse_rules_dir() aggregates results from all .rules files in a directory.
  R7  No forbidden imports (no firewatch_core, no legacy/).
"""
from __future__ import annotations

from pathlib import Path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_rules_file(path: Path, content: str) -> Path:
    """Write a .rules file with the given content."""
    rules_file = path / "test.rules"
    rules_file.write_text(content, encoding="utf-8")
    return rules_file


# ---------------------------------------------------------------------------
# R1 — Basic extraction of sid and msg
# ---------------------------------------------------------------------------


class TestParseRulesFileBasic:
    """R1 — parse_rules_file extracts rule_id (sid) and description (msg)."""

    def test_single_rule_extracted(self, tmp_path: Path) -> None:
        """A standard Suricata rule line yields {sid: msg}."""
        from firewatch_suricata.rules import parse_rules_file

        content = (
            'alert tcp any any -> any 80 (msg:"ET SCAN Potential VNC Scan"; '
            'sid:2002910; rev:4;)\n'
        )
        rules_file = _write_rules_file(tmp_path, content)
        result = parse_rules_file(rules_file)

        assert result == {"2002910": "ET SCAN Potential VNC Scan"}

    def test_multiple_rules_extracted(self, tmp_path: Path) -> None:
        """Multiple rules in a file are all extracted."""
        from firewatch_suricata.rules import parse_rules_file

        content = (
            'alert tcp any any -> any 80 (msg:"ET WEB_SERVER SQL Injection"; sid:2012345; rev:2;)\n'
            'alert tcp any any -> any 443 (msg:"ET MALWARE Beacon"; sid:2030001; rev:1;)\n'
        )
        rules_file = _write_rules_file(tmp_path, content)
        result = parse_rules_file(rules_file)

        assert len(result) == 2
        assert result["2012345"] == "ET WEB_SERVER SQL Injection"
        assert result["2030001"] == "ET MALWARE Beacon"

    def test_msg_with_special_characters(self, tmp_path: Path) -> None:
        """msg: field containing spaces, slashes, parentheses is extracted correctly."""
        from firewatch_suricata.rules import parse_rules_file

        content = (
            'alert http any any -> any any (msg:"ET ATTACK_RESPONSE Command/Shell Output"; '
            'sid:2014726; rev:3;)\n'
        )
        rules_file = _write_rules_file(tmp_path, content)
        result = parse_rules_file(rules_file)

        assert result["2014726"] == "ET ATTACK_RESPONSE Command/Shell Output"


# ---------------------------------------------------------------------------
# R2 — Comment lines skipped
# ---------------------------------------------------------------------------


class TestParseRulesFileComments:
    """R2 — lines starting with # are skipped."""

    def test_comment_line_not_included(self, tmp_path: Path) -> None:
        """Lines starting with # must not be parsed as rules."""
        from firewatch_suricata.rules import parse_rules_file

        content = (
            "# This is a comment line — should be skipped\n"
            'alert tcp any any -> any 80 (msg:"ET TEST Rule"; sid:9000001; rev:1;)\n'
        )
        rules_file = _write_rules_file(tmp_path, content)
        result = parse_rules_file(rules_file)

        assert len(result) == 1
        assert "9000001" in result

    def test_disabled_rule_comment_skipped(self, tmp_path: Path) -> None:
        """Disabled rules (#alert ...) are also comment lines and must be skipped."""
        from firewatch_suricata.rules import parse_rules_file

        content = (
            '#alert tcp any any -> any 80 (msg:"DISABLED RULE"; sid:9000002; rev:1;)\n'
            'alert tcp any any -> any 80 (msg:"ACTIVE RULE"; sid:9000003; rev:1;)\n'
        )
        rules_file = _write_rules_file(tmp_path, content)
        result = parse_rules_file(rules_file)

        assert "9000002" not in result
        assert "9000003" in result


# ---------------------------------------------------------------------------
# R3 — Rules without sid: are skipped
# ---------------------------------------------------------------------------


class TestParseRulesFileMissingSid:
    """R3 — rules missing the sid: keyword are skipped without error."""

    def test_rule_without_sid_skipped(self, tmp_path: Path) -> None:
        """A rule line with msg: but no sid: is silently skipped."""
        from firewatch_suricata.rules import parse_rules_file

        content = (
            'alert tcp any any -> any 80 (msg:"NO SID RULE"; rev:1;)\n'
            'alert tcp any any -> any 80 (msg:"HAS SID"; sid:9000010; rev:1;)\n'
        )
        rules_file = _write_rules_file(tmp_path, content)
        result = parse_rules_file(rules_file)

        assert len(result) == 1
        assert "9000010" in result


# ---------------------------------------------------------------------------
# R4 — Rules without msg: are skipped
# ---------------------------------------------------------------------------


class TestParseRulesFileMissingMsg:
    """R4 — rules missing the msg: keyword are skipped without error."""

    def test_rule_without_msg_skipped(self, tmp_path: Path) -> None:
        """A rule line with sid: but no msg: is silently skipped."""
        from firewatch_suricata.rules import parse_rules_file

        content = (
            "alert tcp any any -> any 80 (sid:9000020; rev:1;)\n"
            'alert tcp any any -> any 80 (msg:"HAS MSG"; sid:9000021; rev:1;)\n'
        )
        rules_file = _write_rules_file(tmp_path, content)
        result = parse_rules_file(rules_file)

        assert len(result) == 1
        assert "9000021" in result


# ---------------------------------------------------------------------------
# R5 — Missing / unreadable file returns {}
# ---------------------------------------------------------------------------


class TestParseRulesFileMissing:
    """R5 — parse_rules_file does not raise on a missing/unreadable file."""

    def test_missing_file_returns_empty_dict(self, tmp_path: Path) -> None:
        """Calling parse_rules_file with a non-existent path must return {} (no raise)."""
        from firewatch_suricata.rules import parse_rules_file

        result = parse_rules_file(tmp_path / "nonexistent.rules")
        assert result == {}

    def test_empty_file_returns_empty_dict(self, tmp_path: Path) -> None:
        """An empty .rules file returns {}."""
        from firewatch_suricata.rules import parse_rules_file

        empty_file = tmp_path / "empty.rules"
        empty_file.write_text("", encoding="utf-8")
        result = parse_rules_file(empty_file)
        assert result == {}


# ---------------------------------------------------------------------------
# R6 — parse_rules_dir aggregates from all .rules files
# ---------------------------------------------------------------------------


class TestParseRulesDir:
    """R6 — parse_rules_dir aggregates results from all .rules files in a directory."""

    def test_aggregates_from_multiple_files(self, tmp_path: Path) -> None:
        """Rules from separate .rules files are combined into one dict."""
        from firewatch_suricata.rules import parse_rules_dir

        file_a = tmp_path / "a.rules"
        file_b = tmp_path / "b.rules"
        file_a.write_text(
            'alert tcp any any -> any 80 (msg:"Rule A"; sid:9001001; rev:1;)\n',
            encoding="utf-8",
        )
        file_b.write_text(
            'alert tcp any any -> any 80 (msg:"Rule B"; sid:9001002; rev:1;)\n',
            encoding="utf-8",
        )

        result = parse_rules_dir(tmp_path)
        assert "9001001" in result
        assert "9001002" in result
        assert result["9001001"] == "Rule A"
        assert result["9001002"] == "Rule B"

    def test_ignores_non_rules_files(self, tmp_path: Path) -> None:
        """Non-.rules files in the directory are not parsed."""
        from firewatch_suricata.rules import parse_rules_dir

        rules_file = tmp_path / "good.rules"
        txt_file = tmp_path / "readme.txt"
        rules_file.write_text(
            'alert tcp any any -> any 80 (msg:"Good Rule"; sid:9002001; rev:1;)\n',
            encoding="utf-8",
        )
        txt_file.write_text("this is not a rules file\n", encoding="utf-8")

        result = parse_rules_dir(tmp_path)
        assert len(result) == 1
        assert "9002001" in result

    def test_missing_directory_returns_empty_dict(self, tmp_path: Path) -> None:
        """parse_rules_dir returns {} for a non-existent directory (no raise)."""
        from firewatch_suricata.rules import parse_rules_dir

        result = parse_rules_dir(tmp_path / "nonexistent_dir")
        assert result == {}

    def test_empty_directory_returns_empty_dict(self, tmp_path: Path) -> None:
        """An empty directory returns {}."""
        from firewatch_suricata.rules import parse_rules_dir

        result = parse_rules_dir(tmp_path)
        assert result == {}


# ---------------------------------------------------------------------------
# R7 — No forbidden imports
# ---------------------------------------------------------------------------


class TestNoForbiddenImports:
    """R7 — rules.py must depend only on stdlib; no firewatch_core, no legacy/."""

    def test_does_not_import_firewatch_core(self) -> None:
        """rules.py must not import firewatch_core."""
        rules_path = (
            Path(__file__).parent.parent / "src" / "firewatch_suricata" / "rules.py"
        )
        assert rules_path.exists(), f"rules.py not found at {rules_path}"
        content = rules_path.read_text()
        assert "firewatch_core" not in content, (
            "rules.py imports firewatch_core — forbidden (PLUGIN_CONTRACT.md)"
        )

    def test_does_not_import_legacy(self) -> None:
        """rules.py must not import legacy/."""
        import re

        rules_path = (
            Path(__file__).parent.parent / "src" / "firewatch_suricata" / "rules.py"
        )
        content = rules_path.read_text()
        import_re = re.compile(r"^\s*(from legacy|import legacy)\b", re.MULTILINE)
        match = import_re.search(content)
        assert match is None, (
            f"rules.py imports legacy — forbidden: {match.group()!r}"
        )

    def test_only_stdlib_and_sdk_imports(self) -> None:
        """rules.py may only import stdlib modules and optionally firewatch_sdk."""
        rules_path = (
            Path(__file__).parent.parent / "src" / "firewatch_suricata" / "rules.py"
        )
        content = rules_path.read_text()
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("from firewatch_") or stripped.startswith("import firewatch_"):
                assert "firewatch_sdk" in stripped or "firewatch_suricata" in stripped, (
                    f"rules.py: forbidden import line: {stripped!r}"
                )


# ---------------------------------------------------------------------------
# NB-4 — File size cap: oversized files are handled gracefully
# ---------------------------------------------------------------------------


class TestFileSizeCap:
    """NB-4 — parse_rules_file must not OOM on huge .rules files."""

    def test_file_over_cap_returns_partial_or_empty(self, tmp_path: Path) -> None:
        """A .rules file exceeding the size cap is skipped or limited, never OOM-ing."""
        from firewatch_suricata.rules import parse_rules_file, _MAX_RULES_BYTES

        rules_file = tmp_path / "huge.rules"
        # Write exactly one valid rule, then pad well past the cap
        valid_line = 'alert tcp any any -> any 80 (msg:"Padded Rule"; sid:9999001; rev:1;)\n'
        # One real rule then synthetic filler to exceed the cap
        pad_line = "# padding\n"
        # Build content just over the cap
        pad_needed = _MAX_RULES_BYTES + 1
        content = valid_line + (pad_line * (pad_needed // len(pad_line) + 1))
        rules_file.write_text(content, encoding="utf-8")

        # Must return without raising (OOM / MemoryError), result may be {} or partial
        result = parse_rules_file(rules_file)
        assert isinstance(result, dict)  # no crash; type is correct
