"""EARS — ``firewatch_sdk.localhost`` must never import core or a plugin.

ADR-0065 §4 / acceptance criterion: "The readers SHALL live in firewatch-sdk
only (no core import, no plugin import)". Mirrors
``firewatch_suricata``'s ``TestNoForbiddenImports`` pattern.
"""
from __future__ import annotations

import re
from pathlib import Path

_LOCALHOST_SRC = (
    Path(__file__).parent.parent.parent / "src" / "firewatch_sdk" / "localhost"
)


def test_localhost_package_exists() -> None:
    """Sanity check the path used below actually resolves (catches typos)."""
    assert _LOCALHOST_SRC.is_dir()
    assert list(_LOCALHOST_SRC.glob("*.py"))


def test_does_not_import_firewatch_core() -> None:
    """Checks actual import statements only — prose mentioning "firewatch_core"
    in a docstring (e.g. explaining the dependency rule) is not a violation."""
    import_re = re.compile(r"^\s*(from firewatch_core|import firewatch_core)\b", re.MULTILINE)
    for py_file in _LOCALHOST_SRC.glob("*.py"):
        content = py_file.read_text()
        assert import_re.search(content) is None, (
            f"{py_file.name} imports firewatch_core — forbidden "
            "(dependency rule: plugins/SDK never import core)"
        )


def test_does_not_import_any_plugin_package() -> None:
    import_re = re.compile(r"^\s*(from firewatch_\w+|import firewatch_\w+)", re.MULTILINE)
    allowed_prefixes = ("firewatch_sdk",)
    for py_file in _LOCALHOST_SRC.glob("*.py"):
        content = py_file.read_text()
        for match in import_re.finditer(content):
            line = match.group(0)
            assert any(p in line for p in allowed_prefixes), (
                f"{py_file.name} has a forbidden import: {line.strip()!r} "
                "— the SDK depends on nothing but itself"
            )


def test_does_not_import_legacy() -> None:
    import_re = re.compile(r"^\s*(from legacy|import legacy)\b", re.MULTILINE)
    for py_file in _LOCALHOST_SRC.glob("*.py"):
        content = py_file.read_text()
        assert import_re.search(content) is None, (
            f"{py_file.name} imports legacy/ — forbidden"
        )
