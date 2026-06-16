"""Dependency-rule tests: the SDK imports nothing forbidden (EARS-5 of issue #1).

The SDK is the shared base everything depends on. It must never import firewatch-core,
any plugin, or legacy/ (CLAUDE.md dependency rule).
"""
import ast
import pathlib
import subprocess
import sys

import firewatch_sdk

FORBIDDEN_PREFIXES = ("firewatch_core", "firewatch_suricata", "legacy")

SRC_DIR = pathlib.Path(firewatch_sdk.__file__).parent


def _imported_module_names(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module)
    return names


def test_no_forbidden_imports_in_source():
    offenders: dict[str, set[str]] = {}
    for py in SRC_DIR.rglob("*.py"):
        bad = {
            name
            for name in _imported_module_names(py)
            if name.startswith(FORBIDDEN_PREFIXES)
        }
        if bad:
            offenders[str(py)] = bad
    assert not offenders, f"forbidden imports found: {offenders}"


def test_importing_sdk_pulls_nothing_forbidden():
    # Run in a fresh interpreter: a shared pytest process has other packages' modules
    # already in sys.modules, so isolation must be checked in a clean import.
    code = (
        "import sys, firewatch_sdk;"
        f"bad=[m for m in sys.modules if m.startswith({FORBIDDEN_PREFIXES!r})];"
        "print(';'.join(bad))"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert out.stdout.strip() == "", f"import firewatch_sdk loaded: {out.stdout.strip()}"
