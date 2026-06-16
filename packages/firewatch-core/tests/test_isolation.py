"""Dependency-rule tests (EARS-5): core imports the SDK only — never a plugin or legacy.

Core MAY import firewatch_sdk (the shared base). It must never import firewatch-core's
plugins (e.g. firewatch_suricata) or legacy/ (CLAUDE.md dependency rule).
"""
import ast
import pathlib
import subprocess
import sys

import firewatch_core

# firewatch_sdk is explicitly allowed; these are not.
FORBIDDEN_PREFIXES = ("legacy", "firewatch_suricata", "firewatch_syslog", "firewatch_azure")

SRC_DIR = pathlib.Path(firewatch_core.__file__).parent


def _imported_module_names(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(), filename=str(path))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def test_no_forbidden_imports_in_source():
    offenders: dict[str, set[str]] = {}
    for py in SRC_DIR.rglob("*.py"):
        bad = {
            name for name in _imported_module_names(py)
            if name.startswith(FORBIDDEN_PREFIXES)
        }
        if bad:
            offenders[str(py)] = bad
    assert not offenders, f"forbidden imports found: {offenders}"


def test_importing_core_pulls_nothing_forbidden():
    # Fresh interpreter — a shared pytest process pollutes sys.modules.
    code = (
        "import sys, firewatch_core;"
        f"bad=[m for m in sys.modules if m.startswith({FORBIDDEN_PREFIXES!r})];"
        "print(';'.join(bad))"
    )
    out = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert out.stdout.strip() == "", f"import firewatch_core loaded: {out.stdout.strip()}"
