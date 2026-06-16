"""Tests for firewatch new-source scaffold command — EARS criteria mapped 1:1.

EARS-1  Event-driven: When `firewatch new-source <name>` runs, it shall emit
        packages/sources/<name>/ that imports firewatch-sdk only, registers its
        entry point, and is discovered by the loader with zero core edits.

EARS-2  Ubiquitous: Generated config stubs shall use SecretStr for secret fields
        and the standard env > file > default pattern (via the config service).

EARS-3  Ubiquitous: The generated package shall not import firewatch-core, another
        plugin, or legacy/.

EARS-4  Unwanted: If a package of that name already exists, the tool shall refuse
        to overwrite it (no silent clobber).

Each test class maps to exactly one EARS criterion.  Sub-cases exercise the
pull/push flavor option and edge cases.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path



# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_scaffold(
    name: str,
    *,
    flavor: str = "pull",
    cwd: Path,
    extra_args: list[str] | None = None,
) -> "subprocess.CompletedProcess[str]":
    """Invoke ``firewatch new-source <name>`` via the module entry point.

    Runs in a subprocess so that the generated package's imports are not
    accidentally satisfied by the current process's sys.modules.
    Uses ``--output-dir`` to direct output into a tmp directory so tests
    never write into the real packages/sources/ tree.
    """
    cmd = [
        sys.executable,
        "-m",
        "firewatch_cli.main",
        "new-source",
        name,
        f"--flavor={flavor}",
        f"--output-dir={cwd}",
    ]
    if extra_args:
        cmd.extend(extra_args)
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
    )


def _scaffold(
    name: str,
    *,
    flavor: str = "pull",
    tmp_path: Path,
) -> Path:
    """Run scaffold and return path to generated package root; assert success."""
    result = _run_scaffold(name, flavor=flavor, cwd=tmp_path)
    assert result.returncode == 0, (
        f"scaffold exited {result.returncode}\n"
        f"stdout: {result.stdout}\n"
        f"stderr: {result.stderr}"
    )
    pkg_root = tmp_path / "packages" / "sources" / name
    assert pkg_root.exists(), f"Expected {pkg_root} to exist after scaffold"
    return pkg_root


def _read_pkg_file(pkg_root: Path, rel: str) -> str:
    """Read a generated file; assert it exists."""
    p = pkg_root / rel
    assert p.exists(), f"Expected generated file {p} to exist"
    return p.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# EARS-1: Generated package structure and file presence
# ---------------------------------------------------------------------------


class TestScaffoldStructure:
    """EARS-1 — the command emits all required files in the correct layout."""

    def test_scaffold_creates_package_root(self, tmp_path: Path) -> None:
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        assert pkg_root.is_dir()

    def test_scaffold_creates_pyproject_toml(self, tmp_path: Path) -> None:
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        _read_pkg_file(pkg_root, "pyproject.toml")

    def test_scaffold_creates_src_layout(self, tmp_path: Path) -> None:
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        src_dir = pkg_root / "src" / "firewatch_mywidget"
        assert src_dir.is_dir(), f"Expected src layout at {src_dir}"

    def test_scaffold_creates_init_py(self, tmp_path: Path) -> None:
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        _read_pkg_file(pkg_root, "src/firewatch_mywidget/__init__.py")

    def test_scaffold_creates_plugin_py(self, tmp_path: Path) -> None:
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        _read_pkg_file(pkg_root, "src/firewatch_mywidget/plugin.py")

    def test_scaffold_creates_config_py(self, tmp_path: Path) -> None:
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        _read_pkg_file(pkg_root, "src/firewatch_mywidget/config.py")

    def test_scaffold_creates_normalize_py(self, tmp_path: Path) -> None:
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        _read_pkg_file(pkg_root, "src/firewatch_mywidget/normalize.py")

    def test_scaffold_creates_tests_directory(self, tmp_path: Path) -> None:
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        tests_dir = pkg_root / "tests"
        assert tests_dir.is_dir()

    def test_scaffold_creates_tests_init(self, tmp_path: Path) -> None:
        """tests/__init__.py must be present so pytest importlib mode works."""
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        _read_pkg_file(pkg_root, "tests/__init__.py")

    def test_scaffold_creates_test_plugin_py(self, tmp_path: Path) -> None:
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        _read_pkg_file(pkg_root, "tests/test_plugin.py")

    def test_scaffold_creates_test_normalize_py(self, tmp_path: Path) -> None:
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        _read_pkg_file(pkg_root, "tests/test_normalize.py")

    def test_push_flavor_creates_listener_py(self, tmp_path: Path) -> None:
        """Push flavor must also generate a listener stub file."""
        pkg_root = _scaffold("mywidget", flavor="push", tmp_path=tmp_path)
        _read_pkg_file(pkg_root, "src/firewatch_mywidget/listener.py")

    def test_pull_flavor_creates_collector_py(self, tmp_path: Path) -> None:
        """Pull flavor must also generate a collector stub file."""
        pkg_root = _scaffold("mywidget", flavor="pull", tmp_path=tmp_path)
        _read_pkg_file(pkg_root, "src/firewatch_mywidget/collector.py")

    def test_scaffold_prints_next_steps(self, tmp_path: Path) -> None:
        """Scaffold must print a helpful next-steps message on stdout."""
        result = _run_scaffold("mywidget", cwd=tmp_path)
        assert result.returncode == 0
        # Must tell the contributor where the files landed
        assert "mywidget" in result.stdout.lower() or "mywidget" in result.stderr.lower()


# ---------------------------------------------------------------------------
# EARS-1 continued: pyproject.toml content (entry-point wiring)
# ---------------------------------------------------------------------------


class TestPyprojectContent:
    """EARS-1 — pyproject.toml depends on firewatch-sdk only and registers the entry point."""

    def test_pyproject_has_correct_project_name(self, tmp_path: Path) -> None:
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        toml = _read_pkg_file(pkg_root, "pyproject.toml")
        assert 'name = "firewatch-mywidget"' in toml

    def test_pyproject_depends_on_sdk_only(self, tmp_path: Path) -> None:
        """The only firewatch-* dependency must be firewatch-sdk (PLUGIN_CONTRACT.md)."""
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        toml = _read_pkg_file(pkg_root, "pyproject.toml")
        assert "firewatch-sdk" in toml
        assert "firewatch-core" not in toml

    def test_pyproject_registers_entry_point(self, tmp_path: Path) -> None:
        """Entry-point group 'firewatch.sources' must be present with correct key."""
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        toml = _read_pkg_file(pkg_root, "pyproject.toml")
        assert 'firewatch.sources' in toml
        assert "mywidget" in toml

    def test_pyproject_entry_point_points_to_plugin_module(self, tmp_path: Path) -> None:
        """Entry-point value must reference firewatch_mywidget.plugin."""
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        toml = _read_pkg_file(pkg_root, "pyproject.toml")
        assert "firewatch_mywidget.plugin" in toml

    def test_pyproject_has_hatchling_build_system(self, tmp_path: Path) -> None:
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        toml = _read_pkg_file(pkg_root, "pyproject.toml")
        assert "hatchling" in toml

    def test_pyproject_has_src_packages_declaration(self, tmp_path: Path) -> None:
        """hatch.build.targets.wheel must list src/firewatch_mywidget."""
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        toml = _read_pkg_file(pkg_root, "pyproject.toml")
        assert "firewatch_mywidget" in toml


# ---------------------------------------------------------------------------
# EARS-1 continued: plugin.py content (SourcePlugin + flavor)
# ---------------------------------------------------------------------------


class TestPluginContent:
    """EARS-1 — plugin.py stubs implement SourcePlugin and the chosen flavor."""

    def test_plugin_imports_sdk_only(self, tmp_path: Path) -> None:
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        plugin_py = _read_pkg_file(pkg_root, "src/firewatch_mywidget/plugin.py")
        assert "firewatch_sdk" in plugin_py

    def test_plugin_defines_class(self, tmp_path: Path) -> None:
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        plugin_py = _read_pkg_file(pkg_root, "src/firewatch_mywidget/plugin.py")
        # Class name must be CamelCase of the source name
        assert "class MywidgetSource" in plugin_py or "MywidgetSource" in plugin_py

    def test_plugin_has_metadata_method(self, tmp_path: Path) -> None:
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        plugin_py = _read_pkg_file(pkg_root, "src/firewatch_mywidget/plugin.py")
        assert "def metadata(" in plugin_py

    def test_plugin_has_config_schema_method(self, tmp_path: Path) -> None:
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        plugin_py = _read_pkg_file(pkg_root, "src/firewatch_mywidget/plugin.py")
        assert "def config_schema(" in plugin_py

    def test_plugin_has_validate_config_method(self, tmp_path: Path) -> None:
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        plugin_py = _read_pkg_file(pkg_root, "src/firewatch_mywidget/plugin.py")
        assert "def validate_config(" in plugin_py

    def test_plugin_has_normalize_method(self, tmp_path: Path) -> None:
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        plugin_py = _read_pkg_file(pkg_root, "src/firewatch_mywidget/plugin.py")
        assert "def normalize(" in plugin_py

    def test_plugin_has_health_check_method(self, tmp_path: Path) -> None:
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        plugin_py = _read_pkg_file(pkg_root, "src/firewatch_mywidget/plugin.py")
        assert "async def health_check(" in plugin_py

    def test_pull_plugin_has_collect_method(self, tmp_path: Path) -> None:
        pkg_root = _scaffold("mywidget", flavor="pull", tmp_path=tmp_path)
        plugin_py = _read_pkg_file(pkg_root, "src/firewatch_mywidget/plugin.py")
        assert "async def collect(" in plugin_py or "def collect(" in plugin_py

    def test_push_plugin_has_start_and_stop_methods(self, tmp_path: Path) -> None:
        pkg_root = _scaffold("mywidget", flavor="push", tmp_path=tmp_path)
        plugin_py = _read_pkg_file(pkg_root, "src/firewatch_mywidget/plugin.py")
        assert "async def start(" in plugin_py
        assert "async def stop(" in plugin_py

    def test_plugin_type_key_constant_matches_name(self, tmp_path: Path) -> None:
        """_TYPE_KEY must be set to the source name."""
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        plugin_py = _read_pkg_file(pkg_root, "src/firewatch_mywidget/plugin.py")
        assert '"mywidget"' in plugin_py or "'mywidget'" in plugin_py

    def test_pull_metadata_flavor_is_pull(self, tmp_path: Path) -> None:
        pkg_root = _scaffold("mywidget", flavor="pull", tmp_path=tmp_path)
        plugin_py = _read_pkg_file(pkg_root, "src/firewatch_mywidget/plugin.py")
        assert '"pull"' in plugin_py or "'pull'" in plugin_py

    def test_push_metadata_flavor_is_push(self, tmp_path: Path) -> None:
        pkg_root = _scaffold("mywidget", flavor="push", tmp_path=tmp_path)
        plugin_py = _read_pkg_file(pkg_root, "src/firewatch_mywidget/plugin.py")
        assert '"push"' in plugin_py or "'push'" in plugin_py

    def test_plugin_has_nb1_delimiter_comment(self, tmp_path: Path) -> None:
        """normalize() stub must include the NB-1 payload-delimiting reminder comment."""
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        normalize_py = _read_pkg_file(pkg_root, "src/firewatch_mywidget/normalize.py")
        # NB-1: payloads reaching the LLM must be delimited as untrusted data
        assert "NB-1" in normalize_py or "delimit" in normalize_py.lower() or "untrusted" in normalize_py.lower()


# ---------------------------------------------------------------------------
# EARS-2: config.py uses SecretStr and env > file > default pattern
# ---------------------------------------------------------------------------


class TestConfigContent:
    """EARS-2 — generated config.py has SecretStr and env > file > default."""

    def test_config_imports_secret_str(self, tmp_path: Path) -> None:
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        config_py = _read_pkg_file(pkg_root, "src/firewatch_mywidget/config.py")
        assert "SecretStr" in config_py

    def test_config_has_secret_field(self, tmp_path: Path) -> None:
        """At least one field uses SecretStr (the example secret field)."""
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        config_py = _read_pkg_file(pkg_root, "src/firewatch_mywidget/config.py")
        assert "SecretStr" in config_py

    def test_config_has_build_config_function(self, tmp_path: Path) -> None:
        """build_config() provides env > file > default resolution (ADR-0006)."""
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        config_py = _read_pkg_file(pkg_root, "src/firewatch_mywidget/config.py")
        assert "def build_config(" in config_py

    def test_config_references_env_map(self, tmp_path: Path) -> None:
        """Config must define _ENV_MAP for env > file resolution."""
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        config_py = _read_pkg_file(pkg_root, "src/firewatch_mywidget/config.py")
        assert "_ENV_MAP" in config_py

    def test_config_uses_pydantic_base_model(self, tmp_path: Path) -> None:
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        config_py = _read_pkg_file(pkg_root, "src/firewatch_mywidget/config.py")
        assert "BaseModel" in config_py

    def test_config_adr0006_comment_present(self, tmp_path: Path) -> None:
        """Config must reference ADR-0006 (env > file > default precedence)."""
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        config_py = _read_pkg_file(pkg_root, "src/firewatch_mywidget/config.py")
        assert "ADR-0006" in config_py

    def test_config_uses_upper_case_env_prefix(self, tmp_path: Path) -> None:
        """Env vars must use FIREWATCH_MYWIDGET_ prefix (consistent with existing plugins)."""
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        config_py = _read_pkg_file(pkg_root, "src/firewatch_mywidget/config.py")
        assert "FIREWATCH_MYWIDGET_" in config_py


# ---------------------------------------------------------------------------
# EARS-3: generated package must not import core, another plugin, or legacy
# ---------------------------------------------------------------------------


class TestIsolation:
    """EARS-3 — generated source files may only import from firewatch-sdk."""

    _FORBIDDEN = re.compile(
        r"^\s*(from|import)\s+(firewatch_core|legacy)\b",
        re.MULTILINE,
    )
    _FIREWATCH_IMPORT = re.compile(
        r"^\s*(from firewatch_\w+|import firewatch_\w+)",
        re.MULTILINE,
    )

    def _src_files(self, pkg_root: Path) -> list[Path]:
        src_dir = pkg_root / "src"
        return list(src_dir.rglob("*.py"))

    def test_no_firewatch_core_import(self, tmp_path: Path) -> None:
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        for py_file in self._src_files(pkg_root):
            content = py_file.read_text()
            assert "firewatch_core" not in content, (
                f"{py_file.name} references firewatch_core — forbidden (PLUGIN_CONTRACT.md)"
            )

    def test_no_legacy_import(self, tmp_path: Path) -> None:
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        for py_file in self._src_files(pkg_root):
            content = py_file.read_text()
            match = self._FORBIDDEN.search(content)
            assert match is None, (
                f"{py_file.name}: forbidden import: {match.group()!r}"
            )

    def test_firewatch_imports_are_sdk_or_self_only(self, tmp_path: Path) -> None:
        """Imports from the firewatch_* namespace must be sdk or own module only."""
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        for py_file in self._src_files(pkg_root):
            content = py_file.read_text()
            for line in content.splitlines():
                stripped = line.strip()
                if stripped.startswith("from firewatch_") or stripped.startswith("import firewatch_"):
                    assert "firewatch_sdk" in stripped or "firewatch_mywidget" in stripped, (
                        f"{py_file.name}: forbidden import: {stripped!r}"
                    )

    def test_generated_plugin_is_importable(self, tmp_path: Path) -> None:
        """plugin.py must be importable in isolation (no missing imports at the
        module level — only placeholders inside functions are fine)."""
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        src_dir = str(pkg_root / "src")
        result = subprocess.run(
            [sys.executable, "-c", "import firewatch_mywidget.plugin"],
            capture_output=True,
            text=True,
            env={
                **__import__("os").environ,
                "PYTHONPATH": src_dir,
            },
        )
        assert result.returncode == 0, (
            f"firewatch_mywidget.plugin import failed:\n{result.stderr}"
        )

    def test_generated_config_is_importable(self, tmp_path: Path) -> None:
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        src_dir = str(pkg_root / "src")
        result = subprocess.run(
            [sys.executable, "-c", "import firewatch_mywidget.config"],
            capture_output=True,
            text=True,
            env={
                **__import__("os").environ,
                "PYTHONPATH": src_dir,
            },
        )
        assert result.returncode == 0, (
            f"firewatch_mywidget.config import failed:\n{result.stderr}"
        )

    def test_generated_normalize_is_importable(self, tmp_path: Path) -> None:
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        src_dir = str(pkg_root / "src")
        result = subprocess.run(
            [sys.executable, "-c", "import firewatch_mywidget.normalize"],
            capture_output=True,
            text=True,
            env={
                **__import__("os").environ,
                "PYTHONPATH": src_dir,
            },
        )
        assert result.returncode == 0, (
            f"firewatch_mywidget.normalize import failed:\n{result.stderr}"
        )


# ---------------------------------------------------------------------------
# EARS-4: refuse to overwrite an existing package
# ---------------------------------------------------------------------------


class TestNoOverwrite:
    """EARS-4 — the tool must refuse to clobber an existing package directory."""

    def test_refuses_to_overwrite_existing_package(self, tmp_path: Path) -> None:
        """Running twice on the same name must fail the second time."""
        # First run: success
        result1 = _run_scaffold("mywidget", cwd=tmp_path)
        assert result1.returncode == 0

        # Second run: must exit non-zero and NOT silently overwrite
        result2 = _run_scaffold("mywidget", cwd=tmp_path)
        assert result2.returncode != 0, (
            "Expected non-zero exit when target already exists; got 0 (silent overwrite)"
        )

    def test_error_message_mentions_existing_path(self, tmp_path: Path) -> None:
        """The refusal error must mention the existing path or name."""
        _run_scaffold("mywidget", cwd=tmp_path)  # first run
        result = _run_scaffold("mywidget", cwd=tmp_path)  # second run
        combined = result.stdout + result.stderr
        assert "mywidget" in combined.lower() or "exist" in combined.lower(), (
            f"Expected error to mention 'mywidget' or 'exist'; got: {combined!r}"
        )

    def test_refuses_even_with_different_flavor(self, tmp_path: Path) -> None:
        """Changing --flavor on the second run must not bypass the guard."""
        _run_scaffold("mywidget", flavor="pull", cwd=tmp_path)
        result = _run_scaffold("mywidget", flavor="push", cwd=tmp_path)
        assert result.returncode != 0


# ---------------------------------------------------------------------------
# EARS-1 continued: test stubs are immediately runnable (golden-test template)
# ---------------------------------------------------------------------------


class TestGeneratedTestStubs:
    """EARS-1 / DoD — generated tests/ must be runnable with pytest (pass green)."""

    def test_generated_test_plugin_runs_with_pytest(self, tmp_path: Path) -> None:
        """The generated test_plugin.py tests that don't require a dist install must pass.

        Entry-point discovery tests (test_entry_point_is_registered,
        test_entry_point_loads_to_source_class) require the package to be installed
        as a distribution (uv pip install -e .) so that importlib.metadata can see it.
        Those tests are generated correctly and pass after install — the same pattern
        used by suricata and syslog plugins.

        Here we run with -k 'not entry_point' to verify all non-discovery tests pass
        immediately (isolation, SourcePlugin conformance, config, normalize stubs).
        """
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                str(pkg_root / "tests"),
                "-v",
                "--tb=short",
                "--import-mode=importlib",
                # Entry-point tests require dist install (importlib.metadata);
                # skip them here — they are correct but not runnable without install.
                "-k",
                "not entry_point",
            ],
            capture_output=True,
            text=True,
            env={
                **__import__("os").environ,
                "PYTHONPATH": str(pkg_root / "src"),
            },
        )
        assert result.returncode == 0, (
            f"Generated tests failed:\n{result.stdout}\n{result.stderr}"
        )

    def test_generated_test_plugin_has_entry_point_test(self, tmp_path: Path) -> None:
        """test_plugin.py must contain an entry-point isolation test."""
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        test_py = _read_pkg_file(pkg_root, "tests/test_plugin.py")
        assert "entry_point" in test_py.lower() or "entry-point" in test_py.lower() or (
            "firewatch.sources" in test_py
        )

    def test_generated_test_normalize_has_golden_stub(self, tmp_path: Path) -> None:
        """test_normalize.py must have a placeholder golden test the author fills in."""
        pkg_root = _scaffold("mywidget", tmp_path=tmp_path)
        test_py = _read_pkg_file(pkg_root, "tests/test_normalize.py")
        assert "normalize" in test_py.lower()
        # Must have a TODO marker so authors know to fill it in
        assert "TODO" in test_py or "todo" in test_py.lower() or "FILL" in test_py


# ---------------------------------------------------------------------------
# Edge cases: name validation
# ---------------------------------------------------------------------------


class TestNameValidation:
    """The type_key constraint: ^[a-z][a-z0-9_]*$ (PLUGIN_CONTRACT.md / ADR-0025).

    Must start with a lowercase letter; leading underscore and leading digit are
    reserved/invalid. Digits and underscores may appear after the first character.
    """

    def test_rejects_uppercase_name(self, tmp_path: Path) -> None:
        result = _run_scaffold("MyWidget", cwd=tmp_path)
        assert result.returncode != 0

    def test_rejects_hyphenated_name(self, tmp_path: Path) -> None:
        result = _run_scaffold("my-widget", cwd=tmp_path)
        assert result.returncode != 0

    def test_rejects_name_with_spaces(self, tmp_path: Path) -> None:
        result = _run_scaffold("my widget", cwd=tmp_path)
        assert result.returncode != 0

    def test_accepts_underscore_name(self, tmp_path: Path) -> None:
        result = _run_scaffold("my_widget", cwd=tmp_path)
        assert result.returncode == 0

    def test_accepts_alphanumeric_name(self, tmp_path: Path) -> None:
        result = _run_scaffold("azure2", cwd=tmp_path)
        assert result.returncode == 0

    def test_rejects_empty_name(self, tmp_path: Path) -> None:
        result = _run_scaffold("", cwd=tmp_path)
        assert result.returncode != 0

    def test_rejects_leading_digit(self, tmp_path: Path) -> None:
        """Names starting with a digit must be rejected (^[a-z][a-z0-9_]*$ requires letter-first)."""
        for bad in ("0bad", "1source", "2widget"):
            result = _run_scaffold(bad, cwd=tmp_path)
            assert result.returncode != 0, (
                f"Expected {bad!r} to be rejected but got exit 0"
            )

    def test_rejects_leading_underscore(self, tmp_path: Path) -> None:
        """Names starting with underscore must be rejected (reserved for core in ADR-0025)."""
        result = _run_scaffold("_global", cwd=tmp_path)
        assert result.returncode != 0, (
            "'_global' starts with underscore (reserved for core) but was accepted"
        )

    def test_rejects_path_traversal_dotdot(self, tmp_path: Path) -> None:
        """Path-traversal names like ../../etc must be rejected by name validation."""
        result = _run_scaffold("../../etc", cwd=tmp_path)
        assert result.returncode != 0

    def test_rejects_absolute_path_name(self, tmp_path: Path) -> None:
        """/etc/passwd as name must be rejected."""
        result = _run_scaffold("/etc/passwd", cwd=tmp_path)
        assert result.returncode != 0

    def test_rejects_name_with_slash(self, tmp_path: Path) -> None:
        """foo/bar must be rejected (slash is not in ^[a-z][a-z0-9_]*$)."""
        result = _run_scaffold("foo/bar", cwd=tmp_path)
        assert result.returncode != 0

    def test_rejects_name_with_dot(self, tmp_path: Path) -> None:
        """foo.bar must be rejected (dot is not in ^[a-z][a-z0-9_]*$)."""
        result = _run_scaffold("foo.bar", cwd=tmp_path)
        assert result.returncode != 0

    def test_accepts_valid_names(self, tmp_path: Path) -> None:
        """suricata and my_widget are valid — must be accepted."""
        result = _run_scaffold("suricata", cwd=tmp_path)
        assert result.returncode == 0, (
            f"'suricata' should be accepted; got exit {result.returncode}"
        )

    def test_accepts_valid_name_with_underscore(self, tmp_path: Path) -> None:
        """my_widget is valid (starts with letter, contains underscore)."""
        result = _run_scaffold("my_widget", cwd=tmp_path)
        assert result.returncode == 0, (
            f"'my_widget' should be accepted; got exit {result.returncode}"
        )
