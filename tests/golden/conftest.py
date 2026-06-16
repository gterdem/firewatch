"""Conftest for tests/golden — adds the package tests helpers to sys.path."""
from __future__ import annotations

import sys
from pathlib import Path

# Expose _fakes from firewatch-core/tests so score tests can reuse FakeStore/FakeAIEngine.
_core_tests = Path(__file__).parent.parent.parent / "packages" / "firewatch-core" / "tests"
if str(_core_tests) not in sys.path:
    sys.path.insert(0, str(_core_tests))
