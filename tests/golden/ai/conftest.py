"""Conftest for tests/golden/ai — adds tests/ root to sys.path so that
``from golden.ai.fixtures import ...`` works under pytest's importlib mode."""
from __future__ import annotations

import sys
from pathlib import Path

_tests_root = Path(__file__).parent.parent.parent  # tests/
if str(_tests_root) not in sys.path:
    sys.path.insert(0, str(_tests_root))
