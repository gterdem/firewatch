"""Conftest for tests/volume — adds this directory to sys.path so sibling
modules (``generator``, ``harness``) are importable by bare name, mirroring
``tests/golden/conftest.py``'s convention."""
from __future__ import annotations

import sys
from pathlib import Path

_this_dir = Path(__file__).parent
if str(_this_dir) not in sys.path:
    sys.path.insert(0, str(_this_dir))
