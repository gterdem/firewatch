"""Make sibling test helpers (e.g. `_reference`) importable under importlib mode."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
