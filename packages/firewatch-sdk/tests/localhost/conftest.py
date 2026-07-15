"""Make sibling test helpers (``_fakes``) importable under importlib mode."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
