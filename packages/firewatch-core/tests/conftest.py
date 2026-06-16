"""Make sibling test helpers (e.g. `_fakes`) importable under importlib mode."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Exempt @slow tests from the fast global pytest-timeout (pyproject: timeout=45).

    The known-slow KV-cardinality tests run 157-298s; without this they would false-fail
    under the global hang-guard. A @slow test that sets its own ``timeout`` marker wins.
    """
    for item in items:
        if item.get_closest_marker("slow") and not item.get_closest_marker("timeout"):
            item.add_marker(pytest.mark.timeout(600))
