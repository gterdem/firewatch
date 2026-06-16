"""Loader tests (EARS-1 discovery + registry, EARS-2 load-failure resilience)."""
from collections.abc import Callable

import firewatch_core.loader as loader_mod
from firewatch_core.loader import load_source_plugins
from _fakes import FakePullPlugin


class GoodSuricata(FakePullPlugin):
    def __init__(self) -> None:
        super().__init__(type_key="suricata")


class GoodSyslog(FakePullPlugin):
    def __init__(self) -> None:
        super().__init__(type_key="syslog")


class FakeEP:
    """Minimal importlib.metadata.EntryPoint stand-in."""

    def __init__(self, name: str, loader: Callable[[], type]) -> None:
        self.name = name
        self._loader = loader

    def load(self) -> type:
        return self._loader()


def _patch_entry_points(monkeypatch, eps: list[FakeEP]) -> None:
    monkeypatch.setattr(loader_mod, "entry_points", lambda group: eps)


def test_discovers_and_registers_plugins(monkeypatch):
    _patch_entry_points(monkeypatch, [
        FakeEP("suricata", lambda: GoodSuricata),
        FakeEP("syslog", lambda: GoodSyslog),
    ])
    registry = load_source_plugins()
    assert set(registry) == {"suricata", "syslog"}
    assert isinstance(registry["suricata"], GoodSuricata)
    assert registry["suricata"].metadata().type_key == "suricata"


def test_failing_plugin_is_skipped_without_aborting(monkeypatch):
    def _boom() -> type:
        raise ImportError("dependency missing")

    _patch_entry_points(monkeypatch, [
        FakeEP("broken", _boom),
        FakeEP("suricata", lambda: GoodSuricata),
    ])
    registry = load_source_plugins()  # must not raise
    assert "broken" not in registry
    assert "suricata" in registry


def test_no_plugins_returns_empty_registry(monkeypatch):
    _patch_entry_points(monkeypatch, [])
    assert load_source_plugins() == {}
