"""run_pull_cycle tests (EARS-4 — watermark dispatch on (source_type, source_id))."""
from datetime import datetime, timedelta, timezone

from firewatch_sdk import AIEngine, EventStore, PluginContext, RawEvent

from firewatch_core.pipeline import Pipeline
from _fakes import FakeAIEngine, FakePullPlugin, FakeStore


def _ctx(store: FakeStore, type_key: str, source_id: str) -> PluginContext:
    """Mint a PluginContext the same way the supervisor does (ADR-0027 §3)."""
    from firewatch_core.scoped_kv import scoped_kv
    from firewatch_sdk import EventStore as _ES
    typed_store: _ES = store
    kv = scoped_kv(typed_store, type_key)
    return PluginContext(kv=kv, source_id=source_id)

T0 = datetime(2026, 6, 3, 12, 0, 0, tzinfo=timezone.utc)


def _raws() -> list[RawEvent]:
    return [
        RawEvent(source_type="suricata", received_at=T0,
                 data={"src_ip": "203.0.113.5"}),
        RawEvent(source_type="suricata", received_at=T0 + timedelta(minutes=5),
                 data={"src_ip": "203.0.113.6"}),
    ]


def _pipeline(store):
    ai: AIEngine = FakeAIEngine()
    return Pipeline(store, ai)


async def test_pull_cycle_dispatches_watermark_by_instance():
    store = FakeStore([])
    typed_store: EventStore = store
    plugin = FakePullPlugin(type_key="suricata", raws=_raws())
    cfg = plugin.config_schema()()
    ctx = _ctx(store, "suricata", "pi-home")

    inserted = await _pipeline(typed_store).run_pull_cycle(plugin, cfg, "pi-home", ctx)

    assert inserted == 2
    assert store.get_watermark_calls == [("suricata", "pi-home")]
    # watermark advanced to the newest raw received_at
    assert store.watermarks[("suricata", "pi-home")] == (T0 + timedelta(minutes=5)).isoformat()


async def test_pull_cycle_passes_prior_watermark_as_since():
    store = FakeStore([])
    store.watermarks[("suricata", "pi-home")] = "2026-06-03T11:00:00+00:00"
    typed_store: EventStore = store
    plugin = FakePullPlugin(type_key="suricata", raws=_raws())
    cfg = plugin.config_schema()()
    ctx = _ctx(store, "suricata", "pi-home")

    await _pipeline(typed_store).run_pull_cycle(plugin, cfg, "pi-home", ctx)
    assert plugin.collect_since == "2026-06-03T11:00:00+00:00"


async def test_pull_cycle_per_source_id_watermarks_are_independent():
    store = FakeStore([])
    typed_store: EventStore = store
    pipe = _pipeline(typed_store)

    ctx_home = _ctx(store, "suricata", "pi-home")
    ctx_azure = _ctx(store, "suricata", "azure-lab")

    await pipe.run_pull_cycle(FakePullPlugin("suricata", _raws()), plugin_cfg(), "pi-home", ctx_home)
    await pipe.run_pull_cycle(FakePullPlugin("suricata", _raws()), plugin_cfg(), "azure-lab", ctx_azure)

    assert set(store.watermarks) == {("suricata", "pi-home"), ("suricata", "azure-lab")}


async def test_pull_cycle_no_events_does_not_write_watermark():
    store = FakeStore([])
    typed_store: EventStore = store
    plugin = FakePullPlugin(type_key="suricata", raws=[])
    cfg = plugin.config_schema()()
    ctx = _ctx(store, "suricata", "pi-home")

    inserted = await _pipeline(typed_store).run_pull_cycle(plugin, cfg, "pi-home", ctx)
    assert inserted == 0
    assert store.set_watermark_calls == []


def plugin_cfg():
    return FakePullPlugin().config_schema()()
