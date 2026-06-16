"""Tests for issue #150 — enrichment wiring in the live collect→normalize→persist pipeline.

EARS criteria covered (mapped 1:1 from issue #150):

E1  When run_pull_cycle() ingests events, each configured enricher is called once
    with the ingested events (geo enrichment fires in the live path).

E2  When run_pull_cycle() completes, any rule descriptions stored in the plugin's
    source_kv (namespace="rule_descriptions") are promoted to the global
    rule_descriptions table, so get_rule_descriptions() returns them.

E3  When no events are collected (empty cycle), enrichers are NOT called and no
    source_kv promotion is attempted.

E4  When an enricher raises, the exception is caught, logged, and the pipeline
    continues (fail-safe; ADR-0003).

E5  The pipeline factory (_build_pipeline) wires a GeoEnricher to the pipeline so
    the live collect path has geo enrichment.

NOTE: RFC 5737 doc IPs (192.0.2.x, 198.51.100.x, 203.0.113.x) are used exclusively
as source IPs. The GeoEnricher's _is_non_public guard treats them as non-global — tests
that exercise the "public IP gets geo-resolved" path must patch _is_non_public, as the
existing geo_enricher tests do (see test_geo_enricher.py, G2 fixtures).
"""
from __future__ import annotations

from datetime import datetime, timezone

from firewatch_sdk import (
    PluginContext,
    RawEvent,
    SecurityEvent,
)

from firewatch_core.pipeline import Pipeline
from _fakes import FakeAIEngine, FakePullPlugin, FakeStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

T0 = datetime(2026, 6, 3, 12, 0, 0, tzinfo=timezone.utc)
_DOC_IP = "192.0.2.10"


def _ctx(store: FakeStore, type_key: str, source_id: str) -> PluginContext:
    """Mint a PluginContext the same way the supervisor does (ADR-0027 §3)."""
    from firewatch_core.scoped_kv import scoped_kv
    kv = scoped_kv(store, type_key)  # type: ignore[arg-type]
    return PluginContext(kv=kv, source_id=source_id)


def _raws(ip: str = _DOC_IP) -> list[RawEvent]:
    return [
        RawEvent(
            source_type="suricata",
            received_at=T0,
            data={"src_ip": ip},
        )
    ]


class _RecordingEnricher:
    """Enricher that records how many times it was called and with which events."""

    name: str = "recording"

    def __init__(self) -> None:
        self.calls: list[list[SecurityEvent]] = []

    async def enrich(self, events: list[SecurityEvent]) -> list[SecurityEvent]:
        self.calls.append(list(events))
        return events


class _RaisingEnricher:
    """Enricher that always raises (to test fail-safe posture)."""

    name: str = "raising"

    async def enrich(self, events: list[SecurityEvent]) -> list[SecurityEvent]:
        raise RuntimeError("enricher exploded")


# ---------------------------------------------------------------------------
# E1 — Enrichers fire during run_pull_cycle
# ---------------------------------------------------------------------------


class TestEnricherFiringInPullCycle:
    """E1 — after ingest, each configured enricher is called with the ingested events."""

    async def test_single_enricher_called_once_per_cycle(self) -> None:
        """A single enricher is called exactly once per pull cycle."""
        store = FakeStore()
        plugin = FakePullPlugin(type_key="suricata", raws=_raws())
        cfg = plugin.config_schema()()
        ctx = _ctx(store, "suricata", "pi-home")
        enricher = _RecordingEnricher()
        pipeline = Pipeline(
            store=store,  # type: ignore[arg-type]
            ai_engine=FakeAIEngine(),  # type: ignore[arg-type]
            enrichers=[enricher],  # type: ignore[arg-type]
        )

        await pipeline.run_pull_cycle(plugin, cfg, "pi-home", ctx)

        assert len(enricher.calls) == 1, (
            f"Expected enricher to be called once; called {len(enricher.calls)} time(s)"
        )

    async def test_multiple_enrichers_each_called_once(self) -> None:
        """Multiple enrichers are each called once per pull cycle."""
        store = FakeStore()
        plugin = FakePullPlugin(type_key="suricata", raws=_raws())
        cfg = plugin.config_schema()()
        ctx = _ctx(store, "suricata", "pi-home")
        e1 = _RecordingEnricher()
        e2 = _RecordingEnricher()
        pipeline = Pipeline(
            store=store,  # type: ignore[arg-type]
            ai_engine=FakeAIEngine(),  # type: ignore[arg-type]
            enrichers=[e1, e2],  # type: ignore[arg-type]
        )

        await pipeline.run_pull_cycle(plugin, cfg, "pi-home", ctx)

        assert len(e1.calls) == 1
        assert len(e2.calls) == 1

    async def test_enricher_receives_the_ingested_events(self) -> None:
        """The enricher receives the list of events that were ingested this cycle."""
        store = FakeStore()
        plugin = FakePullPlugin(type_key="suricata", raws=_raws(_DOC_IP))
        cfg = plugin.config_schema()()
        ctx = _ctx(store, "suricata", "pi-home")
        enricher = _RecordingEnricher()
        pipeline = Pipeline(
            store=store,  # type: ignore[arg-type]
            ai_engine=FakeAIEngine(),  # type: ignore[arg-type]
            enrichers=[enricher],  # type: ignore[arg-type]
        )

        await pipeline.run_pull_cycle(plugin, cfg, "pi-home", ctx)

        assert len(enricher.calls[0]) == 1
        assert enricher.calls[0][0].source_ip == _DOC_IP

    async def test_no_enrichers_by_default(self) -> None:
        """Pipeline with no enrichers parameter works as before (no regression)."""
        store = FakeStore()
        plugin = FakePullPlugin(type_key="suricata", raws=_raws())
        cfg = plugin.config_schema()()
        ctx = _ctx(store, "suricata", "pi-home")
        pipeline = Pipeline(
            store=store,  # type: ignore[arg-type]
            ai_engine=FakeAIEngine(),  # type: ignore[arg-type]
        )

        inserted = await pipeline.run_pull_cycle(plugin, cfg, "pi-home", ctx)
        assert inserted == 1


# ---------------------------------------------------------------------------
# E2 — Rule descriptions promoted from source_kv after pull cycle
# ---------------------------------------------------------------------------


class TestRuleDescriptionsPromotedAfterPullCycle:
    """E2 — rule descriptions stored by the plugin in ctx.kv are promoted to global table."""

    async def test_source_kv_rule_descs_promoted_to_global_after_cycle(self) -> None:
        """After a pull cycle, source_kv entries under 'rule_descriptions' reach get_rule_descriptions()."""
        store = FakeStore()
        plugin = FakePullPlugin(type_key="suricata", raws=_raws())
        cfg = plugin.config_schema()()
        ctx = _ctx(store, "suricata", "pi-home")

        # Simulate what the plugin does during collect: write rule descriptions to kv
        await ctx.kv.put("rule_descriptions", "2001001", "ET SCAN Potential VNC Scan")
        await ctx.kv.put("rule_descriptions", "2002000", "ET MALWARE Generic")

        pipeline = Pipeline(
            store=store,  # type: ignore[arg-type]
            ai_engine=FakeAIEngine(),  # type: ignore[arg-type]
        )

        await pipeline.run_pull_cycle(plugin, cfg, "pi-home", ctx)

        descs = await store.get_rule_descriptions()
        assert "2001001" in descs, (
            "SID 2001001 must appear in global rule_descriptions after pull cycle"
        )
        assert descs["2001001"] == "ET SCAN Potential VNC Scan"
        assert "2002000" in descs

    async def test_empty_source_kv_means_no_rule_descs(self) -> None:
        """If the plugin wrote no rule descriptions, get_rule_descriptions() stays empty."""
        store = FakeStore()
        plugin = FakePullPlugin(type_key="suricata", raws=_raws())
        cfg = plugin.config_schema()()
        ctx = _ctx(store, "suricata", "pi-home")

        pipeline = Pipeline(
            store=store,  # type: ignore[arg-type]
            ai_engine=FakeAIEngine(),  # type: ignore[arg-type]
        )

        await pipeline.run_pull_cycle(plugin, cfg, "pi-home", ctx)

        descs = await store.get_rule_descriptions()
        assert descs == {}

    async def test_promotion_uses_source_type_from_plugin_not_argument(self) -> None:
        """Rule description promotion reads from the plugin's type_key, not caller argument."""
        store = FakeStore()
        plugin = FakePullPlugin(type_key="suricata", raws=_raws())
        cfg = plugin.config_schema()()
        ctx = _ctx(store, "suricata", "pi-home")

        # Write under "suricata" scope (via ctx.kv, which is scoped to "suricata")
        await ctx.kv.put("rule_descriptions", "9999999", "Suricata rule")

        # Write under a different source_type scope manually (should NOT be promoted
        # by this suricata pull cycle)
        await store.source_kv_put("azure_waf", "rule_descriptions", "8888888", "WAF rule")

        pipeline = Pipeline(
            store=store,  # type: ignore[arg-type]
            ai_engine=FakeAIEngine(),  # type: ignore[arg-type]
        )

        await pipeline.run_pull_cycle(plugin, cfg, "pi-home", ctx)

        descs = await store.get_rule_descriptions()
        # Only the suricata rule should be promoted (source_type from plugin.metadata())
        assert "9999999" in descs
        # The azure_waf rule was never promoted by this cycle (wrong source_type)
        assert "8888888" not in descs


# ---------------------------------------------------------------------------
# E3 — Empty cycle: enrichers not called, no source_kv promotion
# ---------------------------------------------------------------------------


class TestEmptyCycleNoop:
    """E3 — when no events are collected, enrichers are not called."""

    async def test_enricher_not_called_on_empty_cycle(self) -> None:
        """Enrichers must not be called when collect() yields no events."""
        store = FakeStore()
        plugin = FakePullPlugin(type_key="suricata", raws=[])  # empty
        cfg = plugin.config_schema()()
        ctx = _ctx(store, "suricata", "pi-home")
        enricher = _RecordingEnricher()
        pipeline = Pipeline(
            store=store,  # type: ignore[arg-type]
            ai_engine=FakeAIEngine(),  # type: ignore[arg-type]
            enrichers=[enricher],  # type: ignore[arg-type]
        )

        inserted = await pipeline.run_pull_cycle(plugin, cfg, "pi-home", ctx)

        assert inserted == 0
        assert enricher.calls == [], (
            "Enricher must not be called when no events were collected"
        )

    async def test_rule_desc_promotion_skipped_on_empty_cycle(self) -> None:
        """Rule description promotion is skipped when no events are collected."""
        store = FakeStore()
        plugin = FakePullPlugin(type_key="suricata", raws=[])
        cfg = plugin.config_schema()()
        ctx = _ctx(store, "suricata", "pi-home")

        # Pre-write a rule description to kv
        await ctx.kv.put("rule_descriptions", "2001001", "ET SCAN")

        pipeline = Pipeline(
            store=store,  # type: ignore[arg-type]
            ai_engine=FakeAIEngine(),  # type: ignore[arg-type]
        )

        await pipeline.run_pull_cycle(plugin, cfg, "pi-home", ctx)

        # No promotion on empty cycle — get_rule_descriptions stays empty
        descs = await store.get_rule_descriptions()
        assert descs == {}


# ---------------------------------------------------------------------------
# E4 — Enricher exception is caught (fail-safe)
# ---------------------------------------------------------------------------


class TestEnricherFailSafe:
    """E4 — an enricher that raises must not crash the pipeline (ADR-0003)."""

    async def test_raising_enricher_does_not_crash_pipeline(self) -> None:
        """A crashing enricher must be caught; the pipeline returns the inserted count."""
        store = FakeStore()
        plugin = FakePullPlugin(type_key="suricata", raws=_raws())
        cfg = plugin.config_schema()()
        ctx = _ctx(store, "suricata", "pi-home")
        pipeline = Pipeline(
            store=store,  # type: ignore[arg-type]
            ai_engine=FakeAIEngine(),  # type: ignore[arg-type]
            enrichers=[_RaisingEnricher()],  # type: ignore[arg-type]
        )

        # Must not raise
        inserted = await pipeline.run_pull_cycle(plugin, cfg, "pi-home", ctx)
        assert inserted == 1, "Events must still be ingested even when enricher raises"

    async def test_enricher_exception_does_not_skip_remaining_enrichers(self) -> None:
        """A crashing enricher must not prevent subsequent enrichers from running."""
        store = FakeStore()
        plugin = FakePullPlugin(type_key="suricata", raws=_raws())
        cfg = plugin.config_schema()()
        ctx = _ctx(store, "suricata", "pi-home")
        good = _RecordingEnricher()
        pipeline = Pipeline(
            store=store,  # type: ignore[arg-type]
            ai_engine=FakeAIEngine(),  # type: ignore[arg-type]
            enrichers=[_RaisingEnricher(), good],  # type: ignore[arg-type]
        )

        await pipeline.run_pull_cycle(plugin, cfg, "pi-home", ctx)

        assert len(good.calls) == 1, (
            "The second (good) enricher must still run after the first raises"
        )


# ---------------------------------------------------------------------------
# E5 — _build_pipeline wires GeoEnricher
# ---------------------------------------------------------------------------


class TestPipelineFactoryWiresGeoEnricher:
    """E5 — the pipeline factory must wire a geo enricher to the live pipeline.

    ADR-0039: the default is now ``MmdbGeoEnricher`` (geo_provider=offline);
    ``GeoEnricher`` (ip-api.com) is used only when geo_provider=online.
    Either way, the pipeline must have exactly one enricher whose name is "geo".
    """

    def test_build_pipeline_returns_pipeline_with_geo_enricher(self) -> None:
        """_build_pipeline returns a Pipeline whose enrichers include a geo enricher.

        The specific type depends on geo_provider (offline → MmdbGeoEnricher,
        online → GeoEnricher). Both expose name='geo' per the Enricher protocol.
        """
        from firewatch_sdk import Enricher
        from firewatch_cli.commands._pipeline_factory import _build_pipeline

        pipeline = _build_pipeline(config_file=None)

        assert hasattr(pipeline, "enrichers"), (
            "Pipeline must expose an 'enrichers' attribute"
        )
        geo_enrichers = [
            e for e in pipeline.enrichers  # type: ignore[attr-defined]
            if isinstance(e, Enricher) and getattr(e, "name", None) == "geo"
        ]
        assert len(geo_enrichers) >= 1, (
            f"Pipeline must have at least one geo enricher (name='geo'); "
            f"got enrichers: {[type(e).__name__ for e in pipeline.enrichers]}"  # type: ignore[attr-defined]
        )
