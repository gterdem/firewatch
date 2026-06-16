"""Tests for ML-10 — beaconing + rare-flow detection (issue #438).

Mapped 1:1 to EARS criteria from issue #438.

EARS-1  A detector SHALL flag:
        (a) periodic src->dst check-ins (timing-delta regularity), keyed on
            the now-persisted destination_ip.
        (b) first-seen (src, dst_ip, dst_port) combinations vs. a rolling baseline.
        - score_periodicity detects regularity; low CV means beaconing
        - first-seen flag fires when (src, dst_ip, dst_port) not in baseline
        - non-periodic (random) inter-arrival times do NOT get flagged as beaconing
        - NULL/missing inter-arrival (single event) does NOT crash; degrades to None
        - empty event list returns empty verdicts

EARS-2  Anomaly verdicts SHALL be queryable as a FilterSpec facet (anomaly_type)
        and exposed as inline row badges (anomaly_flags on paginated rows).
        - FilterSpec accepts anomaly_type field (extensible: "beaconing", "rare_flow", etc.)
        - get_paginated with anomaly_type="beaconing" returns only beacon-flagged rows
        - get_paginated with anomaly_type="rare_flow" returns only rare-flow-flagged rows
        - rows carry anomaly_flags list (possibly empty) in paginated output
        - beaconing anomaly_type is an inline filter; no separate route created

EARS-3  Rolling baseline SHALL persist via core-owned table (no plugin DDL).
        - flow_baseline table created by init() (idempotent)
        - upsert_flow_baseline stores (src_ip, dst_ip, dst_port, first_seen, last_seen, count)
        - upsert_flow_baseline increments count on repeated (src, dst_ip, dst_port) key
        - get_flow_baseline_entry returns None for unknown (src, dst_ip, dst_port)
        - get_flow_baseline_entry returns entry for known combination
        - migration NB-8 adds table to existing DB without data loss (idempotent)

EARS-4  R3 SHALL be able to narrate WHY a flow was flagged (flag_reason / provenance).
        - AnomalyVerdict carries flag_reason string explaining detection
        - flag_reason is non-empty when flagged=True
        - flag_reason includes diagnostic numbers (CV for beaconing, dst_ip/dst_port for
          first-seen) so a narrator can cite them
        - when NOT flagged, flag_reason is None

All IPs use RFC 5737 / RFC 1918 documentation ranges -- never real/routable IPs.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from firewatch_sdk import SecurityEvent
from firewatch_sdk.models import FilterSpec
from firewatch_core.adapters.sqlite_store import SQLiteEventStore
from firewatch_core.analytics.beaconing import (
    AnomalyVerdict,
    BeaconingDetector,
    FlowKey,
    score_periodicity,
)


# ---------------------------------------------------------------------------
# Helpers / constants
# ---------------------------------------------------------------------------

# RFC 5737 / RFC 1918 IPs -- never real/routable
_SRC_A = "192.0.2.10"
_SRC_B = "192.0.2.20"
_DST_A = "198.51.100.1"
_DST_B = "198.51.100.2"
_DST_C = "203.0.113.50"

_BASE_TS = datetime(2026, 6, 13, 12, 0, 0, tzinfo=timezone.utc)


def _ev(
    *,
    source_ip: str = _SRC_A,
    destination_ip: str | None = _DST_A,
    destination_port: int | None = 443,
    ts_offset_sec: int = 0,
    **kwargs: Any,
) -> SecurityEvent:
    """Build a minimal SecurityEvent with RFC-compliant IPs."""
    ts = _BASE_TS + timedelta(seconds=ts_offset_sec)
    return SecurityEvent(
        source_type="suricata",
        source_id="sensor",
        source_ip=source_ip,
        destination_ip=destination_ip,
        destination_port=destination_port,
        action="ALERT",
        timestamp=ts,
        **kwargs,
    )


def _periodic_events(
    src: str = _SRC_A,
    dst: str = _DST_A,
    port: int = 443,
    interval_sec: int = 60,
    count: int = 10,
) -> list[SecurityEvent]:
    """Generate a list of events with perfectly periodic inter-arrival times."""
    return [
        _ev(
            source_ip=src,
            destination_ip=dst,
            destination_port=port,
            ts_offset_sec=i * interval_sec,
        )
        for i in range(count)
    ]


@pytest.fixture
async def store(tmp_path: Path) -> SQLiteEventStore:  # type: ignore[misc]
    s = SQLiteEventStore(tmp_path / "ml10.db")
    await s.init()
    yield s  # type: ignore[misc]
    await s.close()


# ---------------------------------------------------------------------------
# EARS-1a: periodicity (timing-delta regularity) detection
# ---------------------------------------------------------------------------


class TestPeriodicityScoring:
    """EARS-1a -- score_periodicity detects regular inter-arrival times."""

    def test_perfectly_periodic_has_zero_cv(self) -> None:
        """Perfectly periodic events have CV ~= 0 (coefficient of variation)."""
        events = _periodic_events(interval_sec=60, count=10)
        result = score_periodicity(events)
        assert result is not None
        # CV near 0 for perfect regularity
        assert result.cv < 0.05

    def test_perfectly_periodic_is_flagged(self) -> None:
        """Periodic check-ins (low CV) are flagged as beaconing."""
        events = _periodic_events(interval_sec=60, count=10)
        result = score_periodicity(events)
        assert result is not None
        assert result.flagged is True

    def test_random_intervals_not_flagged(self) -> None:
        """Random / high-variance inter-arrival times are NOT flagged as beaconing."""
        # Jitter between 1s and 900s is irregular (CV >> threshold)
        offsets = [0, 1, 4, 70, 150, 155, 300, 310, 600, 900]
        events = [
            _ev(ts_offset_sec=off) for off in offsets
        ]
        result = score_periodicity(events)
        assert result is not None
        assert result.flagged is False

    def test_single_event_returns_none(self) -> None:
        """A single event has no inter-arrival deltas -- degrades gracefully to None."""
        result = score_periodicity([_ev(ts_offset_sec=0)])
        assert result is None

    def test_empty_events_returns_none(self) -> None:
        """Empty event list returns None (no crash)."""
        result = score_periodicity([])
        assert result is None

    def test_two_events_returns_none(self) -> None:
        """Two events have only one delta -- insufficient for CV; returns None."""
        result = score_periodicity([_ev(ts_offset_sec=0), _ev(ts_offset_sec=60)])
        # Require >= 3 events for a meaningful CV
        assert result is None


class TestPeriodicityFlagReason:
    """EARS-4 -- flag_reason is non-empty for flagged events; None for non-flagged."""

    def test_flagged_beacon_has_flag_reason(self) -> None:
        """A flagged beaconing verdict carries a non-empty flag_reason string."""
        events = _periodic_events(interval_sec=60, count=10)
        result = score_periodicity(events)
        assert result is not None
        assert result.flagged is True
        assert result.flag_reason is not None
        assert len(result.flag_reason) > 0

    def test_flagged_reason_cites_cv(self) -> None:
        """flag_reason cites the CV value so R3 can narrate the detection."""
        events = _periodic_events(interval_sec=60, count=10)
        result = score_periodicity(events)
        assert result is not None
        # flag_reason should mention CV or coefficient of variation
        reason_lower = result.flag_reason.lower() if result.flag_reason else ""
        assert "cv" in reason_lower or "coefficient" in reason_lower

    def test_non_flagged_has_no_flag_reason(self) -> None:
        """A non-flagged verdict has flag_reason=None."""
        offsets = [0, 1, 4, 70, 150, 155, 300, 310, 600, 900]
        events = [_ev(ts_offset_sec=off) for off in offsets]
        result = score_periodicity(events)
        assert result is not None
        assert result.flagged is False
        assert result.flag_reason is None


# ---------------------------------------------------------------------------
# EARS-1b: first-seen (rare-flow) detection
# ---------------------------------------------------------------------------


class TestFirstSeenDetection:
    """EARS-1b -- BeaconingDetector flags first-seen (src, dst_ip, dst_port) vs baseline."""

    @pytest.mark.asyncio
    async def test_new_flow_is_flagged_as_rare(self, store: SQLiteEventStore) -> None:
        """A (src, dst_ip, dst_port) combo not in baseline is flagged as rare_flow."""
        detector = BeaconingDetector(store)
        ev = _ev(source_ip=_SRC_A, destination_ip=_DST_A, destination_port=443)
        verdict = await detector.check_rare_flow(ev)
        assert verdict.flagged is True
        assert verdict.anomaly_type == "rare_flow"

    @pytest.mark.asyncio
    async def test_known_flow_is_not_flagged(self, store: SQLiteEventStore) -> None:
        """A (src, dst_ip, dst_port) combo already in baseline is NOT flagged."""
        detector = BeaconingDetector(store)
        # Prime the baseline
        await store.upsert_flow_baseline(
            src_ip=_SRC_A,
            dst_ip=_DST_A,
            dst_port=443,
            first_seen=_BASE_TS.isoformat(),
            last_seen=_BASE_TS.isoformat(),
        )
        ev = _ev(source_ip=_SRC_A, destination_ip=_DST_A, destination_port=443)
        verdict = await detector.check_rare_flow(ev)
        assert verdict.flagged is False

    @pytest.mark.asyncio
    async def test_null_destination_ip_does_not_crash(
        self, store: SQLiteEventStore
    ) -> None:
        """An event with NULL destination_ip gracefully degrades (no crash)."""
        detector = BeaconingDetector(store)
        ev = _ev(destination_ip=None, destination_port=None)
        # Should not crash; must return a verdict with flagged=False
        verdict = await detector.check_rare_flow(ev)
        assert verdict is not None
        assert verdict.flagged is False

    @pytest.mark.asyncio
    async def test_rare_flow_flag_reason_cites_dst(
        self, store: SQLiteEventStore
    ) -> None:
        """EARS-4: rare_flow flag_reason cites dst_ip and dst_port for narration."""
        detector = BeaconingDetector(store)
        ev = _ev(source_ip=_SRC_A, destination_ip=_DST_A, destination_port=8443)
        verdict = await detector.check_rare_flow(ev)
        assert verdict.flagged is True
        assert verdict.flag_reason is not None
        # flag_reason must include enough info for R3 to narrate why
        assert _DST_A in verdict.flag_reason or "8443" in verdict.flag_reason


# ---------------------------------------------------------------------------
# EARS-3: flow_baseline table (persistence, migration, idempotency)
# ---------------------------------------------------------------------------


class TestFlowBaselinePersistence:
    """EARS-3 -- flow_baseline table: upsert, lookup, migration idempotency."""

    @pytest.mark.asyncio
    async def test_init_creates_flow_baseline_table(
        self, store: SQLiteEventStore
    ) -> None:
        """init() creates the flow_baseline table (EARS-3)."""
        import aiosqlite
        async with aiosqlite.connect(str(store.db_path)) as db:
            cursor = await db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='flow_baseline'"
            )
            row = await cursor.fetchone()
        assert row is not None, "flow_baseline table must be created by init()"

    @pytest.mark.asyncio
    async def test_upsert_stores_entry(self, store: SQLiteEventStore) -> None:
        """upsert_flow_baseline stores a (src, dst_ip, dst_port) entry."""
        await store.upsert_flow_baseline(
            src_ip=_SRC_A,
            dst_ip=_DST_A,
            dst_port=443,
            first_seen=_BASE_TS.isoformat(),
            last_seen=_BASE_TS.isoformat(),
        )
        entry = await store.get_flow_baseline_entry(_SRC_A, _DST_A, 443)
        assert entry is not None
        assert entry["src_ip"] == _SRC_A
        assert entry["dst_ip"] == _DST_A
        assert entry["dst_port"] == 443

    @pytest.mark.asyncio
    async def test_upsert_increments_count(self, store: SQLiteEventStore) -> None:
        """Repeated upserts on the same (src, dst_ip, dst_port) increment the count."""
        for _ in range(3):
            await store.upsert_flow_baseline(
                src_ip=_SRC_A,
                dst_ip=_DST_A,
                dst_port=443,
                first_seen=_BASE_TS.isoformat(),
                last_seen=(_BASE_TS + timedelta(seconds=120)).isoformat(),
            )
        entry = await store.get_flow_baseline_entry(_SRC_A, _DST_A, 443)
        assert entry is not None
        assert entry["count"] >= 3

    @pytest.mark.asyncio
    async def test_upsert_updates_last_seen(self, store: SQLiteEventStore) -> None:
        """Repeated upserts update last_seen to the most recent timestamp."""
        later = _BASE_TS + timedelta(hours=1)
        await store.upsert_flow_baseline(
            src_ip=_SRC_A,
            dst_ip=_DST_A,
            dst_port=443,
            first_seen=_BASE_TS.isoformat(),
            last_seen=_BASE_TS.isoformat(),
        )
        await store.upsert_flow_baseline(
            src_ip=_SRC_A,
            dst_ip=_DST_A,
            dst_port=443,
            first_seen=_BASE_TS.isoformat(),
            last_seen=later.isoformat(),
        )
        entry = await store.get_flow_baseline_entry(_SRC_A, _DST_A, 443)
        assert entry is not None
        assert entry["last_seen"] == later.isoformat()

    @pytest.mark.asyncio
    async def test_unknown_combination_returns_none(
        self, store: SQLiteEventStore
    ) -> None:
        """get_flow_baseline_entry returns None for an unknown (src, dst_ip, dst_port)."""
        entry = await store.get_flow_baseline_entry(_SRC_A, _DST_B, 9999)
        assert entry is None

    @pytest.mark.asyncio
    async def test_different_dst_port_is_separate_key(
        self, store: SQLiteEventStore
    ) -> None:
        """(src, dst_ip, dst_port=80) and (src, dst_ip, dst_port=443) are separate keys."""
        await store.upsert_flow_baseline(
            src_ip=_SRC_A,
            dst_ip=_DST_A,
            dst_port=80,
            first_seen=_BASE_TS.isoformat(),
            last_seen=_BASE_TS.isoformat(),
        )
        # Port 443 not in baseline
        entry = await store.get_flow_baseline_entry(_SRC_A, _DST_A, 443)
        assert entry is None

    @pytest.mark.asyncio
    async def test_migration_noop_on_existing_db(self, tmp_path: Path) -> None:
        """NB-8: calling init() twice does not error on the flow_baseline table."""
        db_path = tmp_path / "double_init.db"
        s = SQLiteEventStore(db_path)
        await s.init()
        await s.init()  # second init must be a no-op
        await s.close()

    @pytest.mark.asyncio
    async def test_migration_adds_table_to_old_schema(self, tmp_path: Path) -> None:
        """NB-8: an old-schema DB without flow_baseline gets the table on init()."""
        import aiosqlite
        db_path = tmp_path / "old_schema.db"

        # Simulate an old DB with only the minimal schema (no flow_baseline)
        async with aiosqlite.connect(str(db_path)) as db:
            await db.execute("""
                CREATE TABLE logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_ip TEXT NOT NULL,
                    destination_port INTEGER NOT NULL DEFAULT 0,
                    protocol TEXT NOT NULL DEFAULT '',
                    action TEXT NOT NULL,
                    rule_id TEXT,
                    rule_name TEXT,
                    payload_snippet TEXT,
                    timestamp TEXT NOT NULL,
                    source_type TEXT NOT NULL DEFAULT 'unknown',
                    source_id TEXT NOT NULL DEFAULT 'default',
                    severity TEXT,
                    category TEXT
                )
            """)
            await db.execute(
                "INSERT INTO logs (source_ip, action, timestamp) VALUES (?, ?, ?)",
                (_SRC_A, "ALERT", _BASE_TS.isoformat()),
            )
            await db.commit()

        # Run init() -- should create flow_baseline without error
        s = SQLiteEventStore(db_path)
        await s.init()

        async with aiosqlite.connect(str(db_path)) as db:
            cursor = await db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='flow_baseline'"
            )
            row = await cursor.fetchone()
        assert row is not None, "NB-8 migration must add flow_baseline table"

        # Original data must survive
        events = await s.get_by_ip(_SRC_A)
        assert len(events) >= 1
        await s.close()


# ---------------------------------------------------------------------------
# EARS-2: anomaly_type FilterSpec facet + inline row badges
# ---------------------------------------------------------------------------


class TestAnomalyFacet:
    """EARS-2 -- anomaly_type FilterSpec facet + anomaly_flags on paginated rows."""

    def test_filterspec_accepts_anomaly_type(self) -> None:
        """FilterSpec has anomaly_type field (extensible to ML-11 and beyond)."""
        fs = FilterSpec(anomaly_type="beaconing")
        assert fs.anomaly_type == "beaconing"

    def test_filterspec_anomaly_type_defaults_none(self) -> None:
        """anomaly_type defaults to None (no filter applied by default)."""
        fs = FilterSpec()
        assert fs.anomaly_type is None

    def test_filterspec_anomaly_type_none_no_filter(self) -> None:
        """None anomaly_type means no filtering -- backward compatible."""
        fs = FilterSpec(anomaly_type=None)
        assert fs.anomaly_type is None

    @pytest.mark.asyncio
    async def test_paginated_rows_carry_anomaly_flags_field(
        self, store: SQLiteEventStore
    ) -> None:
        """Paginated rows include anomaly_flags list (possibly empty)."""
        await store.save_many([_ev(ts_offset_sec=0)])
        result = await store.get_paginated()
        assert result["total_matching"] == 1
        row = result["logs"][0]
        # anomaly_flags must be present (list, possibly empty)
        assert "anomaly_flags" in row
        assert isinstance(row["anomaly_flags"], list)

    @pytest.mark.asyncio
    async def test_beaconing_flagged_row_has_badge(
        self, store: SQLiteEventStore
    ) -> None:
        """A row tagged with a beaconing anomaly carries 'beaconing' in anomaly_flags."""
        # Insert an event and manually write its anomaly into the anomaly_verdicts table
        ev = _ev(ts_offset_sec=0)
        await store.save_many([ev])

        # Record a beaconing verdict for this flow
        await store.record_anomaly_verdict(
            src_ip=_SRC_A,
            dst_ip=_DST_A,
            dst_port=443,
            anomaly_type="beaconing",
            flag_reason="Periodic check-in detected: CV=0.02",
        )

        result = await store.get_paginated()
        assert result["total_matching"] == 1
        row = result["logs"][0]
        assert "beaconing" in row["anomaly_flags"]

    @pytest.mark.asyncio
    async def test_anomaly_type_filter_returns_flagged_rows_only(
        self, store: SQLiteEventStore
    ) -> None:
        """anomaly_type='beaconing' filter returns only rows flagged as beaconing."""
        # Row A: beaconing flagged (to DST_A port 443)
        ev_a = _ev(
            source_ip=_SRC_A,
            destination_ip=_DST_A,
            destination_port=443,
            ts_offset_sec=0,
        )
        # Row B: no anomaly (to DST_B port 80)
        ev_b = _ev(
            source_ip=_SRC_B,
            destination_ip=_DST_B,
            destination_port=80,
            ts_offset_sec=1,
        )
        await store.save_many([ev_a, ev_b])

        await store.record_anomaly_verdict(
            src_ip=_SRC_A,
            dst_ip=_DST_A,
            dst_port=443,
            anomaly_type="beaconing",
            flag_reason="CV=0.01",
        )

        result = await store.get_paginated(filters=FilterSpec(anomaly_type="beaconing"))
        # Only the beaconing-flagged row (ev_a) should appear
        assert result["total_matching"] == 1
        assert result["logs"][0]["source_ip"] == _SRC_A

    @pytest.mark.asyncio
    async def test_rare_flow_filter_returns_rare_flow_rows_only(
        self, store: SQLiteEventStore
    ) -> None:
        """anomaly_type='rare_flow' filter returns only rare-flow-flagged rows."""
        ev_a = _ev(
            source_ip=_SRC_A,
            destination_ip=_DST_A,
            destination_port=443,
            ts_offset_sec=0,
        )
        ev_b = _ev(
            source_ip=_SRC_B,
            destination_ip=_DST_B,
            destination_port=80,
            ts_offset_sec=1,
        )
        await store.save_many([ev_a, ev_b])

        await store.record_anomaly_verdict(
            src_ip=_SRC_A,
            dst_ip=_DST_A,
            dst_port=443,
            anomaly_type="rare_flow",
            flag_reason="First-seen flow to 198.51.100.1:443",
        )

        result = await store.get_paginated(filters=FilterSpec(anomaly_type="rare_flow"))
        assert result["total_matching"] == 1
        assert result["logs"][0]["source_ip"] == _SRC_A

    @pytest.mark.asyncio
    async def test_anomaly_type_filter_extensible_to_new_type(
        self, store: SQLiteEventStore
    ) -> None:
        """anomaly_type filter works for any string -- extensible to ML-11 volumetric."""
        ev = _ev(ts_offset_sec=0)
        await store.save_many([ev])

        await store.record_anomaly_verdict(
            src_ip=_SRC_A,
            dst_ip=_DST_A,
            dst_port=443,
            anomaly_type="volumetric_exfil",  # future ML-11 type
            flag_reason="Data exfil suspected",
        )

        result = await store.get_paginated(
            filters=FilterSpec(anomaly_type="volumetric_exfil")
        )
        assert result["total_matching"] == 1

    @pytest.mark.asyncio
    async def test_no_anomaly_filter_returns_all_rows(
        self, store: SQLiteEventStore
    ) -> None:
        """No anomaly_type filter returns all rows (backward compatible)."""
        await store.save_many([
            _ev(ts_offset_sec=0),
            _ev(source_ip=_SRC_B, ts_offset_sec=1),
        ])
        result = await store.get_paginated()
        assert result["total_matching"] == 2


# ---------------------------------------------------------------------------
# EARS-4 (provenance): AnomalyVerdict carries structured flag_reason
# ---------------------------------------------------------------------------


class TestAnomalyVerdictProvenance:
    """EARS-4 -- AnomalyVerdict provides structured provenance for R3 narration."""

    def test_anomaly_verdict_flagged_has_reason(self) -> None:
        """A flagged AnomalyVerdict carries flag_reason; unflagged carries None."""
        flagged = AnomalyVerdict(
            flow_key=FlowKey(src_ip=_SRC_A, dst_ip=_DST_A, dst_port=443),
            flagged=True,
            anomaly_type="beaconing",
            flag_reason="Periodic check-in: CV=0.01 (threshold=0.20)",
        )
        assert flagged.flagged is True
        assert flagged.flag_reason is not None
        assert "CV" in flagged.flag_reason

    def test_anomaly_verdict_not_flagged_has_no_reason(self) -> None:
        """An unflagged AnomalyVerdict has flag_reason=None."""
        not_flagged = AnomalyVerdict(
            flow_key=FlowKey(src_ip=_SRC_A, dst_ip=_DST_A, dst_port=443),
            flagged=False,
            anomaly_type=None,
            flag_reason=None,
        )
        assert not_flagged.flagged is False
        assert not_flagged.flag_reason is None

    def test_flow_key_includes_dst_ip_and_port(self) -> None:
        """FlowKey carries dst_ip and dst_port (the destination-keyed fields)."""
        key = FlowKey(src_ip=_SRC_A, dst_ip=_DST_A, dst_port=8443)
        assert key.dst_ip == _DST_A
        assert key.dst_port == 8443


# ---------------------------------------------------------------------------
# EARS-1: detect() integration -- run both checks together
# ---------------------------------------------------------------------------


class TestBeaconingDetectorIntegration:
    """Integration test: BeaconingDetector.detect() runs both checks."""

    @pytest.mark.asyncio
    async def test_detect_periodic_events_returns_beaconing_verdict(
        self, store: SQLiteEventStore
    ) -> None:
        """detect() with periodic events returns a beaconing verdict."""
        events = _periodic_events(interval_sec=60, count=10)
        detector = BeaconingDetector(store)
        verdicts = await detector.detect(events)
        beacon_verdicts = [v for v in verdicts if v.anomaly_type == "beaconing"]
        assert len(beacon_verdicts) >= 1
        assert all(v.flagged for v in beacon_verdicts)

    @pytest.mark.asyncio
    async def test_detect_new_flow_returns_rare_flow_verdict(
        self, store: SQLiteEventStore
    ) -> None:
        """detect() on a new (src, dst_ip, dst_port) returns a rare_flow verdict."""
        events = [_ev(ts_offset_sec=0)]
        detector = BeaconingDetector(store)
        verdicts = await detector.detect(events)
        rare_verdicts = [v for v in verdicts if v.anomaly_type == "rare_flow"]
        assert len(rare_verdicts) >= 1

    @pytest.mark.asyncio
    async def test_detect_empty_events_returns_empty(
        self, store: SQLiteEventStore
    ) -> None:
        """detect() with empty event list returns []."""
        detector = BeaconingDetector(store)
        verdicts = await detector.detect([])
        assert verdicts == []

    @pytest.mark.asyncio
    async def test_detect_null_dst_ip_events_not_crash(
        self, store: SQLiteEventStore
    ) -> None:
        """detect() with events that have NULL dst_ip/port does not crash."""
        events = [_ev(destination_ip=None, destination_port=None)]
        detector = BeaconingDetector(store)
        verdicts = await detector.detect(events)
        # Should not crash; NULL-dst events are skipped (no flow key derivable)
        assert isinstance(verdicts, list)


# ---------------------------------------------------------------------------
# Golden oracle guard: existing scoring is unaffected
# ---------------------------------------------------------------------------


class TestGoldenOraclePreserved:
    """Verify beaconing detection does not perturb existing scoring paths."""

    def test_import_does_not_affect_scoring_module(self) -> None:
        """Importing beaconing module does not break the scoring module."""
        from firewatch_core.scoring import run_rules  # noqa: F401
        from firewatch_core.analytics.beaconing import BeaconingDetector  # noqa: F401
        # If imports succeed without error, the modules are independent

    def test_detector_module_does_not_import_legacy(self) -> None:
        """beaconing module must not import legacy/ (non-negotiable)."""
        import importlib
        import sys
        importlib.import_module("firewatch_core.analytics.beaconing")
        for name in list(sys.modules.keys()):
            if name.startswith("legacy"):
                mod = sys.modules.get(name)
                if mod is not None:
                    assert False, f"beaconing module imported legacy module: {name}"
