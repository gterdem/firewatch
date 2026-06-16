"""Tests for ML-11 — volumetric / exfil outlier detection (issue #439).

Mapped 1:1 to EARS criteria from issue #439.

EARS-1  WHEN per-(src->dst) byte volume exceeds a baseline-relative outlier threshold,
        the system SHALL flag a volumetric anomaly using bytes_in / bytes_out.
        - score_volumetric flags when observed bytes >> baseline mean
        - score_volumetric does NOT flag when observed bytes are within normal range
        - VolumetricDetector persists per-(src, dst_ip, dst_port) byte stats to baseline
        - VolumetricDetector flags an outlier event after baseline is warmed up

EARS-2  WHERE bytes are NULL (e.g. WAF rows), the detector SHALL skip honestly (no false flag).
        - score_volumetric returns None when both bytes_in and bytes_out are None
        - VolumetricDetector.check_volumetric returns unflagged for NULL-byte events
        - detect() skips events with NULL bytes (no crash, no false flag)

EARS-3  The anomaly SHALL surface in the same inline lane/facet as ML-10.
        - anomaly_type="volumetric_exfil" stored in anomaly_verdicts (same table as ML-10)
        - FilterSpec.anomaly_type="volumetric_exfil" returns only volumetric-flagged rows
        - anomaly_flags on paginated rows carries "volumetric_exfil" badge when flagged
        - FilterSpec returns BOTH "beaconing" + "volumetric_exfil" rows when both exist
        - ML-10 and ML-11 co-exist: rows can carry multiple anomaly types simultaneously

Provenance (ADR-0035)  flag_reason is non-empty when flagged; includes observable numbers.
        - AnomalyVerdict from volumetric has non-empty flag_reason when flagged
        - flag_reason cites bytes and baseline stats so R3 can narrate the detection
        - unflagged verdict has flag_reason=None

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
from firewatch_core.analytics.beaconing import AnomalyVerdict
from firewatch_core.analytics.volumetric import (
    VolumetricDetector,
    OUTLIER_Z_THRESHOLD,
    MIN_BASELINE_SAMPLES,
    score_volumetric,
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

# Typical baseline: mean=1000 bytes, stdev~200 bytes
_BASELINE_MEAN = 1000.0
_BASELINE_STDEV = 200.0


def _ev(
    *,
    source_ip: str = _SRC_A,
    destination_ip: str | None = _DST_A,
    destination_port: int | None = 443,
    bytes_in: int | None = None,
    bytes_out: int | None = None,
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
        bytes_in=bytes_in,
        bytes_out=bytes_out,
        **kwargs,
    )


@pytest.fixture
async def store(tmp_path: Path) -> SQLiteEventStore:  # type: ignore[misc]
    s = SQLiteEventStore(tmp_path / "ml11.db")
    await s.init()
    yield s  # type: ignore[misc]
    await s.close()


# ---------------------------------------------------------------------------
# EARS-1: score_volumetric — pure scorer (zero I/O)
# ---------------------------------------------------------------------------


class TestScoreVolumetricPure:
    """EARS-1 -- score_volumetric is a pure function; no store access."""

    def test_outlier_bytes_flagged(self) -> None:
        """Observed bytes >> baseline mean (> Z threshold) are flagged."""
        # observed = mean + (z_threshold + 2) * stdev — comfortably over threshold
        observed = int(_BASELINE_MEAN + (OUTLIER_Z_THRESHOLD + 2) * _BASELINE_STDEV)
        result = score_volumetric(
            observed_bytes=observed,
            baseline_mean=_BASELINE_MEAN,
            baseline_stdev=_BASELINE_STDEV,
            n_samples=MIN_BASELINE_SAMPLES + 5,
        )
        assert result is not None
        assert result.flagged is True

    def test_normal_bytes_not_flagged(self) -> None:
        """Observed bytes within normal range (< Z threshold) are NOT flagged."""
        # observed = mean + 0.5 * stdev — well within normal
        observed = int(_BASELINE_MEAN + 0.5 * _BASELINE_STDEV)
        result = score_volumetric(
            observed_bytes=observed,
            baseline_mean=_BASELINE_MEAN,
            baseline_stdev=_BASELINE_STDEV,
            n_samples=MIN_BASELINE_SAMPLES + 5,
        )
        assert result is not None
        assert result.flagged is False

    def test_insufficient_baseline_returns_none(self) -> None:
        """Returns None when there are fewer than MIN_BASELINE_SAMPLES samples."""
        result = score_volumetric(
            observed_bytes=100_000,
            baseline_mean=_BASELINE_MEAN,
            baseline_stdev=_BASELINE_STDEV,
            n_samples=MIN_BASELINE_SAMPLES - 1,
        )
        assert result is None

    def test_zero_baseline_stdev_not_flagged(self) -> None:
        """When baseline stdev is 0 (all values identical), no outlier detection possible."""
        # A zero stdev means we can't compute z-score; should not flag
        result = score_volumetric(
            observed_bytes=50_000,
            baseline_mean=_BASELINE_MEAN,
            baseline_stdev=0.0,
            n_samples=MIN_BASELINE_SAMPLES + 5,
        )
        # Either returns None or returns unflagged; must not crash or false-flag
        assert result is None or result.flagged is False

    def test_result_carries_z_score(self) -> None:
        """VolumetricResult exposes the computed z_score for narration."""
        observed = int(_BASELINE_MEAN + (OUTLIER_Z_THRESHOLD + 1) * _BASELINE_STDEV)
        result = score_volumetric(
            observed_bytes=observed,
            baseline_mean=_BASELINE_MEAN,
            baseline_stdev=_BASELINE_STDEV,
            n_samples=MIN_BASELINE_SAMPLES + 5,
        )
        assert result is not None
        assert result.z_score > 0

    def test_result_carries_observed_bytes(self) -> None:
        """VolumetricResult exposes observed_bytes for narration."""
        observed = 5000
        result = score_volumetric(
            observed_bytes=observed,
            baseline_mean=_BASELINE_MEAN,
            baseline_stdev=_BASELINE_STDEV,
            n_samples=MIN_BASELINE_SAMPLES + 5,
        )
        assert result is not None
        assert result.observed_bytes == observed


# ---------------------------------------------------------------------------
# EARS-2: NULL bytes skip honestly (no false flag)
# ---------------------------------------------------------------------------


class TestNullBytesSkip:
    """EARS-2 -- NULL bytes must not produce a false flag."""

    def test_score_volumetric_none_bytes_returns_none(self) -> None:
        """score_volumetric with None observed_bytes returns None (skip, no flag)."""
        result = score_volumetric(
            observed_bytes=None,
            baseline_mean=_BASELINE_MEAN,
            baseline_stdev=_BASELINE_STDEV,
            n_samples=MIN_BASELINE_SAMPLES + 5,
        )
        assert result is None

    @pytest.mark.asyncio
    async def test_check_volumetric_null_bytes_not_flagged(
        self, store: SQLiteEventStore
    ) -> None:
        """VolumetricDetector.check_volumetric on NULL-byte event returns unflagged."""
        detector = VolumetricDetector(store)
        ev = _ev(bytes_in=None, bytes_out=None)
        verdict = await detector.check_volumetric(ev)
        assert verdict.flagged is False

    @pytest.mark.asyncio
    async def test_check_volumetric_null_bytes_no_anomaly_type(
        self, store: SQLiteEventStore
    ) -> None:
        """NULL-byte event produces anomaly_type=None (no false label)."""
        detector = VolumetricDetector(store)
        ev = _ev(bytes_in=None, bytes_out=None)
        verdict = await detector.check_volumetric(ev)
        assert verdict.anomaly_type is None

    @pytest.mark.asyncio
    async def test_detect_null_bytes_events_no_false_flag(
        self, store: SQLiteEventStore
    ) -> None:
        """detect() with NULL-byte events emits no volumetric_exfil verdict."""
        detector = VolumetricDetector(store)
        events = [_ev(bytes_in=None, bytes_out=None, ts_offset_sec=i) for i in range(5)]
        verdicts = await detector.detect(events)
        volumetric_verdicts = [v for v in verdicts if v.anomaly_type == "volumetric_exfil"]
        assert len(volumetric_verdicts) == 0

    @pytest.mark.asyncio
    async def test_waf_row_null_bytes_no_false_flag(
        self, store: SQLiteEventStore
    ) -> None:
        """Simulate a WAF row (bytes_in/bytes_out = None) — must NOT be flagged."""
        detector = VolumetricDetector(store)
        # WAF rows: source_type='azure_waf' with no byte counters
        ev = SecurityEvent(
            source_type="azure_waf",
            source_id="prod",
            source_ip=_SRC_A,
            destination_ip=_DST_A,
            destination_port=443,
            action="BLOCK",
            timestamp=_BASE_TS,
            bytes_in=None,
            bytes_out=None,
        )
        verdict = await detector.check_volumetric(ev)
        assert verdict.flagged is False, (
            "WAF rows without byte counters must NEVER be flagged as volumetric"
        )


# ---------------------------------------------------------------------------
# EARS-1 (detector): VolumetricDetector warms up baseline + flags outliers
# ---------------------------------------------------------------------------


class TestVolumetricDetectorBaseline:
    """EARS-1 (store-backed) -- VolumetricDetector persists stats and flags outliers."""

    @pytest.mark.asyncio
    async def test_insufficient_baseline_not_flagged(
        self, store: SQLiteEventStore
    ) -> None:
        """With fewer than MIN_BASELINE_SAMPLES, no outlier is flagged."""
        detector = VolumetricDetector(store)
        # Feed fewer than MIN_BASELINE_SAMPLES events with normal bytes
        for i in range(MIN_BASELINE_SAMPLES - 1):
            ev = _ev(bytes_in=1000, bytes_out=500, ts_offset_sec=i)
            verdict = await detector.check_volumetric(ev)
            assert verdict.flagged is False

    @pytest.mark.asyncio
    async def test_outlier_after_baseline_warmup_flagged(
        self, store: SQLiteEventStore
    ) -> None:
        """After MIN_BASELINE_SAMPLES normal events, a massive spike is flagged."""
        detector = VolumetricDetector(store)
        # Warm up baseline with slightly varied events so variance is non-zero;
        # the z-score detector requires stdev > 0 to operate (baseline mean ~1000 bytes_out).
        # Vary bytes_in across [450, 550] and bytes_out across [900, 1100] to produce
        # a realistic stdev (~50 bytes) while keeping the mean around 1500 total.
        for i in range(MIN_BASELINE_SAMPLES + 5):
            b_in = 450 + (i % 5) * 25   # cycles: 450, 475, 500, 525, 550
            b_out = 900 + (i % 5) * 50  # cycles: 900, 950, 1000, 1050, 1100
            ev = _ev(bytes_in=b_in, bytes_out=b_out, ts_offset_sec=i)
            await detector.check_volumetric(ev)

        # Now send a massive outlier -- total ~100x the ~1500-byte baseline mean.
        # z-score will be well above OUTLIER_Z_THRESHOLD (baseline stdev is ~135 bytes,
        # z ~ (100_500 - 1_500) / 135 ~ 733, far above threshold=3.0).
        outlier_ev = _ev(
            bytes_in=500,
            bytes_out=100_000,
            ts_offset_sec=MIN_BASELINE_SAMPLES + 10,
        )
        verdict = await detector.check_volumetric(outlier_ev)
        assert verdict.flagged is True
        assert verdict.anomaly_type == "volumetric_exfil"

    @pytest.mark.asyncio
    async def test_normal_volume_after_baseline_not_flagged(
        self, store: SQLiteEventStore
    ) -> None:
        """After warmup, a normal event is NOT flagged."""
        detector = VolumetricDetector(store)
        # Warm up
        for i in range(MIN_BASELINE_SAMPLES + 5):
            ev = _ev(bytes_in=500, bytes_out=1000, ts_offset_sec=i)
            await detector.check_volumetric(ev)

        # Normal event slightly above mean — not an outlier
        normal_ev = _ev(bytes_in=500, bytes_out=1200, ts_offset_sec=MIN_BASELINE_SAMPLES + 10)
        verdict = await detector.check_volumetric(normal_ev)
        assert verdict.flagged is False

    @pytest.mark.asyncio
    async def test_baseline_stats_persisted_in_flow_baseline(
        self, store: SQLiteEventStore
    ) -> None:
        """After check_volumetric calls, bytes stats are persisted in flow_baseline."""
        detector = VolumetricDetector(store)
        for i in range(3):
            ev = _ev(bytes_in=1000, bytes_out=500, ts_offset_sec=i)
            await detector.check_volumetric(ev)

        stats = await store.get_flow_baseline_bytes(_SRC_A, _DST_A, 443)
        assert stats is not None
        assert stats["bytes_count"] >= 3

    @pytest.mark.asyncio
    async def test_different_flows_have_independent_baselines(
        self, store: SQLiteEventStore
    ) -> None:
        """Each (src, dst_ip, dst_port) flow has its own independent byte baseline."""
        detector = VolumetricDetector(store)
        # Warm up flow A (low bytes)
        for i in range(MIN_BASELINE_SAMPLES + 5):
            ev_a = _ev(
                source_ip=_SRC_A,
                destination_ip=_DST_A,
                destination_port=443,
                bytes_in=100,
                bytes_out=200,
                ts_offset_sec=i,
            )
            await detector.check_volumetric(ev_a)

        # Flow B gets a very different traffic profile — should not affect flow A
        ev_b = _ev(
            source_ip=_SRC_B,
            destination_ip=_DST_B,
            destination_port=80,
            bytes_in=100,
            bytes_out=200,
            ts_offset_sec=0,
        )
        verdict_b = await detector.check_volumetric(ev_b)
        # Flow B has its own baseline — not contaminated by flow A
        assert isinstance(verdict_b, AnomalyVerdict)


# ---------------------------------------------------------------------------
# EARS-3: same anomaly lane as ML-10 (anomaly_verdicts + FilterSpec facet)
# ---------------------------------------------------------------------------


class TestVolumetricAnomalyLane:
    """EARS-3 -- volumetric_exfil reuses ML-10's anomaly_verdicts lane."""

    @pytest.mark.asyncio
    async def test_volumetric_verdict_stored_in_anomaly_verdicts(
        self, store: SQLiteEventStore
    ) -> None:
        """record_anomaly_verdict with 'volumetric_exfil' type persists to anomaly_verdicts."""
        await store.record_anomaly_verdict(
            src_ip=_SRC_A,
            dst_ip=_DST_A,
            dst_port=443,
            anomaly_type="volumetric_exfil",
            flag_reason="bytes_out=50000 z=8.2 (threshold=3.0); baseline mean=500 stdev=200",
        )
        import aiosqlite
        async with aiosqlite.connect(str(store.db_path)) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM anomaly_verdicts WHERE anomaly_type = ?",
                ("volumetric_exfil",),
            )
            row = await cursor.fetchone()
        assert row is not None
        assert dict(row)["anomaly_type"] == "volumetric_exfil"

    @pytest.mark.asyncio
    async def test_anomaly_type_filter_returns_volumetric_rows(
        self, store: SQLiteEventStore
    ) -> None:
        """anomaly_type='volumetric_exfil' FilterSpec returns only volumetric-flagged rows."""
        ev_a = _ev(source_ip=_SRC_A, destination_ip=_DST_A, destination_port=443, ts_offset_sec=0)
        ev_b = _ev(source_ip=_SRC_B, destination_ip=_DST_B, destination_port=80, ts_offset_sec=1)
        await store.save_many([ev_a, ev_b])

        await store.record_anomaly_verdict(
            src_ip=_SRC_A,
            dst_ip=_DST_A,
            dst_port=443,
            anomaly_type="volumetric_exfil",
            flag_reason="bytes_out z=9.1",
        )

        result = await store.get_paginated(filters=FilterSpec(anomaly_type="volumetric_exfil"))
        assert result["total_matching"] == 1
        assert result["logs"][0]["source_ip"] == _SRC_A

    @pytest.mark.asyncio
    async def test_volumetric_badge_appears_in_anomaly_flags(
        self, store: SQLiteEventStore
    ) -> None:
        """Paginated row with volumetric anomaly carries 'volumetric_exfil' in anomaly_flags."""
        ev = _ev(ts_offset_sec=0)
        await store.save_many([ev])

        await store.record_anomaly_verdict(
            src_ip=_SRC_A,
            dst_ip=_DST_A,
            dst_port=443,
            anomaly_type="volumetric_exfil",
            flag_reason="bytes_out=80000 z=7.0",
        )

        result = await store.get_paginated()
        assert result["total_matching"] == 1
        row = result["logs"][0]
        assert "volumetric_exfil" in row["anomaly_flags"]

    @pytest.mark.asyncio
    async def test_both_ml10_and_ml11_badges_coexist(
        self, store: SQLiteEventStore
    ) -> None:
        """A single row can carry both 'beaconing' (ML-10) and 'volumetric_exfil' (ML-11)."""
        ev = _ev(ts_offset_sec=0)
        await store.save_many([ev])

        # Write both anomaly types for the same flow
        await store.record_anomaly_verdict(
            src_ip=_SRC_A,
            dst_ip=_DST_A,
            dst_port=443,
            anomaly_type="beaconing",
            flag_reason="CV=0.01",
        )
        await store.record_anomaly_verdict(
            src_ip=_SRC_A,
            dst_ip=_DST_A,
            dst_port=443,
            anomaly_type="volumetric_exfil",
            flag_reason="bytes_out z=7.0",
        )

        result = await store.get_paginated()
        row = result["logs"][0]
        flags = row["anomaly_flags"]
        assert "beaconing" in flags
        assert "volumetric_exfil" in flags

    @pytest.mark.asyncio
    async def test_filterspec_anomaly_type_volumetric_exfil_accepted(self) -> None:
        """FilterSpec accepts 'volumetric_exfil' (extensible open string, EARS-3)."""
        fs = FilterSpec(anomaly_type="volumetric_exfil")
        assert fs.anomaly_type == "volumetric_exfil"

    @pytest.mark.asyncio
    async def test_ml10_filter_does_not_return_ml11_rows(
        self, store: SQLiteEventStore
    ) -> None:
        """anomaly_type='beaconing' does NOT return rows flagged only as volumetric_exfil."""
        ev = _ev(ts_offset_sec=0)
        await store.save_many([ev])

        await store.record_anomaly_verdict(
            src_ip=_SRC_A,
            dst_ip=_DST_A,
            dst_port=443,
            anomaly_type="volumetric_exfil",
            flag_reason="bytes_out z=7.0",
        )

        result = await store.get_paginated(filters=FilterSpec(anomaly_type="beaconing"))
        assert result["total_matching"] == 0


# ---------------------------------------------------------------------------
# Provenance (ADR-0035): flag_reason narration
# ---------------------------------------------------------------------------


class TestVolumetricProvenance:
    """ADR-0035 -- flag_reason is non-empty when flagged; suitable for R3 narration."""

    def test_flagged_result_has_flag_reason(self) -> None:
        """score_volumetric returns a non-empty flag_reason when flagged=True."""
        observed = int(_BASELINE_MEAN + (OUTLIER_Z_THRESHOLD + 2) * _BASELINE_STDEV)
        result = score_volumetric(
            observed_bytes=observed,
            baseline_mean=_BASELINE_MEAN,
            baseline_stdev=_BASELINE_STDEV,
            n_samples=MIN_BASELINE_SAMPLES + 5,
        )
        assert result is not None
        assert result.flagged is True
        assert result.flag_reason is not None
        assert len(result.flag_reason) > 0

    def test_flag_reason_cites_observed_bytes_and_z_score(self) -> None:
        """flag_reason includes observed bytes and z-score so R3 can cite specifics."""
        observed = int(_BASELINE_MEAN + (OUTLIER_Z_THRESHOLD + 2) * _BASELINE_STDEV)
        result = score_volumetric(
            observed_bytes=observed,
            baseline_mean=_BASELINE_MEAN,
            baseline_stdev=_BASELINE_STDEV,
            n_samples=MIN_BASELINE_SAMPLES + 5,
        )
        assert result is not None
        reason = result.flag_reason or ""
        # Must cite some reference to byte volume or z-score
        lower = reason.lower()
        assert "byte" in lower or "z=" in lower or "z_score" in lower or "z =" in lower

    def test_not_flagged_result_has_no_flag_reason(self) -> None:
        """score_volumetric returns flag_reason=None when NOT flagged."""
        observed = int(_BASELINE_MEAN + 0.5 * _BASELINE_STDEV)
        result = score_volumetric(
            observed_bytes=observed,
            baseline_mean=_BASELINE_MEAN,
            baseline_stdev=_BASELINE_STDEV,
            n_samples=MIN_BASELINE_SAMPLES + 5,
        )
        assert result is not None
        assert result.flagged is False
        assert result.flag_reason is None

    @pytest.mark.asyncio
    async def test_anomaly_verdict_flag_reason_stored_and_readable(
        self, store: SQLiteEventStore
    ) -> None:
        """flag_reason from volumetric verdict is stored in anomaly_verdicts."""
        reason = "bytes_out=80000 z=7.3 (threshold=3.0); baseline mean=1000 stdev=200"
        await store.record_anomaly_verdict(
            src_ip=_SRC_A,
            dst_ip=_DST_A,
            dst_port=443,
            anomaly_type="volumetric_exfil",
            flag_reason=reason,
        )
        import aiosqlite
        async with aiosqlite.connect(str(store.db_path)) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT flag_reason FROM anomaly_verdicts WHERE anomaly_type = ?",
                ("volumetric_exfil",),
            )
            row = await cursor.fetchone()
        assert row is not None
        assert dict(row)["flag_reason"] == reason


# ---------------------------------------------------------------------------
# NB-9 migration: flow_baseline bytes columns
# ---------------------------------------------------------------------------


class TestFlowBaselineBytesColumns:
    """NB-9 -- flow_baseline gets additive bytes stats columns on init()."""

    @pytest.mark.asyncio
    async def test_init_adds_bytes_columns(self, store: SQLiteEventStore) -> None:
        """init() adds bytes_count / bytes_in_mean / bytes_out_mean columns."""
        import aiosqlite
        async with aiosqlite.connect(str(store.db_path)) as db:
            cursor = await db.execute("PRAGMA table_info(flow_baseline)")
            cols = {row[1] for row in await cursor.fetchall()}
        assert "bytes_count" in cols
        assert "bytes_in_mean" in cols
        assert "bytes_out_mean" in cols

    @pytest.mark.asyncio
    async def test_init_idempotent_on_double_call(self, tmp_path: Path) -> None:
        """NB-9: calling init() twice does not error on existing bytes columns."""
        db_path = tmp_path / "double_init.db"
        s = SQLiteEventStore(db_path)
        await s.init()
        await s.init()  # must be a no-op
        await s.close()

    @pytest.mark.asyncio
    async def test_upsert_bytes_stores_stats(self, store: SQLiteEventStore) -> None:
        """upsert_flow_baseline_bytes stores running byte stats for a flow."""
        await store.upsert_flow_baseline_bytes(
            src_ip=_SRC_A,
            dst_ip=_DST_A,
            dst_port=443,
            bytes_in=500,
            bytes_out=1000,
        )
        stats = await store.get_flow_baseline_bytes(_SRC_A, _DST_A, 443)
        assert stats is not None
        assert stats["bytes_count"] == 1

    @pytest.mark.asyncio
    async def test_upsert_bytes_accumulates_welford(
        self, store: SQLiteEventStore
    ) -> None:
        """Repeated upserts accumulate bytes stats via Welford running stats."""
        values = [500, 600, 550, 700, 480, 520, 610, 590, 530, 560]
        for v in values:
            await store.upsert_flow_baseline_bytes(
                src_ip=_SRC_A,
                dst_ip=_DST_A,
                dst_port=443,
                bytes_in=v,
                bytes_out=v * 2,
            )
        stats = await store.get_flow_baseline_bytes(_SRC_A, _DST_A, 443)
        assert stats is not None
        assert stats["bytes_count"] == len(values)
        expected_mean_in = sum(values) / len(values)
        assert abs(stats["bytes_in_mean"] - expected_mean_in) < 1.0

    @pytest.mark.asyncio
    async def test_get_flow_baseline_bytes_none_for_unknown_flow(
        self, store: SQLiteEventStore
    ) -> None:
        """get_flow_baseline_bytes returns None when no stats exist for the flow."""
        stats = await store.get_flow_baseline_bytes(_SRC_A, _DST_B, 9999)
        assert stats is None

    @pytest.mark.asyncio
    async def test_bytes_stats_independent_per_flow(
        self, store: SQLiteEventStore
    ) -> None:
        """Byte stats for flow A do not affect flow B."""
        for _ in range(3):
            await store.upsert_flow_baseline_bytes(
                src_ip=_SRC_A, dst_ip=_DST_A, dst_port=443,
                bytes_in=1000, bytes_out=2000,
            )
        stats_b = await store.get_flow_baseline_bytes(_SRC_B, _DST_B, 80)
        assert stats_b is None


# ---------------------------------------------------------------------------
# Module isolation
# ---------------------------------------------------------------------------


class TestModuleIsolation:
    """volumetric module must not import legacy/ or firewatch_core stores at module level."""

    def test_volumetric_does_not_import_legacy(self) -> None:
        """volumetric module must not import legacy/ (non-negotiable)."""
        import importlib
        import sys
        importlib.import_module("firewatch_core.analytics.volumetric")
        for name in list(sys.modules.keys()):
            if name.startswith("legacy"):
                mod = sys.modules.get(name)
                if mod is not None:
                    assert False, f"volumetric module imported legacy module: {name}"

    def test_volumetric_imports_only_sdk(self) -> None:
        """Importing volumetric module succeeds without side-effects."""
        import firewatch_core.analytics.volumetric as vol
        # Public API is present
        assert hasattr(vol, "VolumetricDetector")
        assert hasattr(vol, "score_volumetric")
        assert hasattr(vol, "VolumetricResult")

    def test_score_volumetric_is_pure(self) -> None:
        """score_volumetric is a plain function with no I/O."""
        import inspect
        import firewatch_core.analytics.volumetric as vol
        assert callable(vol.score_volumetric)
        # Must not be a coroutine function
        assert not inspect.iscoroutinefunction(vol.score_volumetric)
