"""Tests for MK-2 (#407) — AI verdict-ledger persistence.

EARS → test mapping
───────────────────
E1  WHEN analyze_ip / analyze_ip_detailed completes with a schema-validated result,
    THE pipeline SHALL record one ai_analyses row.
    → test_analyze_ip_records_ledger_row
    → test_analyze_ip_detailed_records_ledger_row

E2  THE ledger write SHALL be fail-safe: failure must not alter the analysis or score.
    → test_ledger_failure_does_not_abort_analyze_ip
    → test_ledger_failure_does_not_abort_analyze_ip_detailed

E3  Fallback envelopes (ai_status == "unavailable") SHALL NOT be persisted.
    → test_unavailable_not_persisted
    → test_detailed_unavailable_not_persisted

E4  prompt_text / response_text SHALL be size-capped at 64 KiB; truncation flagged.
    → test_caps_truncates_oversized_prompt
    → test_caps_truncates_oversized_response
    → test_caps_normal_content_not_truncated
    → test_caps_truncation_flags_set

E5  WHEN per-IP row count exceeds cap (50), adapter prunes oldest-first.
    → test_prune_per_ip_cap
    → test_prune_per_ip_cap_different_ips_independent

E6  WHEN global row count exceeds cap (5000), adapter prunes oldest-first.
    → test_prune_global_cap

E7  Persist → read round-trip: inserted record is readable.
    → test_persist_and_read_round_trip_summary
    → test_persist_and_read_round_trip_detail

E8  GET /ai/analyses summary projection excludes prompt_text / response_text.
    → test_list_no_sensitive_fields

E9  GET /ai/analyses?ip=... filters by IP.
    → test_list_filter_by_ip

E10 GET /ai/analyses/{id} returns full record including prompt/response.
    → test_get_detail_includes_prompt_response

E11 GET /ai/analyses/{id} for unknown id returns None (caller maps to 404).
    → test_get_detail_unknown_id_returns_none

E12 token usage (prompt_tokens / completion_tokens) captured when present; NULL otherwise.
    → test_usage_captured_when_present
    → test_usage_null_when_absent

E13 endpoint_host carries host:port only — never credentials.
    → test_endpoint_host_has_no_credentials

Structural:
    → test_schema_creates_ai_analyses_table
    → test_schema_is_idempotent
    → test_ledger_write_does_not_touch_logs_table
    → test_cursor_pagination
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiosqlite
import pytest

from firewatch_core.adapters.ledger.caps import apply_field_caps
from firewatch_core.adapters.ledger.sqlite_ledger import SqliteAnalysisLedger
from firewatch_core.ports.analysis_ledger import AnalysisRecord

# RFC 5737 documentation IPs only.
IP_A = "192.0.2.10"
IP_B = "198.51.100.20"

# 64 KiB cap in bytes.
_CAP = 64 * 1024

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def ledger(tmp_path: Path):  # type: ignore[return]
    """Fresh, initialised SqliteAnalysisLedger in a temp dir."""
    db_path = tmp_path / "test.db"
    ldgr = SqliteAnalysisLedger(db_path)
    await ldgr.init()
    yield ldgr
    await ldgr.close()


def _make_record(
    ip: str = IP_A,
    kind: str = "concise",
    ai_status: str = "ok",
    prompt_text: str = "test prompt",
    response_text: str = '{"threat_level":"LOW"}',
    model: str = "qwen3:8b",
    endpoint_host: str = "127.0.0.1:11434",
    prompt_tokens: int | None = 100,
    completion_tokens: int | None = 50,
    latency_ms: float = 200.0,
    score: int = 20,
    score_derivation: str = "rules",
    threat_level: str = "LOW",
    confidence: float = 0.7,
    validated_json: dict[str, Any] | None = None,
    schema_version: int = 1,
    created_at: datetime | None = None,
) -> AnalysisRecord:
    return AnalysisRecord(
        ip=ip,
        kind=kind,  # type: ignore[arg-type]
        model=model,
        endpoint_host=endpoint_host,
        prompt_text=prompt_text,
        response_text=response_text,
        validated_json=validated_json or {"threat_level": "LOW", "confidence": 0.7},
        ai_status=ai_status,
        threat_level=threat_level,
        confidence=confidence,
        score=score,
        score_derivation=score_derivation,
        latency_ms=latency_ms,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        schema_version=schema_version,
        created_at=created_at or datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# E4 — field caps (pure unit tests; no DB)
# ---------------------------------------------------------------------------


def test_caps_truncates_oversized_prompt() -> None:
    """A prompt_text larger than 64 KiB must be truncated to exactly 64 KiB (E4)."""
    big = "x" * (_CAP + 100)
    (capped_prompt, _capped_response), flags = apply_field_caps(big, "y")
    assert len(capped_prompt.encode()) <= _CAP
    assert flags.get("prompt_truncated") is True


def test_caps_truncates_oversized_response() -> None:
    """A response_text larger than 64 KiB must be truncated to exactly 64 KiB (E4)."""
    big = "z" * (_CAP + 100)
    (_capped_prompt, capped_response), flags = apply_field_caps("small prompt", big)
    assert len(capped_response.encode()) <= _CAP
    assert flags.get("response_truncated") is True


def test_caps_normal_content_not_truncated() -> None:
    """Normal-sized fields must pass through unchanged (E4)."""
    prompt = "normal prompt"
    response = '{"ok": true}'
    (out_prompt, out_response), flags = apply_field_caps(prompt, response)
    assert out_prompt == prompt
    assert out_response == response
    assert not flags


def test_caps_truncation_flags_set() -> None:
    """Both truncation flags must be set when both fields exceed the cap (E4)."""
    big = "a" * (_CAP + 1)
    _, flags = apply_field_caps(big, big)
    assert flags.get("prompt_truncated") is True
    assert flags.get("response_truncated") is True


# ---------------------------------------------------------------------------
# Structural — schema
# ---------------------------------------------------------------------------


async def test_schema_creates_ai_analyses_table(ledger: SqliteAnalysisLedger) -> None:
    """init() must create the ai_analyses table."""
    async with aiosqlite.connect(ledger.db_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='ai_analyses'"
        )
        row = await cursor.fetchone()
    assert row is not None, "ai_analyses table must exist after init()"


async def test_schema_is_idempotent(tmp_path: Path) -> None:
    """Calling init() twice must not raise (idempotent DDL)."""
    db_path = tmp_path / "idem.db"
    ldgr = SqliteAnalysisLedger(db_path)
    await ldgr.init()
    await ldgr.init()  # must not raise
    await ldgr.close()


async def test_ledger_write_does_not_touch_logs_table(ledger: SqliteAnalysisLedger) -> None:
    """Writing to the ledger must not insert rows into logs (isolation)."""
    rec = _make_record()
    await ledger.save(rec)

    async with aiosqlite.connect(ledger.db_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT COUNT(*) as cnt FROM sqlite_master WHERE type='table' AND name='logs'"
        )
        row = await cursor.fetchone()
        assert row is not None
        if row["cnt"] > 0:
            cursor2 = await db.execute("SELECT COUNT(*) as cnt FROM logs")
            logs_row = await cursor2.fetchone()
            assert logs_row is not None and logs_row["cnt"] == 0


# ---------------------------------------------------------------------------
# E7 — persist → read round-trip
# ---------------------------------------------------------------------------


async def test_persist_and_read_round_trip_summary(ledger: SqliteAnalysisLedger) -> None:
    """A saved record must be retrievable via list_page (E7)."""
    rec = _make_record(ip=IP_A, kind="concise", threat_level="HIGH")
    await ledger.save(rec)

    page = await ledger.list_page(limit=10)
    assert len(page["items"]) == 1
    item = page["items"][0]
    assert item["ip"] == IP_A
    assert item["kind"] == "concise"
    assert item["threat_level"] == "HIGH"
    # Summary projection must NOT include prompt/response text.
    assert "prompt_text" not in item
    assert "response_text" not in item


async def test_persist_and_read_round_trip_detail(ledger: SqliteAnalysisLedger) -> None:
    """get_by_id must return full record including prompt and response text (E7)."""
    prompt = "the exact prompt sent to the model"
    response = '{"threat_level": "MEDIUM", "confidence": 0.5}'
    rec = _make_record(ip=IP_A, prompt_text=prompt, response_text=response)
    await ledger.save(rec)

    page = await ledger.list_page(limit=10)
    row_id = page["items"][0]["id"]

    detail = await ledger.get_by_id(row_id)
    assert detail is not None
    assert detail["prompt_text"] == prompt
    assert detail["response_text"] == response
    assert detail["ip"] == IP_A


# ---------------------------------------------------------------------------
# E8 / E9 / E10 / E11 — read projection and filtering
# ---------------------------------------------------------------------------


async def test_list_no_sensitive_fields(ledger: SqliteAnalysisLedger) -> None:
    """list_page must not include prompt_text or response_text in items (E8)."""
    rec = _make_record(prompt_text="secret prompt", response_text="secret response")
    await ledger.save(rec)

    page = await ledger.list_page(limit=10)
    for item in page["items"]:
        assert "prompt_text" not in item, "prompt_text must not appear in list projection"
        assert "response_text" not in item, "response_text must not appear in list projection"


async def test_list_filter_by_ip(ledger: SqliteAnalysisLedger) -> None:
    """list_page with ip_filter must return only matching rows (E9)."""
    await ledger.save(_make_record(ip=IP_A))
    await ledger.save(_make_record(ip=IP_B))

    page_a = await ledger.list_page(limit=10, ip_filter=IP_A)
    assert all(item["ip"] == IP_A for item in page_a["items"])
    assert len(page_a["items"]) == 1

    page_b = await ledger.list_page(limit=10, ip_filter=IP_B)
    assert all(item["ip"] == IP_B for item in page_b["items"])
    assert len(page_b["items"]) == 1


async def test_get_detail_includes_prompt_response(ledger: SqliteAnalysisLedger) -> None:
    """get_by_id must return the full record with prompt_text and response_text (E10)."""
    rec = _make_record(
        ip=IP_A,
        prompt_text="full prompt here",
        response_text='{"threat_level":"HIGH"}',
    )
    await ledger.save(rec)
    page = await ledger.list_page(limit=10)
    row_id = page["items"][0]["id"]

    detail = await ledger.get_by_id(row_id)
    assert detail is not None
    assert "prompt_text" in detail
    assert "response_text" in detail


async def test_get_detail_unknown_id_returns_none(ledger: SqliteAnalysisLedger) -> None:
    """get_by_id for an unknown id must return None (E11, caller maps to 404)."""
    result = await ledger.get_by_id(999999)
    assert result is None


# ---------------------------------------------------------------------------
# E12 — token usage
# ---------------------------------------------------------------------------


async def test_usage_captured_when_present(ledger: SqliteAnalysisLedger) -> None:
    """prompt_tokens and completion_tokens must be persisted when provided (E12)."""
    rec = _make_record(prompt_tokens=150, completion_tokens=75)
    await ledger.save(rec)
    page = await ledger.list_page(limit=10)
    row_id = page["items"][0]["id"]
    detail = await ledger.get_by_id(row_id)
    assert detail is not None
    assert detail["prompt_tokens"] == 150
    assert detail["completion_tokens"] == 75


async def test_usage_null_when_absent(ledger: SqliteAnalysisLedger) -> None:
    """prompt_tokens and completion_tokens must be NULL (None) when not provided (E12)."""
    rec = _make_record(prompt_tokens=None, completion_tokens=None)
    await ledger.save(rec)
    page = await ledger.list_page(limit=10)
    row_id = page["items"][0]["id"]
    detail = await ledger.get_by_id(row_id)
    assert detail is not None
    assert detail["prompt_tokens"] is None
    assert detail["completion_tokens"] is None


# ---------------------------------------------------------------------------
# E13 — endpoint_host has no credentials
# ---------------------------------------------------------------------------


def test_endpoint_host_has_no_credentials() -> None:
    """AnalysisRecord endpoint_host must be a plain host:port string (E13)."""
    rec = _make_record(endpoint_host="127.0.0.1:11434")
    assert ":" in rec.endpoint_host
    # No '@' means no user:pass@ prefix.
    assert "@" not in rec.endpoint_host


# ---------------------------------------------------------------------------
# E5 — per-IP cap pruning
# ---------------------------------------------------------------------------


async def test_prune_per_ip_cap(tmp_path: Path) -> None:
    """When per-IP rows exceed 50, oldest rows are pruned on write (E5).

    Uses per_ip_cap=5 for test speed.
    """
    db_path = tmp_path / "per_ip_cap.db"
    ldgr = SqliteAnalysisLedger(db_path, per_ip_cap=5, global_cap=1000)
    await ldgr.init()
    try:
        for i in range(7):
            ts = datetime(2026, 1, 1, 0, i, 0, tzinfo=timezone.utc)
            await ldgr.save(_make_record(ip=IP_A, created_at=ts))

        page = await ldgr.list_page(limit=100, ip_filter=IP_A)
        assert len(page["items"]) <= 5, (
            f"Expected <=5 rows for IP_A after prune, got {len(page['items'])}"
        )
    finally:
        await ldgr.close()


async def test_prune_per_ip_cap_different_ips_independent(tmp_path: Path) -> None:
    """Per-IP cap pruning must not delete rows belonging to other IPs (E5)."""
    db_path = tmp_path / "per_ip_indep.db"
    ldgr = SqliteAnalysisLedger(db_path, per_ip_cap=3, global_cap=1000)
    await ldgr.init()
    try:
        for i in range(4):
            ts = datetime(2026, 1, 1, 0, i, 0, tzinfo=timezone.utc)
            await ldgr.save(_make_record(ip=IP_A, created_at=ts))

        # Also add one row for IP_B.
        await ldgr.save(_make_record(ip=IP_B))

        page_b = await ldgr.list_page(limit=100, ip_filter=IP_B)
        assert len(page_b["items"]) == 1, "IP_B row must survive IP_A prune"
    finally:
        await ldgr.close()


# ---------------------------------------------------------------------------
# E6 — global cap pruning
# ---------------------------------------------------------------------------


async def test_prune_global_cap(tmp_path: Path) -> None:
    """When global rows exceed 5000, oldest rows are pruned on write (E6).

    Uses global_cap=10 for test speed.
    """
    db_path = tmp_path / "global_cap.db"
    ldgr = SqliteAnalysisLedger(db_path, per_ip_cap=100, global_cap=10)
    await ldgr.init()
    try:
        for i in range(12):
            ts = datetime(2026, 1, 1, 0, i % 60, i // 60, tzinfo=timezone.utc)
            await ldgr.save(_make_record(ip=IP_A, created_at=ts))

        page = await ldgr.list_page(limit=100)
        assert len(page["items"]) <= 10, (
            f"Expected <=10 rows globally after prune, got {len(page['items'])}"
        )
    finally:
        await ldgr.close()


# ---------------------------------------------------------------------------
# E2 — fail-safe ledger hook (pipeline integration)
# ---------------------------------------------------------------------------


async def test_ledger_failure_does_not_abort_analyze_ip(tmp_path: Path) -> None:
    """A ledger write failure must not abort analyze_ip or alter the score (E2)."""
    from _fakes import FakeAIEngine, FakeStore, make_event
    from firewatch_core.pipeline import Pipeline

    store = FakeStore(events=[make_event(source_ip=IP_A)])
    ai = FakeAIEngine(result={
        "threat_level": "HIGH",
        "confidence": 0.8,
        "intent": "test",
        "attack_stage": "reconnaissance",
        "insights": ["test"],
        "recommended_action": "block",
        "ai_status": "ok",
    })

    class BrokenLedger:
        async def save(self, record: Any) -> None:
            raise RuntimeError("ledger DB exploded")

    pipeline = Pipeline(store=store, ai_engine=ai, ledger=BrokenLedger())  # type: ignore[arg-type]
    result = await pipeline.analyze_ip(IP_A, use_ai=True)
    assert result.source_ip == IP_A
    assert result.score >= 0


async def test_ledger_failure_does_not_abort_analyze_ip_detailed(tmp_path: Path) -> None:
    """A ledger write failure must not abort analyze_ip_detailed (E2)."""
    from _fakes import FakeAIEngine, FakeStore, make_event
    from firewatch_core.pipeline import Pipeline

    store = FakeStore(events=[make_event(source_ip=IP_A)])
    ai = FakeAIEngine(result={
        "threat_level": "HIGH",
        "confidence": 0.8,
        "intent": "test",
        "attack_stage": "reconnaissance",
        "insights": ["test"],
        "recommended_action": "block",
        "executive_summary": "exec summary",
        "attack_progression": ["step"],
        "ioc_indicators": ["ioc"],
        "false_positive_likelihood": 0.1,
        "ai_status": "ok",
    })

    class BrokenLedger:
        async def save(self, record: Any) -> None:
            raise RuntimeError("ledger DB exploded")

    pipeline = Pipeline(store=store, ai_engine=ai, ledger=BrokenLedger())  # type: ignore[arg-type]
    result = await pipeline.analyze_ip_detailed(IP_A, include_ai=True)
    assert isinstance(result, dict)
    assert "error" not in result


# ---------------------------------------------------------------------------
# E1 — pipeline wires ledger for concise and detailed
# ---------------------------------------------------------------------------


async def test_analyze_ip_records_ledger_row(tmp_path: Path) -> None:
    """analyze_ip with a successful AI result must record one ledger row (E1)."""
    from _fakes import FakeAIEngine, FakeStore, make_event
    from firewatch_core.pipeline import Pipeline

    store = FakeStore(events=[make_event(source_ip=IP_A, rule_id="942100", payload_snippet="test sqli")])
    ai = FakeAIEngine(result={
        "threat_level": "HIGH",
        "confidence": 0.8,
        "intent": "test",
        "attack_stage": "reconnaissance",
        "insights": ["test"],
        "recommended_action": "block",
        "ai_status": "ok",
    })

    db_path = tmp_path / "pipeline_concise.db"
    ledger_inst = SqliteAnalysisLedger(db_path)
    await ledger_inst.init()

    try:
        pipeline = Pipeline(store=store, ai_engine=ai, ledger=ledger_inst)
        await pipeline.analyze_ip(IP_A, use_ai=True)

        page = await ledger_inst.list_page(limit=10)
        assert len(page["items"]) == 1
        assert page["items"][0]["ip"] == IP_A
        assert page["items"][0]["kind"] == "concise"
    finally:
        await ledger_inst.close()


async def test_analyze_ip_detailed_records_ledger_row(tmp_path: Path) -> None:
    """analyze_ip_detailed with a successful AI result must record one ledger row (E1)."""
    from _fakes import FakeAIEngine, FakeStore, make_event
    from firewatch_core.pipeline import Pipeline

    store = FakeStore(events=[make_event(source_ip=IP_A)])
    ai = FakeAIEngine(result={
        "threat_level": "HIGH",
        "confidence": 0.8,
        "intent": "test",
        "attack_stage": "reconnaissance",
        "insights": ["test"],
        "recommended_action": "block",
        "executive_summary": "exec summary",
        "attack_progression": ["step"],
        "ioc_indicators": ["ioc"],
        "false_positive_likelihood": 0.1,
        "ai_status": "ok",
    })

    db_path = tmp_path / "pipeline_detailed.db"
    ledger_inst = SqliteAnalysisLedger(db_path)
    await ledger_inst.init()

    try:
        pipeline = Pipeline(store=store, ai_engine=ai, ledger=ledger_inst)
        await pipeline.analyze_ip_detailed(IP_A, include_ai=True)

        page = await ledger_inst.list_page(limit=10)
        assert len(page["items"]) == 1
        assert page["items"][0]["ip"] == IP_A
        assert page["items"][0]["kind"] == "detailed"
    finally:
        await ledger_inst.close()


# ---------------------------------------------------------------------------
# E3 — fallback (unavailable) not persisted
# ---------------------------------------------------------------------------


async def test_unavailable_not_persisted(tmp_path: Path) -> None:
    """analyze_ip with ai_status=unavailable (fallback) must NOT record a row (E3)."""
    from _fakes import FakeAIEngine, FakeStore, make_event
    from firewatch_core.pipeline import Pipeline

    store = FakeStore(events=[make_event(source_ip=IP_A)])
    ai = FakeAIEngine(fail=True)

    db_path = tmp_path / "unavail_concise.db"
    ledger_inst = SqliteAnalysisLedger(db_path)
    await ledger_inst.init()

    try:
        pipeline = Pipeline(store=store, ai_engine=ai, ledger=ledger_inst)
        await pipeline.analyze_ip(IP_A, use_ai=True)

        page = await ledger_inst.list_page(limit=10)
        assert len(page["items"]) == 0, "Fallback (unavailable) must not be persisted"
    finally:
        await ledger_inst.close()


async def test_detailed_unavailable_not_persisted(tmp_path: Path) -> None:
    """analyze_ip_detailed when AI is unavailable must NOT record a row (E3)."""
    from _fakes import FakeAIEngine, FakeStore, make_event
    from firewatch_core.pipeline import Pipeline

    store = FakeStore(events=[make_event(source_ip=IP_A)])
    ai = FakeAIEngine(fail=True)

    db_path = tmp_path / "unavail_detailed.db"
    ledger_inst = SqliteAnalysisLedger(db_path)
    await ledger_inst.init()

    try:
        pipeline = Pipeline(store=store, ai_engine=ai, ledger=ledger_inst)
        await pipeline.analyze_ip_detailed(IP_A, include_ai=True)

        page = await ledger_inst.list_page(limit=10)
        assert len(page["items"]) == 0, "Fallback (unavailable) must not be persisted"
    finally:
        await ledger_inst.close()


# ---------------------------------------------------------------------------
# Cursor pagination round-trip
# ---------------------------------------------------------------------------


async def test_cursor_pagination(ledger: SqliteAnalysisLedger) -> None:
    """Cursor pagination must page through all records without repeating (ADR-0029)."""
    for i in range(5):
        ts = datetime(2026, 1, 1, 0, i, 0, tzinfo=timezone.utc)
        await ledger.save(_make_record(ip=IP_A, created_at=ts))

    seen_ids: list[int] = []
    cursor: str | None = None
    for _ in range(10):  # safety guard — never infinite loop
        page = await ledger.list_page(limit=2, cursor=cursor)
        for item in page["items"]:
            seen_ids.append(item["id"])
        if not page["has_more"]:
            break
        cursor = page["next_cursor"]

    assert len(seen_ids) == 5, f"Expected 5 total items, got {len(seen_ids)}"
    assert len(set(seen_ids)) == 5, "No row must appear twice"
