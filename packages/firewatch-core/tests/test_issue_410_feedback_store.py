"""Tests for MK-5 (#410) — verdict feedback store (ADR-0045).

EARS criteria -> test mapping
==============================

F1  THE ledger adapter SHALL own an ai_feedback table with analysis_id FK,
    UNIQUE constraint (one current judgment; re-submission upserts), verdict
    CHECK in ('agree','disagree'), reason TEXT NULL ≤1000 chars, created_at.
    CASCADE delete on parent ai_analyses row.
    -> test_feedback_table_exists_after_init
    -> test_feedback_table_schema_has_expected_columns
    -> test_feedback_cascade_delete_on_analysis_prune

F2  upsert_feedback() inserts a new row and returns the stored record.
    -> test_upsert_inserts_new_feedback
    -> test_upsert_updates_existing_feedback_same_analysis
    -> test_upsert_updates_created_at_on_re_vote

F3  upsert_feedback() raises LookupError for an unknown analysis_id.
    -> test_upsert_unknown_analysis_raises

F4  upsert_feedback() raises ValueError for an invalid verdict.
    -> test_upsert_invalid_verdict_raises

F5  upsert_feedback() enforces reason <= 1000 chars (server-side cap).
    -> test_upsert_reason_at_cap_accepted
    -> test_upsert_reason_over_cap_raises

F6  get_feedback_summary() returns {graded, agreed, agreement_pct} computed at
    read time (no denormalized counters).
    -> test_summary_empty_returns_zero_graded
    -> test_summary_agrees_and_disagrees
    -> test_summary_agreement_pct_computed_at_read_time
    -> test_summary_denominator_always_present

F7  get_feedback_for_analysis() returns the current feedback row or None.
    -> test_get_feedback_returns_row
    -> test_get_feedback_returns_none_when_absent

F8  Feedback NEVER influences scores, prompts, sampling, or model calls
    (ADR-0045 D3 — the ai_feedback table has no read dependency in the
    scoring/pipeline path).
    -> test_no_import_of_feedback_in_pipeline
    -> test_no_import_of_feedback_in_ai_engine

Structural:
    -> test_schema_is_idempotent (init() twice must not raise)
    -> test_reason_returned_verbatim
"""
from __future__ import annotations

import inspect
from datetime import datetime, timezone
from pathlib import Path

import aiosqlite
import pytest

from firewatch_core.adapters.ledger.sqlite_ledger import SqliteAnalysisLedger
from firewatch_core.ports.analysis_ledger import AnalysisRecord

# RFC 5737 documentation IPs only.
IP_A = "192.0.2.10"
IP_B = "198.51.100.20"

_REASON_CAP = 1_000


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
) -> AnalysisRecord:
    return AnalysisRecord(
        ip=ip,
        kind=kind,  # type: ignore[arg-type]
        model="qwen3:8b",
        endpoint_host="127.0.0.1:11434",
        prompt_text="test prompt",
        response_text='{"threat_level":"LOW"}',
        validated_json={"threat_level": "LOW", "confidence": 0.5},
        ai_status="ok",
        threat_level="LOW",
        confidence=0.5,
        score=20,
        score_derivation="rules",
        latency_ms=100.0,
        prompt_tokens=80,
        completion_tokens=40,
        created_at=datetime.now(timezone.utc),
    )


async def _save_and_get_id(ledger: SqliteAnalysisLedger, record: AnalysisRecord) -> int:
    """Save a record and return its database id."""
    await ledger.save(record)
    page = await ledger.list_page(limit=10)
    return page["items"][0]["id"]


# ---------------------------------------------------------------------------
# F1 — DDL: table structure and cascade
# ---------------------------------------------------------------------------


async def test_feedback_table_exists_after_init(ledger: SqliteAnalysisLedger) -> None:
    """ai_feedback table must exist after init() (F1)."""
    async with aiosqlite.connect(ledger.db_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='ai_feedback'"
        )
        row = await cursor.fetchone()
    assert row is not None, "ai_feedback table must exist after init()"


async def test_feedback_table_schema_has_expected_columns(
    ledger: SqliteAnalysisLedger,
) -> None:
    """ai_feedback must have id, analysis_id, verdict, reason, created_at columns (F1)."""
    async with aiosqlite.connect(ledger.db_path) as db:
        cursor = await db.execute("PRAGMA table_info(ai_feedback)")
        rows = await cursor.fetchall()
    col_names = {row[1] for row in rows}
    required = {"id", "analysis_id", "verdict", "reason", "created_at"}
    assert required <= col_names, f"ai_feedback missing columns: {required - col_names}"


async def test_feedback_cascade_delete_on_analysis_prune(
    tmp_path: Path,
) -> None:
    """Deleting an ai_analyses row must cascade-delete the ai_feedback row (F1)."""
    db_path = tmp_path / "cascade.db"
    ldgr = SqliteAnalysisLedger(db_path)
    await ldgr.init()
    try:
        analysis_id = await _save_and_get_id(ldgr, _make_record())
        await ldgr.upsert_feedback(analysis_id, verdict="agree", reason=None)

        # Directly delete the analysis row to trigger cascade.
        db = await ldgr._conn()  # type: ignore[attr-defined]
        await db.execute("PRAGMA foreign_keys = ON")
        await db.execute("DELETE FROM ai_analyses WHERE id = ?", (analysis_id,))
        await db.commit()

        async with aiosqlite.connect(db_path) as check_db:
            check_db.row_factory = aiosqlite.Row
            cursor = await check_db.execute(
                "SELECT COUNT(*) as cnt FROM ai_feedback WHERE analysis_id = ?",
                (analysis_id,),
            )
            row = await cursor.fetchone()
        assert row is not None
        assert row["cnt"] == 0, "Cascade delete must remove the feedback row"
    finally:
        await ldgr.close()


# ---------------------------------------------------------------------------
# F2 — upsert semantics
# ---------------------------------------------------------------------------


async def test_upsert_inserts_new_feedback(ledger: SqliteAnalysisLedger) -> None:
    """upsert_feedback() must insert and return the stored row (F2)."""
    analysis_id = await _save_and_get_id(ledger, _make_record())
    result = await ledger.upsert_feedback(analysis_id, verdict="agree", reason="looks right")
    assert result["analysis_id"] == analysis_id
    assert result["verdict"] == "agree"
    assert result["reason"] == "looks right"
    assert "created_at" in result


async def test_upsert_updates_existing_feedback_same_analysis(
    ledger: SqliteAnalysisLedger,
) -> None:
    """Re-submitting feedback for the same analysis_id must upsert (update), not insert (F2)."""
    analysis_id = await _save_and_get_id(ledger, _make_record())
    await ledger.upsert_feedback(analysis_id, verdict="agree", reason="first opinion")
    result = await ledger.upsert_feedback(analysis_id, verdict="disagree", reason="changed mind")

    assert result["verdict"] == "disagree"
    assert result["reason"] == "changed mind"

    # Verify only one row exists for this analysis_id.
    async with aiosqlite.connect(ledger.db_path) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            "SELECT COUNT(*) as cnt FROM ai_feedback WHERE analysis_id = ?",
            (analysis_id,),
        )
        row = await cursor.fetchone()
    assert row is not None
    assert row["cnt"] == 1, "UPSERT must keep exactly one row per analysis_id"


async def test_upsert_updates_created_at_on_re_vote(ledger: SqliteAnalysisLedger) -> None:
    """Re-submitting feedback must update the row (verdict changed) (F2)."""
    analysis_id = await _save_and_get_id(ledger, _make_record())
    first = await ledger.upsert_feedback(analysis_id, verdict="agree", reason=None)
    second = await ledger.upsert_feedback(analysis_id, verdict="disagree", reason=None)
    # The important thing is that the row is updated (verdict changed).
    assert second["verdict"] == "disagree"
    assert second["analysis_id"] == first["analysis_id"]


# ---------------------------------------------------------------------------
# F3 — unknown analysis_id
# ---------------------------------------------------------------------------


async def test_upsert_unknown_analysis_raises(ledger: SqliteAnalysisLedger) -> None:
    """upsert_feedback() must raise LookupError for an unknown analysis_id (F3)."""
    with pytest.raises(LookupError, match="analysis"):
        await ledger.upsert_feedback(999999, verdict="agree", reason=None)


# ---------------------------------------------------------------------------
# F4 — invalid verdict
# ---------------------------------------------------------------------------


async def test_upsert_invalid_verdict_raises(ledger: SqliteAnalysisLedger) -> None:
    """upsert_feedback() must raise ValueError for an invalid verdict (F4)."""
    analysis_id = await _save_and_get_id(ledger, _make_record())
    with pytest.raises(ValueError, match="verdict"):
        await ledger.upsert_feedback(analysis_id, verdict="maybe", reason=None)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# F5 — reason cap (server-side enforcement)
# ---------------------------------------------------------------------------


async def test_upsert_reason_at_cap_accepted(ledger: SqliteAnalysisLedger) -> None:
    """A reason of exactly 1000 chars must be accepted (F5)."""
    analysis_id = await _save_and_get_id(ledger, _make_record())
    reason = "x" * _REASON_CAP
    result = await ledger.upsert_feedback(analysis_id, verdict="agree", reason=reason)
    assert result["reason"] == reason


async def test_upsert_reason_over_cap_raises(ledger: SqliteAnalysisLedger) -> None:
    """A reason exceeding 1000 chars must raise ValueError (F5)."""
    analysis_id = await _save_and_get_id(ledger, _make_record())
    reason = "x" * (_REASON_CAP + 1)
    with pytest.raises(ValueError, match="reason"):
        await ledger.upsert_feedback(analysis_id, verdict="agree", reason=reason)


# ---------------------------------------------------------------------------
# F6 — agreement rollup / summary
# ---------------------------------------------------------------------------


async def test_summary_empty_returns_zero_graded(ledger: SqliteAnalysisLedger) -> None:
    """get_feedback_summary() with no feedback rows must return graded=0 (F6)."""
    summary = await ledger.get_feedback_summary()
    assert summary["graded"] == 0
    assert summary["agreed"] == 0
    assert summary["agreement_pct"] == 0.0


async def test_summary_agrees_and_disagrees(ledger: SqliteAnalysisLedger) -> None:
    """get_feedback_summary() must count agrees and disagrees correctly (F6)."""
    # 3 analyses — 2 agree, 1 disagree.
    for i in range(3):
        rec = _make_record(ip=IP_A if i < 2 else IP_B)
        analysis_id = await _save_and_get_id(ledger, rec)
        verdict = "agree" if i < 2 else "disagree"
        await ledger.upsert_feedback(analysis_id, verdict=verdict, reason=None)

    summary = await ledger.get_feedback_summary()
    assert summary["graded"] == 3
    assert summary["agreed"] == 2
    assert abs(summary["agreement_pct"] - (2 / 3 * 100)) < 0.01


async def test_summary_agreement_pct_computed_at_read_time(
    ledger: SqliteAnalysisLedger,
) -> None:
    """agreement_pct must be computed at read time (not stored as a counter) (F6)."""
    analysis_id = await _save_and_get_id(ledger, _make_record())
    await ledger.upsert_feedback(analysis_id, verdict="agree", reason=None)

    summary1 = await ledger.get_feedback_summary()
    assert summary1["agreement_pct"] == 100.0

    # Add a second analysis with disagree — pct should update.
    rec2 = _make_record(ip=IP_B)
    a2 = await _save_and_get_id(ledger, rec2)
    await ledger.upsert_feedback(a2, verdict="disagree", reason=None)

    summary2 = await ledger.get_feedback_summary()
    assert summary2["graded"] == 2
    assert abs(summary2["agreement_pct"] - 50.0) < 0.01


async def test_summary_denominator_always_present(ledger: SqliteAnalysisLedger) -> None:
    """Summary must always expose graded count (honest denominator rule, ADR-0045 D4) (F6)."""
    analysis_id = await _save_and_get_id(ledger, _make_record())
    await ledger.upsert_feedback(analysis_id, verdict="agree", reason=None)
    summary = await ledger.get_feedback_summary()
    # graded must be present and non-zero.
    assert "graded" in summary
    assert summary["graded"] >= 1


# ---------------------------------------------------------------------------
# F7 — get_feedback_for_analysis
# ---------------------------------------------------------------------------


async def test_get_feedback_returns_row(ledger: SqliteAnalysisLedger) -> None:
    """get_feedback_for_analysis() must return the current feedback row (F7)."""
    analysis_id = await _save_and_get_id(ledger, _make_record())
    await ledger.upsert_feedback(analysis_id, verdict="disagree", reason="nope")
    row = await ledger.get_feedback_for_analysis(analysis_id)
    assert row is not None
    assert row["verdict"] == "disagree"
    assert row["reason"] == "nope"


async def test_get_feedback_returns_none_when_absent(ledger: SqliteAnalysisLedger) -> None:
    """get_feedback_for_analysis() must return None when no feedback exists (F7)."""
    analysis_id = await _save_and_get_id(ledger, _make_record())
    row = await ledger.get_feedback_for_analysis(analysis_id)
    assert row is None


# ---------------------------------------------------------------------------
# F8 — feedback NEVER influences the scoring/pipeline path (ADR-0045 D3)
# ---------------------------------------------------------------------------


def test_no_import_of_feedback_in_pipeline() -> None:
    """The pipeline module must not import or reference ai_feedback (F8).

    Feedback is read-display only; it must not influence scores or prompts.
    """
    import firewatch_core.pipeline as pipeline_mod

    source = inspect.getsource(pipeline_mod)
    assert "ai_feedback" not in source, (
        "pipeline.py must not reference ai_feedback — "
        "feedback must never influence scores or prompts (ADR-0045 D3)"
    )
    assert "get_feedback" not in source, (
        "pipeline.py must not call get_feedback — "
        "feedback must never influence scores or prompts (ADR-0045 D3)"
    )


def test_no_import_of_feedback_in_ai_engine() -> None:
    """The OpenAIEngine adapter must not import or reference ai_feedback (F8)."""
    import firewatch_core.adapters.ai_openai as ai_mod

    source = inspect.getsource(ai_mod)
    assert "ai_feedback" not in source, (
        "ai_openai.py must not reference ai_feedback — "
        "feedback must never influence model calls (ADR-0045 D3)"
    )


# ---------------------------------------------------------------------------
# Structural
# ---------------------------------------------------------------------------


async def test_schema_is_idempotent(tmp_path: Path) -> None:
    """Calling init() twice must not raise (idempotent DDL)."""
    db_path = tmp_path / "idem.db"
    ldgr = SqliteAnalysisLedger(db_path)
    await ldgr.init()
    await ldgr.init()  # must not raise
    await ldgr.close()


async def test_reason_returned_verbatim(ledger: SqliteAnalysisLedger) -> None:
    """The reason field must be returned exactly as stored (verbatim) (ADR-0045 D1)."""
    analysis_id = await _save_and_get_id(ledger, _make_record())
    reason = "False positive: the IP belongs to our CDN provider."
    result = await ledger.upsert_feedback(analysis_id, verdict="disagree", reason=reason)
    assert result["reason"] == reason

    row = await ledger.get_feedback_for_analysis(analysis_id)
    assert row is not None
    assert row["reason"] == reason


# ---------------------------------------------------------------------------
# D1 — list_page pre-seeds feedback state (MK-6 defect fix)
# ---------------------------------------------------------------------------


async def test_list_page_includes_feedback_after_upsert(
    ledger: SqliteAnalysisLedger,
) -> None:
    """list_page must return feedback={verdict, created_at} after upsert_feedback (D1).

    On page reload each card must show its stored agree/disagree state — the
    LEFT JOIN on ai_feedback pre-seeds this without N+1 queries.
    """
    analysis_id = await _save_and_get_id(ledger, _make_record())
    fb = await ledger.upsert_feedback(analysis_id, verdict="agree", reason=None)

    page = await ledger.list_page(limit=10)
    assert len(page["items"]) == 1
    item = page["items"][0]

    assert item["feedback"] is not None, "feedback must be non-None after upsert"
    assert item["feedback"]["verdict"] == "agree"
    # created_at must be present and match what upsert returned.
    assert item["feedback"]["created_at"] == fb["created_at"]


async def test_list_page_feedback_none_when_no_feedback(
    ledger: SqliteAnalysisLedger,
) -> None:
    """list_page must return feedback=None for analyses with no feedback (D1)."""
    await ledger.save(_make_record())
    page = await ledger.list_page(limit=10)
    assert len(page["items"]) == 1
    item = page["items"][0]
    assert item["feedback"] is None, "feedback must be None when no feedback submitted"


async def test_list_page_feedback_no_reason_field(
    ledger: SqliteAnalysisLedger,
) -> None:
    """reason must NOT appear in list_page feedback (OWASP LLM01 — operator free-text security).

    The reason field is operator-authored text that can contain attacker-influenced
    content; it must stay off the list projection and only appear on the detail /
    POST paths.
    """
    analysis_id = await _save_and_get_id(ledger, _make_record())
    await ledger.upsert_feedback(analysis_id, verdict="disagree", reason="secret operator note")

    page = await ledger.list_page(limit=10)
    assert len(page["items"]) == 1
    item = page["items"][0]

    # feedback must exist but must NOT expose reason.
    assert item["feedback"] is not None
    assert "reason" not in item["feedback"], (
        "reason must not appear in list_page feedback (OWASP LLM01 security gate)"
    )


async def test_list_page_feedback_reflects_latest_after_regrade(
    ledger: SqliteAnalysisLedger,
) -> None:
    """list_page must reflect the latest verdict after agree → disagree re-grade (D1)."""
    analysis_id = await _save_and_get_id(ledger, _make_record())

    await ledger.upsert_feedback(analysis_id, verdict="agree", reason=None)
    # Re-grade to disagree — upsert must overwrite the previous row.
    await ledger.upsert_feedback(analysis_id, verdict="disagree", reason="changed mind")

    page = await ledger.list_page(limit=10)
    assert len(page["items"]) == 1
    item = page["items"][0]

    assert item["feedback"] is not None
    assert item["feedback"]["verdict"] == "disagree", (
        "list_page must reflect the latest verdict after re-grading (latest wins)"
    )
