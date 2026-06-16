"""Tests for issue #534 — cases store (ADR-0053 D4).

EARS → test mapping
───────────────────
EARS-2  Timeline assembles related events + verdicts at read time (references, not copies).
    → test_timeline_contains_linked_events
    → test_timeline_contains_linked_analyses

EARS-3  Add markdown notes; each note persists author + created_at.
    → test_add_note_persists_author_and_body
    → test_list_notes_returns_all_notes

EARS-4  case_notes.author defaults to 'local operator'; accepts real identity with
        zero schema change (auth-aware seam ADR-0053 D3).
    → test_note_author_defaults_to_local_operator
    → test_note_author_can_be_overridden

EARS-5  Analyst sets disposition (true-positive / false-positive / benign / open).
    → test_set_disposition_persists
    → test_set_disposition_invalid_raises

EARS-6  Case data stored on-box in SQLite (structural — all ops use local DB).
    → test_create_case_returns_id
    → test_get_case_returns_case
    → test_list_cases_cursor_pagination

EARS-7  Cases store shares single loop-bound aiosqlite connection (ADR-0023 §F).
    → test_init_is_idempotent  (apply_schema runs twice; no error)

Caps:
    → test_note_body_over_cap_raises
    → test_notes_per_case_over_cap_raises

All IPs in this file are RFC 5737 documentation IPs (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) or RFC1918/loopback — never real public IPs.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import aiosqlite
import pytest

from firewatch_core.adapters.cases.caps import (
    MAX_NOTE_BODY_CHARS,
    MAX_NOTES_PER_CASE,
)
from firewatch_core.adapters.cases.schema import apply_schema
from firewatch_core.adapters.cases.sqlite_cases import SqliteCaseStore

# RFC 5737 documentation IPs only.
_IP_A = "192.0.2.10"
_IP_B = "198.51.100.20"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "cases_test.db"


@pytest.fixture()
def store(db_path: Path) -> SqliteCaseStore:
    return SqliteCaseStore(db_path=db_path)


# ---------------------------------------------------------------------------
# Schema / lifecycle
# ---------------------------------------------------------------------------


def test_init_is_idempotent(store: SqliteCaseStore, db_path: Path) -> None:
    """apply_schema runs twice without error (CREATE TABLE IF NOT EXISTS)."""

    async def _run() -> None:
        await store.init()
        await store.init()  # second init must not raise
        await store.close()

    asyncio.run(_run())


def test_schema_creates_tables(db_path: Path) -> None:
    """apply_schema creates all three tables."""

    async def _run() -> None:
        async with aiosqlite.connect(db_path) as db:
            await apply_schema(db)
            await db.commit()
            cursor = await db.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
            tables = {row[0] for row in await cursor.fetchall()}
        assert "case_files" in tables
        assert "case_notes" in tables
        assert "case_events" in tables

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# EARS-6 — create/get/list
# ---------------------------------------------------------------------------


def test_create_case_returns_id(store: SqliteCaseStore) -> None:
    """create_case returns a positive integer ID."""

    async def _run() -> int:
        await store.init()
        case_id = await store.create_case(title="Test case", subject=_IP_A)
        await store.close()
        return case_id

    case_id = asyncio.run(_run())
    assert isinstance(case_id, int)
    assert case_id > 0


def test_get_case_returns_case(store: SqliteCaseStore) -> None:
    """get_case returns the created case with correct fields."""

    async def _run() -> dict:  # type: ignore[type-arg]
        await store.init()
        case_id = await store.create_case(title="Investigation", subject=_IP_A)
        case = await store.get_case(case_id)
        await store.close()
        return case  # type: ignore[return-value]

    case = asyncio.run(_run())
    assert case is not None
    assert case["title"] == "Investigation"
    assert case["subject"] == _IP_A
    assert case["disposition"] == "open"
    assert case["status"] == "open"
    assert "created_at" in case
    assert "updated_at" in case


def test_get_case_unknown_returns_none(store: SqliteCaseStore) -> None:
    """get_case returns None for an unknown ID."""

    async def _run() -> None:
        await store.init()
        result = await store.get_case(99999)
        await store.close()
        assert result is None

    asyncio.run(_run())


def test_list_cases_cursor_pagination(store: SqliteCaseStore) -> None:
    """list_cases returns cursor-paginated results (ADR-0029 envelope)."""

    async def _run() -> dict:  # type: ignore[type-arg]
        await store.init()
        for i in range(5):
            await store.create_case(title=f"Case {i}", subject=_IP_A)
        page = await store.list_cases(limit=3)
        await store.close()
        return page  # type: ignore[return-value]

    page = asyncio.run(_run())
    assert "items" in page
    assert "next_cursor" in page
    assert "has_more" in page
    assert len(page["items"]) == 3
    assert page["has_more"] is True
    assert page["next_cursor"] is not None


def test_list_cases_second_page(store: SqliteCaseStore) -> None:
    """list_cases with next_cursor returns the next page."""

    async def _run() -> tuple[dict, dict]:  # type: ignore[type-arg]
        await store.init()
        for i in range(4):
            await store.create_case(title=f"Case {i}", subject=_IP_B)
        page1 = await store.list_cases(limit=2)
        page2 = await store.list_cases(limit=2, cursor=page1["next_cursor"])
        await store.close()
        return page1, page2  # type: ignore[return-value]

    page1, page2 = asyncio.run(_run())
    ids1 = {item["id"] for item in page1["items"]}
    ids2 = {item["id"] for item in page2["items"]}
    assert ids1.isdisjoint(ids2), "pages must not overlap"


# ---------------------------------------------------------------------------
# EARS-3 / EARS-4 — notes
# ---------------------------------------------------------------------------


def test_add_note_persists_author_and_body(store: SqliteCaseStore) -> None:
    """add_note persists author, body_md, and created_at."""

    async def _run() -> dict:  # type: ignore[type-arg]
        await store.init()
        case_id = await store.create_case(title="N-test", subject=_IP_A)
        note_id = await store.add_note(
            case_id=case_id, body_md="## Finding\nSuspicious beacon.", author="alice"
        )
        notes = await store.list_notes(case_id)
        await store.close()
        return {"note_id": note_id, "notes": notes}

    result = asyncio.run(_run())
    assert result["note_id"] > 0
    notes = result["notes"]
    assert len(notes) == 1
    assert notes[0]["author"] == "alice"
    assert "## Finding" in notes[0]["body_md"]
    assert "created_at" in notes[0]


def test_note_author_defaults_to_local_operator(store: SqliteCaseStore) -> None:
    """When author is not supplied, it defaults to 'local operator' (EARS-4)."""

    async def _run() -> str:
        await store.init()
        case_id = await store.create_case(title="Auth seam", subject=_IP_A)
        await store.add_note(case_id=case_id, body_md="Note without explicit author.")
        notes = await store.list_notes(case_id)
        await store.close()
        return notes[0]["author"]

    author = asyncio.run(_run())
    assert author == "local operator"


def test_note_author_can_be_overridden(store: SqliteCaseStore) -> None:
    """Author can be set explicitly — the seam for post-ADR-0026 real identity (EARS-4)."""

    async def _run() -> str:
        await store.init()
        case_id = await store.create_case(title="Auth override", subject=_IP_A)
        await store.add_note(case_id=case_id, body_md="Identity-aware note.", author="bob@example.com")
        notes = await store.list_notes(case_id)
        await store.close()
        return notes[0]["author"]

    author = asyncio.run(_run())
    assert author == "bob@example.com"


def test_list_notes_returns_all_notes(store: SqliteCaseStore) -> None:
    """list_notes returns all notes for a case in chronological order."""

    async def _run() -> list:  # type: ignore[type-arg]
        await store.init()
        case_id = await store.create_case(title="Multi-note", subject=_IP_A)
        await store.add_note(case_id=case_id, body_md="First.")
        await store.add_note(case_id=case_id, body_md="Second.")
        await store.add_note(case_id=case_id, body_md="Third.")
        notes = await store.list_notes(case_id)
        await store.close()
        return notes  # type: ignore[return-value]

    notes = asyncio.run(_run())
    assert len(notes) == 3
    bodies = [n["body_md"] for n in notes]
    assert bodies[0] == "First."
    assert bodies[2] == "Third."


# ---------------------------------------------------------------------------
# EARS-5 — disposition
# ---------------------------------------------------------------------------


def test_set_disposition_persists(store: SqliteCaseStore) -> None:
    """set_disposition writes true-positive/false-positive/benign (EARS-5)."""

    async def _run() -> str:
        await store.init()
        case_id = await store.create_case(title="Disposition test", subject=_IP_B)
        await store.set_disposition(case_id=case_id, disposition="true-positive")
        case = await store.get_case(case_id)
        await store.close()
        return case["disposition"]  # type: ignore[index]

    disposition = asyncio.run(_run())
    assert disposition == "true-positive"


def test_set_disposition_all_valid_values(store: SqliteCaseStore) -> None:
    """All valid disposition values are accepted."""
    valid = ["true-positive", "false-positive", "benign", "open"]

    async def _run() -> None:
        await store.init()
        for val in valid:
            case_id = await store.create_case(title=f"disp-{val}", subject=_IP_A)
            await store.set_disposition(case_id=case_id, disposition=val)
            case = await store.get_case(case_id)
            assert case is not None
            assert case["disposition"] == val
        await store.close()

    asyncio.run(_run())


def test_set_disposition_invalid_raises(store: SqliteCaseStore) -> None:
    """set_disposition raises ValueError for unknown disposition values."""

    async def _run() -> None:
        await store.init()
        case_id = await store.create_case(title="Invalid disp", subject=_IP_A)
        with pytest.raises(ValueError, match="Invalid disposition"):
            await store.set_disposition(case_id=case_id, disposition="maybe")
        await store.close()

    asyncio.run(_run())


# ---------------------------------------------------------------------------
# EARS-2 — timeline (case_events references)
# ---------------------------------------------------------------------------


def test_timeline_contains_linked_events(store: SqliteCaseStore) -> None:
    """timeline_for_case returns case_events referencing security event IDs (EARS-2)."""

    async def _run() -> dict:  # type: ignore[type-arg]
        await store.init()
        case_id = await store.create_case(title="Timeline test", subject=_IP_A)
        await store.link_event(case_id=case_id, ref_kind="security_event", ref_id="evt-001")
        await store.link_event(case_id=case_id, ref_kind="security_event", ref_id="evt-002")
        timeline = await store.get_timeline(case_id)
        await store.close()
        return timeline  # type: ignore[return-value]

    timeline = asyncio.run(_run())
    assert "events" in timeline
    ref_ids = {e["ref_id"] for e in timeline["events"]}
    assert "evt-001" in ref_ids
    assert "evt-002" in ref_ids
    # Each entry has ref_kind and created_at.
    for ev in timeline["events"]:
        assert "ref_kind" in ev
        assert "ref_id" in ev
        assert "created_at" in ev


def test_timeline_contains_linked_analyses(store: SqliteCaseStore) -> None:
    """timeline_for_case includes ai_analysis references (ADR-0044 verdict ledger, EARS-2)."""

    async def _run() -> dict:  # type: ignore[type-arg]
        await store.init()
        case_id = await store.create_case(title="Analysis link", subject=_IP_A)
        await store.link_event(case_id=case_id, ref_kind="ai_analysis", ref_id="42")
        timeline = await store.get_timeline(case_id)
        await store.close()
        return timeline  # type: ignore[return-value]

    timeline = asyncio.run(_run())
    ref_kinds = {e["ref_kind"] for e in timeline["events"]}
    assert "ai_analysis" in ref_kinds


def test_timeline_events_not_denormalized(db_path: Path) -> None:
    """case_events stores references only — no denormalized copies (ADR-0041, EARS-2)."""

    async def _run() -> list:  # type: ignore[type-arg]
        async with aiosqlite.connect(db_path) as db:
            await apply_schema(db)
            await db.commit()
            cursor = await db.execute("PRAGMA table_info(case_events)")
            cols = [row[1] for row in await cursor.fetchall()]
        return cols  # type: ignore[return-value]

    cols = asyncio.run(_run())
    # Must have reference columns, must NOT have event payload columns.
    assert "ref_kind" in cols
    assert "ref_id" in cols
    # These would indicate denormalized copies — must be absent.
    assert "source_ip" not in cols
    assert "prompt_text" not in cols
    assert "body" not in cols


# ---------------------------------------------------------------------------
# Caps
# ---------------------------------------------------------------------------


def test_note_body_over_cap_raises(store: SqliteCaseStore) -> None:
    """add_note raises ValueError when body_md exceeds MAX_NOTE_BODY_CHARS."""

    async def _run() -> None:
        await store.init()
        case_id = await store.create_case(title="Cap test", subject=_IP_A)
        oversized = "x" * (MAX_NOTE_BODY_CHARS + 1)
        with pytest.raises(ValueError, match="body_md exceeds"):
            await store.add_note(case_id=case_id, body_md=oversized)
        await store.close()

    asyncio.run(_run())


def test_notes_per_case_over_cap_raises(store: SqliteCaseStore) -> None:
    """add_note raises ValueError when notes-per-case would exceed MAX_NOTES_PER_CASE."""

    async def _run() -> None:
        await store.init()
        case_id = await store.create_case(title="Count cap", subject=_IP_A)
        for i in range(MAX_NOTES_PER_CASE):
            await store.add_note(case_id=case_id, body_md=f"Note {i}.")
        with pytest.raises(ValueError, match="notes per case"):
            await store.add_note(case_id=case_id, body_md="One too many.")
        await store.close()

    asyncio.run(_run())
