"""Tests for the ``triage_decisions`` store — ``SqliteDecisionStore`` (ADR-0072 D2).

EARS → test mapping
───────────────────
D2  create_decision persists a row; the response carries the full record
    including the server-computed snapshot (decided_tier/decided_score).
    → test_create_decision_returns_full_record

D2  verb/rule_name CHECK: false_positive REQUIRES rule_name; other verbs
    FORBID it. Violations raise ValueError (never an sqlite IntegrityError
    surfaced to a caller).
    → TestVerbRuleNamePairing

D2  Append-only: revoke_decision soft-revokes (sets revoked_at); the row is
    never deleted. Idempotent on a second call. LookupError on unknown id.
    → TestRevoke

D2  list_decisions returns the ADR-0029 D2 cursor envelope, newest-first,
    full history (active + revoked); actor filter scopes to one actor.
    → TestListDecisions

D2  get_active_for_actor returns ONLY non-revoked rows for one actor.
    → TestGetActiveForActor

Schema  apply_schema is idempotent; the CHECK constraint is enforced at the
        DB layer as defense-in-depth (a direct INSERT bypassing Python
        validation still fails).
    → TestSchema

Caps  Field-length caps reject oversized actor_ip/rule_name/note.
    → TestCaps

All IPs are RFC 5737 documentation IPs (192.0.2.0/24, 198.51.100.0/24).
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import aiosqlite
import pytest

from firewatch_core.adapters.decisions.caps import MAX_ACTOR_IP_CHARS, MAX_NOTE_CHARS
from firewatch_core.adapters.decisions.schema import apply_schema
from firewatch_core.adapters.decisions.sqlite_decisions import SqliteDecisionStore

_IP_A = "192.0.2.50"
_IP_B = "198.51.100.60"


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "decisions_test.db"


@pytest.fixture()
def store(db_path: Path) -> SqliteDecisionStore:
    return SqliteDecisionStore(db_path=db_path)


# ---------------------------------------------------------------------------
# Schema / lifecycle
# ---------------------------------------------------------------------------


class TestSchema:
    def test_init_is_idempotent(self, store: SqliteDecisionStore) -> None:
        async def _run() -> None:
            await store.init()
            await store.init()  # second init must not raise
            await store.close()

        asyncio.run(_run())

    def test_schema_creates_table(self, db_path: Path) -> None:
        async def _run() -> set[str]:
            async with aiosqlite.connect(db_path) as db:
                await apply_schema(db)
                await db.commit()
                cursor = await db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
                return {row[0] for row in await cursor.fetchall()}

        tables = asyncio.run(_run())
        assert "triage_decisions" in tables

    def test_db_check_constraint_rejects_direct_insert_violation(self, db_path: Path) -> None:
        """Defense-in-depth: the DB CHECK fires even bypassing Python validation."""

        async def _run() -> None:
            async with aiosqlite.connect(db_path) as db:
                await apply_schema(db)
                await db.commit()
                with pytest.raises(aiosqlite.IntegrityError):
                    await db.execute(
                        "INSERT INTO triage_decisions "
                        "(actor_ip, verb, rule_name, decided_score, decided_at) "
                        "VALUES (?, 'false_positive', NULL, 10, '2026-01-01T00:00:00+00:00')",
                        (_IP_A,),
                    )

        asyncio.run(_run())


# ---------------------------------------------------------------------------
# D2 — create_decision
# ---------------------------------------------------------------------------


class TestCreateDecision:
    def test_create_decision_returns_full_record(self, store: SqliteDecisionStore) -> None:
        async def _run() -> dict:  # type: ignore[type-arg]
            await store.init()
            record = await store.create_decision(
                actor_ip=_IP_A,
                verb="expected",
                rule_name=None,
                decided_tier=2,
                decided_score=45,
            )
            await store.close()
            return record

        record = asyncio.run(_run())
        assert record["id"] > 0
        assert record["actor_ip"] == _IP_A
        assert record["verb"] == "expected"
        assert record["decided_tier"] == 2
        assert record["decided_score"] == 45
        assert record["revoked_at"] is None
        assert record["author"] == "local operator"

    def test_create_decision_persists_custom_author_and_note(
        self, store: SqliteDecisionStore
    ) -> None:
        async def _run() -> dict:  # type: ignore[type-arg]
            await store.init()
            record = await store.create_decision(
                actor_ip=_IP_A,
                verb="dismissed",
                rule_name=None,
                decided_tier=None,
                decided_score=0,
                author="analyst@example",
                note="known scanner",
            )
            await store.close()
            return record

        record = asyncio.run(_run())
        assert record["author"] == "analyst@example"
        assert record["note"] == "known scanner"


class TestVerbRuleNamePairing:
    def test_false_positive_without_rule_name_raises(self, store: SqliteDecisionStore) -> None:
        async def _run() -> None:
            await store.init()
            with pytest.raises(ValueError):
                await store.create_decision(
                    actor_ip=_IP_A,
                    verb="false_positive",
                    rule_name=None,
                    decided_tier=2,
                    decided_score=10,
                )
            await store.close()

        asyncio.run(_run())

    def test_expected_with_rule_name_raises(self, store: SqliteDecisionStore) -> None:
        async def _run() -> None:
            await store.init()
            with pytest.raises(ValueError):
                await store.create_decision(
                    actor_ip=_IP_A,
                    verb="expected",
                    rule_name="waf_sqli",
                    decided_tier=2,
                    decided_score=10,
                )
            await store.close()

        asyncio.run(_run())

    def test_false_positive_with_rule_name_succeeds(self, store: SqliteDecisionStore) -> None:
        async def _run() -> dict:  # type: ignore[type-arg]
            await store.init()
            record = await store.create_decision(
                actor_ip=_IP_A,
                verb="false_positive",
                rule_name="waf_sqli",
                decided_tier=2,
                decided_score=10,
            )
            await store.close()
            return record

        record = asyncio.run(_run())
        assert record["rule_name"] == "waf_sqli"

    def test_invalid_verb_raises(self, store: SqliteDecisionStore) -> None:
        async def _run() -> None:
            await store.init()
            with pytest.raises(ValueError):
                await store.create_decision(
                    actor_ip=_IP_A,
                    verb="acknowledge",  # retired verb (ADR-0072 D6)
                    rule_name=None,
                    decided_tier=2,
                    decided_score=10,
                )
            await store.close()

        asyncio.run(_run())


class TestCaps:
    def test_oversized_actor_ip_raises(self, store: SqliteDecisionStore) -> None:
        async def _run() -> None:
            await store.init()
            with pytest.raises(ValueError):
                await store.create_decision(
                    actor_ip="1" * (MAX_ACTOR_IP_CHARS + 1),
                    verb="expected",
                    rule_name=None,
                    decided_tier=2,
                    decided_score=10,
                )
            await store.close()

        asyncio.run(_run())

    def test_oversized_note_raises(self, store: SqliteDecisionStore) -> None:
        async def _run() -> None:
            await store.init()
            with pytest.raises(ValueError):
                await store.create_decision(
                    actor_ip=_IP_A,
                    verb="expected",
                    rule_name=None,
                    decided_tier=2,
                    decided_score=10,
                    note="x" * (MAX_NOTE_CHARS + 1),
                )
            await store.close()

        asyncio.run(_run())


# ---------------------------------------------------------------------------
# D2 — revoke_decision (soft-revoke, append-only)
# ---------------------------------------------------------------------------


class TestRevoke:
    def test_revoke_sets_revoked_at_row_survives(self, store: SqliteDecisionStore) -> None:
        async def _run() -> dict:  # type: ignore[type-arg]
            await store.init()
            record = await store.create_decision(
                actor_ip=_IP_A, verb="expected", rule_name=None,
                decided_tier=2, decided_score=10,
            )
            await store.revoke_decision(record["id"])
            page = await store.list_decisions(actor=_IP_A)
            await store.close()
            return page

        page = asyncio.run(_run())
        assert len(page["items"]) == 1  # row survives — never deleted
        assert page["items"][0]["revoked_at"] is not None

    def test_revoke_unknown_id_raises_lookup_error(self, store: SqliteDecisionStore) -> None:
        async def _run() -> None:
            await store.init()
            with pytest.raises(LookupError):
                await store.revoke_decision(999)
            await store.close()

        asyncio.run(_run())

    def test_revoke_is_idempotent(self, store: SqliteDecisionStore) -> None:
        async def _run() -> None:
            await store.init()
            record = await store.create_decision(
                actor_ip=_IP_A, verb="expected", rule_name=None,
                decided_tier=2, decided_score=10,
            )
            await store.revoke_decision(record["id"])
            await store.revoke_decision(record["id"])  # no-op, must not raise
            await store.close()

        asyncio.run(_run())


# ---------------------------------------------------------------------------
# D2 / ADR-0029 D2 — list_decisions cursor envelope
# ---------------------------------------------------------------------------


class TestListDecisions:
    def test_list_decisions_newest_first(self, store: SqliteDecisionStore) -> None:
        async def _run() -> dict:  # type: ignore[type-arg]
            await store.init()
            await store.create_decision(
                actor_ip=_IP_A, verb="expected", rule_name=None,
                decided_tier=2, decided_score=10,
            )
            await store.create_decision(
                actor_ip=_IP_A, verb="dismissed", rule_name=None,
                decided_tier=2, decided_score=20,
            )
            page = await store.list_decisions()
            await store.close()
            return page

        page = asyncio.run(_run())
        assert [item["verb"] for item in page["items"]] == ["dismissed", "expected"]
        assert page["has_more"] is False

    def test_list_decisions_actor_filter_scopes_result(self, store: SqliteDecisionStore) -> None:
        async def _run() -> dict:  # type: ignore[type-arg]
            await store.init()
            await store.create_decision(
                actor_ip=_IP_A, verb="expected", rule_name=None,
                decided_tier=2, decided_score=10,
            )
            await store.create_decision(
                actor_ip=_IP_B, verb="expected", rule_name=None,
                decided_tier=2, decided_score=10,
            )
            page = await store.list_decisions(actor=_IP_A)
            await store.close()
            return page

        page = asyncio.run(_run())
        assert len(page["items"]) == 1
        assert page["items"][0]["actor_ip"] == _IP_A

    def test_list_decisions_includes_revoked_rows(self, store: SqliteDecisionStore) -> None:
        """Full history (D2) — revoked rows are NOT excluded from list_decisions."""

        async def _run() -> dict:  # type: ignore[type-arg]
            await store.init()
            record = await store.create_decision(
                actor_ip=_IP_A, verb="expected", rule_name=None,
                decided_tier=2, decided_score=10,
            )
            await store.revoke_decision(record["id"])
            page = await store.list_decisions(actor=_IP_A)
            await store.close()
            return page

        page = asyncio.run(_run())
        assert len(page["items"]) == 1

    def test_list_decisions_cursor_pagination(self, store: SqliteDecisionStore) -> None:
        async def _run() -> tuple[dict, dict]:  # type: ignore[type-arg]
            await store.init()
            for i in range(3):
                await store.create_decision(
                    actor_ip=_IP_A, verb="expected", rule_name=None,
                    decided_tier=2, decided_score=i,
                )
            page1 = await store.list_decisions(limit=2, actor=_IP_A)
            page2 = await store.list_decisions(
                limit=2, cursor=page1["next_cursor"], actor=_IP_A
            )
            await store.close()
            return page1, page2

        page1, page2 = asyncio.run(_run())
        assert len(page1["items"]) == 2
        assert page1["has_more"] is True
        assert len(page2["items"]) == 1
        assert page2["has_more"] is False


# ---------------------------------------------------------------------------
# D4 evaluator input — get_active_for_actor
# ---------------------------------------------------------------------------


class TestGetActiveForActor:
    def test_returns_only_non_revoked_rows(self, store: SqliteDecisionStore) -> None:
        async def _run() -> list[dict]:  # type: ignore[type-arg]
            await store.init()
            await store.create_decision(
                actor_ip=_IP_A, verb="expected", rule_name=None,
                decided_tier=2, decided_score=10,
            )
            revoked = await store.create_decision(
                actor_ip=_IP_A, verb="dismissed", rule_name=None,
                decided_tier=2, decided_score=20,
            )
            await store.revoke_decision(revoked["id"])
            rows = await store.get_active_for_actor(_IP_A)
            await store.close()
            return rows

        rows = asyncio.run(_run())
        assert len(rows) == 1
        assert rows[0]["verb"] == "expected"

    def test_returns_empty_for_unknown_actor(self, store: SqliteDecisionStore) -> None:
        async def _run() -> list[dict]:  # type: ignore[type-arg]
            await store.init()
            rows = await store.get_active_for_actor(_IP_A)
            await store.close()
            return rows

        rows = asyncio.run(_run())
        assert rows == []
