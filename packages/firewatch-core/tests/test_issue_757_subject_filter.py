"""Tests for issue #757 — subject filter on list_cases (SqliteCaseStore).

EARS criterion map
------------------
EARS-1  WHEN 'Open case' is clicked AND an open case already exists for that
        subject, THE UI SHALL open the existing case (no new case created).
        Backend pre-requisite: GET /cases?subject=<value> returns matching cases.

Test coverage (store layer):
  test_list_cases_subject_filter_returns_matching_only
      Create 2 cases with subject A and 1 with subject B.
      list_cases(subject="A") returns exactly the 2 A cases.
  test_list_cases_subject_filter_empty_when_no_match
      list_cases(subject="unknown") returns empty items list.
  test_list_cases_subject_filter_newest_first
      Filtered results are ordered newest-first (desc created_at, id).
  test_list_cases_no_subject_returns_all
      Omitting subject returns all cases (backward-compatible).
  test_list_cases_subject_filter_envelope_shape
      Filtered result conforms to ADR-0029 envelope.
  test_list_cases_subject_parameterized_no_injection
      SQL injection string in subject is treated as a literal (no crash, empty result).

All IPs are RFC 5737 documentation IPs (192.0.2.0/24, 198.51.100.0/24,
203.0.113.0/24) — never real/public/routable IPs.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from firewatch_core.adapters.cases.sqlite_cases import SqliteCaseStore

# RFC 5737 documentation IPs only.
_SUBJECT_A = "192.0.2.10"
_SUBJECT_B = "198.51.100.20"
_SUBJECT_C = "203.0.113.5"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "cases_subject_test.db"


@pytest.fixture()
def store(db_path: Path) -> SqliteCaseStore:
    return SqliteCaseStore(db_path=db_path)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


async def _seed_and_filter(
    store: SqliteCaseStore,
    subject_filter: str | None = None,
) -> dict:  # type: ignore[type-arg]
    """Seed 2 A cases + 1 B case and call list_cases with the given subject filter."""
    await store.init()
    id_a1 = await store.create_case(title="Case A1", subject=_SUBJECT_A)
    id_a2 = await store.create_case(title="Case A2", subject=_SUBJECT_A)
    id_b1 = await store.create_case(title="Case B1", subject=_SUBJECT_B)
    _ = id_a1, id_a2, id_b1  # recorded for clarity
    page = await store.list_cases(subject=subject_filter)
    await store.close()
    return page  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_list_cases_subject_filter_returns_matching_only(
    store: SqliteCaseStore,
) -> None:
    """list_cases(subject=A) returns exactly the 2 cases with subject A.

    Regression spec from issue #757: GET /cases?subject=<value> must return
    only matching cases (the frontend find-or-create depends on this).
    """
    page = asyncio.run(_seed_and_filter(store, subject_filter=_SUBJECT_A))
    assert len(page["items"]) == 2
    for item in page["items"]:
        assert item["subject"] == _SUBJECT_A


def test_list_cases_subject_filter_empty_when_no_match(
    store: SqliteCaseStore,
) -> None:
    """list_cases(subject=unknown) returns empty items when no match."""
    page = asyncio.run(_seed_and_filter(store, subject_filter=_SUBJECT_C))
    assert page["items"] == []
    assert page["has_more"] is False
    assert page["next_cursor"] is None


def test_list_cases_subject_filter_newest_first(
    store: SqliteCaseStore,
) -> None:
    """Filtered results are ordered newest-first (descending created_at, id).

    The most-recently-created case must appear first in items.
    """

    async def _run() -> dict:  # type: ignore[type-arg]
        await store.init()
        id1 = await store.create_case(title="First A", subject=_SUBJECT_A)
        id2 = await store.create_case(title="Second A", subject=_SUBJECT_A)
        page = await store.list_cases(subject=_SUBJECT_A)
        await store.close()
        return {"page": page, "id1": id1, "id2": id2}

    result = asyncio.run(_run())
    page = result["page"]
    id1 = result["id1"]
    id2 = result["id2"]

    assert len(page["items"]) == 2
    # Newest first: id2 was inserted last so it must come before id1.
    assert page["items"][0]["id"] == id2
    assert page["items"][1]["id"] == id1


def test_list_cases_no_subject_returns_all(
    store: SqliteCaseStore,
) -> None:
    """Omitting subject (None) returns all cases — backward-compatible."""
    page = asyncio.run(_seed_and_filter(store, subject_filter=None))
    assert len(page["items"]) == 3


def test_list_cases_subject_filter_envelope_shape(
    store: SqliteCaseStore,
) -> None:
    """Filtered result conforms to ADR-0029 envelope keys."""
    page = asyncio.run(_seed_and_filter(store, subject_filter=_SUBJECT_A))
    assert "items" in page
    assert "next_cursor" in page
    assert "has_more" in page


def test_list_cases_subject_parameterized_no_injection(
    store: SqliteCaseStore,
) -> None:
    """SQL injection string in subject is treated as a literal value.

    The query must not crash and must return an empty result (no match),
    confirming parameterized binding (no string interpolation).
    """
    injection = "'; DROP TABLE case_files; --"
    page = asyncio.run(_seed_and_filter(store, subject_filter=injection))
    # If injection succeeded, the table would be gone and the next query would
    # raise; instead we expect an empty-but-valid envelope.
    assert page["items"] == []
    assert page["has_more"] is False
