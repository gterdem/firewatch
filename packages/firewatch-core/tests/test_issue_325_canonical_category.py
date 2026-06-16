"""Tests for issue #325 — canonical stored category as single source of truth.

EARS criteria → test mapping:

  EARS-1  WHEN client requests GET /logs/categories, the system SHALL return one entry per
          distinct stored ``category`` value among BLOCK/DROP rows, each as {category, count},
          with NULL/empty aggregated under "Other", ordered by count descending.
          → test_get_categories_groups_by_stored_column
          → test_get_categories_null_maps_to_other
          → test_get_categories_ordered_by_count_descending
          → test_get_categories_empty_returns_empty_list

  EARS-2  Every category value returned by /logs/categories must be a value that
          ?category=<value>&action=blocked matches at least one row for (shared vocabulary).
          → test_categories_and_paginated_share_vocabulary

  EARS-3  WHEN ?category=<v> is requested and <v> is not "all" or a legacy shorthand key,
          the system SHALL filter rows by exact parameterized match on stored category column,
          and total_matching SHALL reflect the filtered count.
          → test_paginated_canonical_category_filters_rows
          → test_paginated_canonical_category_total_matching
          → test_paginated_canonical_category_no_match_returns_empty

  EARS-4  WHEN ?category=<k> is a legacy shorthand key (sqli/xss/lfi/cmdi/proto/anomaly/
          bot/ratelimit/geo), the system SHALL preserve the existing rule_id prefix/contains
          filtering (no regression).
          → test_paginated_legacy_shorthand_sqli_prefix_match
          → test_paginated_legacy_shorthand_geo_contains_match
          → test_paginated_legacy_all_returns_no_filter

  EARS-5  (Frontend — verified via store contract; the panel gets canonical labels and the
          paginated filter now honours them.)
          → covered by EARS-2, EARS-3 together

  EARS-6  IF two or more distinct rule_ids share the same stored category, THEN
          /logs/categories SHALL still emit exactly one entry for that category.
          → test_get_categories_one_row_per_category_regardless_of_rule_id_count

  EARS-7  WHEN category rows are filtered, the system SHALL bind all filter values as SQL
          parameters (no string interpolation of user input).
          → test_paginated_category_filter_is_parameterized (structural)
          → test_paginated_category_filter_sql_injection_safe
"""
from __future__ import annotations

import pytest
from collections.abc import AsyncGenerator
from datetime import datetime, timezone
from pathlib import Path

from firewatch_sdk import SecurityEvent
from firewatch_sdk.models import FilterSpec

from firewatch_core.adapters.sqlite_store import SQLiteEventStore


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
async def store(tmp_path: Path) -> AsyncGenerator[SQLiteEventStore, None]:
    """Fresh, initialised SQLiteEventStore backed by a tmp file."""
    s = SQLiteEventStore(tmp_path / "test_325.db")
    await s.init()
    yield s
    await s.close()


def _evt(
    *,
    source_ip: str = "192.0.2.1",
    action: str = "BLOCK",
    rule_id: str | None = "942100",
    category: str | None = "WAF Rule",
    source_type: str = "azure-waf",
    source_id: str = "my-waf",
    timestamp: datetime | None = None,
    severity: str | None = "high",
) -> SecurityEvent:
    ts = timestamp or datetime(2026, 6, 1, 12, 0, 0, tzinfo=timezone.utc)
    return SecurityEvent(
        source_type=source_type,
        source_id=source_id,
        source_ip=source_ip,
        action=action,  # type: ignore[arg-type]
        timestamp=ts,
        rule_id=rule_id,
        category=category,
        severity=severity,  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# EARS-1: get_categories — groups by stored column, blocked-only, NULL->Other
# ---------------------------------------------------------------------------


async def test_get_categories_groups_by_stored_column(store: SQLiteEventStore) -> None:
    """get_categories groups by the stored category column, not rule_id."""
    await store.save_many([
        _evt(source_ip="192.0.2.10", action="BLOCK", rule_id="942100", category="WAF Rule"),
        _evt(source_ip="192.0.2.11", action="BLOCK", rule_id="942200", category="WAF Rule"),  # same category, diff rule
        _evt(source_ip="192.0.2.12", action="DROP",  rule_id="941001", category="XSS"),
    ])
    cats = await store.get_categories()

    labels = {r["category"] for r in cats}
    # Two distinct rule_ids with same stored category must produce ONE "WAF Rule" entry
    assert labels == {"WAF Rule", "XSS"}, f"Unexpected labels: {labels}"
    waf_row = next(r for r in cats if r["category"] == "WAF Rule")
    assert waf_row["count"] == 2, f"Expected count=2 for WAF Rule, got {waf_row['count']}"


async def test_get_categories_null_maps_to_other(store: SQLiteEventStore) -> None:
    """Rows with NULL category are aggregated under 'Other'."""
    await store.save_many([
        _evt(source_ip="192.0.2.20", action="BLOCK", rule_id=None, category=None),
        _evt(source_ip="192.0.2.21", action="DROP",  rule_id="CUSTOM", category=None),
        _evt(source_ip="192.0.2.22", action="BLOCK", rule_id="942100", category="WAF Rule"),
    ])
    cats = await store.get_categories()

    other_rows = [r for r in cats if r["category"] == "Other"]
    assert len(other_rows) == 1, f"Expected exactly one 'Other' row, got {other_rows}"
    assert other_rows[0]["count"] == 2, f"Expected count=2 for Other, got {other_rows[0]['count']}"


async def test_get_categories_ordered_by_count_descending(store: SQLiteEventStore) -> None:
    """Results are ordered by count descending."""
    await store.save_many([
        _evt(source_ip="192.0.2.30", action="BLOCK", category="XSS"),
        _evt(source_ip="192.0.2.31", action="BLOCK", category="WAF Rule"),
        _evt(source_ip="192.0.2.32", action="BLOCK", category="WAF Rule"),
        _evt(source_ip="192.0.2.33", action="BLOCK", category="WAF Rule"),
    ])
    cats = await store.get_categories()
    counts = [r["count"] for r in cats]
    assert counts == sorted(counts, reverse=True), f"Not ordered descending: {cats}"


async def test_get_categories_empty_returns_empty_list(store: SQLiteEventStore) -> None:
    """Empty store returns []."""
    cats = await store.get_categories()
    assert cats == []


async def test_get_categories_blocked_only(store: SQLiteEventStore) -> None:
    """ALLOW events must not appear in get_categories output."""
    await store.save_many([
        _evt(source_ip="192.0.2.40", action="BLOCK", category="WAF Rule"),
        _evt(source_ip="192.0.2.41", action="ALLOW", category="WAF Rule"),  # must be excluded
        _evt(source_ip="192.0.2.42", action="ALLOW", category="Bot Detection"),  # must be excluded
    ])
    cats = await store.get_categories()
    total = sum(r["count"] for r in cats)
    assert total == 1, f"Only BLOCK/DROP rows should be counted; got total={total}"


# ---------------------------------------------------------------------------
# EARS-6: one row per category regardless of how many distinct rule_ids map to it
# ---------------------------------------------------------------------------


async def test_get_categories_one_row_per_category_regardless_of_rule_id_count(
    store: SQLiteEventStore,
) -> None:
    """Structural guarantee: GROUP BY stored column means one row per distinct category."""
    await store.save_many([
        _evt(source_ip="192.0.2.50", rule_id="942001", category="WAF Rule"),
        _evt(source_ip="192.0.2.51", rule_id="942002", category="WAF Rule"),
        _evt(source_ip="192.0.2.52", rule_id="942003", category="WAF Rule"),
        _evt(source_ip="192.0.2.53", rule_id="900001", category="Bot Detection"),
        _evt(source_ip="192.0.2.54", rule_id="900002", category="Bot Detection"),
    ])
    cats = await store.get_categories()
    labels = [r["category"] for r in cats]
    assert len(labels) == len(set(labels)), f"Duplicate category rows: {cats}"


# ---------------------------------------------------------------------------
# EARS-2: shared vocabulary — every /logs/categories label matches paginated rows
# ---------------------------------------------------------------------------


async def test_categories_and_paginated_share_vocabulary(store: SQLiteEventStore) -> None:
    """Every label from get_categories must match at least one row via category= filter."""
    await store.save_many([
        _evt(source_ip="192.0.2.60", action="BLOCK", category="WAF Rule"),
        _evt(source_ip="192.0.2.61", action="DROP",  category="Anomaly Score Threshold"),
    ])
    cats = await store.get_categories()

    for row in cats:
        label = row["category"]
        if label == "Other":
            # "Other" represents NULL stored category; skip vocabulary check for it
            continue
        result = await store.get_paginated(
            filters=FilterSpec(category=label, action="blocked")
        )
        assert result["total_matching"] >= 1, (
            f"category='{label}' from /categories returned no paginated rows"
        )


# ---------------------------------------------------------------------------
# EARS-3: canonical category value exact-match in get_paginated
# ---------------------------------------------------------------------------


async def test_paginated_canonical_category_filters_rows(store: SQLiteEventStore) -> None:
    """?category=<canonical> filters by exact stored category value."""
    await store.save_many([
        _evt(source_ip="192.0.2.70", action="BLOCK", category="WAF Rule"),
        _evt(source_ip="192.0.2.71", action="BLOCK", category="WAF Rule"),
        _evt(source_ip="192.0.2.72", action="BLOCK", category="Bot Detection"),
    ])
    result = await store.get_paginated(filters=FilterSpec(category="WAF Rule"))
    returned_ips = {r["source_ip"] for r in result["logs"]}
    assert "192.0.2.72" not in returned_ips, "Bot Detection row must not appear for WAF Rule filter"
    # All returned rows must have category="WAF Rule"
    for row in result["logs"]:
        assert row.get("category") == "WAF Rule", f"Unexpected category in row: {row}"


async def test_paginated_canonical_category_total_matching(store: SQLiteEventStore) -> None:
    """total_matching reflects the filtered count for a canonical category value."""
    await store.save_many([
        _evt(source_ip="192.0.2.80", action="BLOCK", category="WAF Rule"),
        _evt(source_ip="192.0.2.81", action="BLOCK", category="WAF Rule"),
        _evt(source_ip="192.0.2.82", action="DROP",  category="Bot Detection"),
    ])
    result = await store.get_paginated(filters=FilterSpec(category="WAF Rule"))
    assert result["total_matching"] == 2, (
        f"Expected total_matching=2 for category='WAF Rule', got {result['total_matching']}"
    )


async def test_paginated_canonical_category_no_match_returns_empty(store: SQLiteEventStore) -> None:
    """A canonical category value with no matching rows returns empty logs + total_matching=0."""
    await store.save_many([
        _evt(source_ip="192.0.2.90", action="BLOCK", category="WAF Rule"),
    ])
    result = await store.get_paginated(filters=FilterSpec(category="Nonexistent Category XYZ"))
    assert result["logs"] == []
    assert result["total_matching"] == 0


# ---------------------------------------------------------------------------
# EARS-4: legacy shorthand keys still work (regression guard)
# ---------------------------------------------------------------------------


async def test_paginated_legacy_shorthand_sqli_prefix_match(store: SQLiteEventStore) -> None:
    """category='sqli' still prefix-matches rule_id starting with '942'."""
    await store.save_many([
        _evt(source_ip="192.0.2.100", action="BLOCK", rule_id="942100", category="WAF Rule"),
        _evt(source_ip="192.0.2.101", action="BLOCK", rule_id="941001", category="XSS"),  # must be excluded
    ])
    result = await store.get_paginated(filters=FilterSpec(category="sqli"))
    returned_ips = {r["source_ip"] for r in result["logs"]}
    assert "192.0.2.100" in returned_ips, "sqli shorthand must match 942xxx rule_id"
    assert "192.0.2.101" not in returned_ips, "sqli must not match XSS row"


async def test_paginated_legacy_shorthand_geo_contains_match(store: SQLiteEventStore) -> None:
    """category='geo' still contains-matches rule_id containing 'GeoBlock'."""
    await store.save_many([
        _evt(source_ip="192.0.2.110", action="BLOCK", rule_id="GeoBlock-US", category="Geo-Blocked"),
        _evt(source_ip="192.0.2.111", action="BLOCK", rule_id="942100",     category="WAF Rule"),
    ])
    result = await store.get_paginated(filters=FilterSpec(category="geo"))
    returned_ips = {r["source_ip"] for r in result["logs"]}
    assert "192.0.2.110" in returned_ips, "geo shorthand must match GeoBlock rule_id"
    assert "192.0.2.111" not in returned_ips, "geo must not match WAF Rule row"


async def test_paginated_legacy_all_returns_no_filter(store: SQLiteEventStore) -> None:
    """category='all' applies no category filter — all rows returned."""
    await store.save_many([
        _evt(source_ip="192.0.2.120", action="BLOCK", category="WAF Rule"),
        _evt(source_ip="192.0.2.121", action="BLOCK", category="Bot Detection"),
        _evt(source_ip="192.0.2.122", action="ALLOW", category="WAF Rule"),
    ])
    result_all = await store.get_paginated(filters=FilterSpec(category="all"))
    result_unfiltered = await store.get_paginated()
    assert result_all["total_matching"] == result_unfiltered["total_matching"]


# ---------------------------------------------------------------------------
# EARS-7: parameterized SQL — no string interpolation of user input
# ---------------------------------------------------------------------------


async def test_paginated_category_filter_sql_injection_safe(store: SQLiteEventStore) -> None:
    """SQL injection attempt via category= must not crash or return unfiltered rows."""
    await store.save_many([
        _evt(source_ip="192.0.2.130", action="BLOCK", category="WAF Rule"),
    ])
    # A SQL-injection-like value should yield zero rows (not an error, not all rows)
    result = await store.get_paginated(
        filters=FilterSpec(category="WAF Rule' OR '1'='1")
    )
    assert result["logs"] == [], "SQL injection payload must not return rows"
    assert result["total_matching"] == 0


async def test_paginated_category_filter_is_parameterized(store: SQLiteEventStore) -> None:
    """Structural: category value with SQL special chars must not cause an exception."""
    await store.save_many([
        _evt(source_ip="192.0.2.140", action="BLOCK", category="WAF Rule"),
    ])
    # These would raise sqlite3.OperationalError if interpolated directly
    for payload in ["' OR ''='", "'; DROP TABLE logs; --", '"; DROP TABLE logs; --']:
        result = await store.get_paginated(filters=FilterSpec(category=payload))
        assert isinstance(result, dict), f"Expected dict result for payload {payload!r}"
        assert result["logs"] == []


# ---------------------------------------------------------------------------
# Response shape: get_categories returns {category, count} only (no rule_id/filter)
# ---------------------------------------------------------------------------


async def test_get_categories_response_shape(store: SQLiteEventStore) -> None:
    """get_categories rows must contain 'category' and 'count' keys only."""
    await store.save_many([
        _evt(source_ip="192.0.2.150", action="BLOCK", category="WAF Rule"),
    ])
    cats = await store.get_categories()
    assert len(cats) == 1
    row = cats[0]
    assert set(row.keys()) == {"category", "count"}, (
        f"Expected only {{category, count}}, got keys: {set(row.keys())}"
    )


# ---------------------------------------------------------------------------
# Regression: category_name param still works (deprecated synonym, stays functional)
# ---------------------------------------------------------------------------


async def test_paginated_category_name_still_works(store: SQLiteEventStore) -> None:
    """category_name= still does exact match on the stored category column."""
    await store.save_many([
        _evt(source_ip="192.0.2.160", action="BLOCK", category="WAF Rule"),
        _evt(source_ip="192.0.2.161", action="BLOCK", category="Bot Detection"),
    ])
    result = await store.get_paginated(filters=FilterSpec(category_name="WAF Rule"))
    assert result["total_matching"] == 1
    assert result["logs"][0]["source_ip"] == "192.0.2.160"
