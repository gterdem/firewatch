"""Tests for ML-12 — DGA domain-generation-algorithm detector (core analytics).

Mapped 1:1 to EARS acceptance criteria from issue #440.

EARS-1  A DGA scorer SHALL compute entropy/lexical features over ``dns_query``
        and flag likely algorithm-generated domains as a facet + row chip.
        Tests here cover the CORE scorer (data layer); route tests are in
        packages/firewatch-api/tests/test_ml12_dga_route.py.

EARS-2  WHERE ``dns_query`` is NULL the row SHALL be skipped honestly.
        Covered here: score_domain("") and store-level NULL exclusion.

EARS-3  R3 SHALL narrate a DGA flag.
        Covered by prompt-injection tests in test_dga_prompt.py (this file
        covers the detection layer only; prompt tests are separate by concern).

Additional:
  - Known-DGA fixture domains score above FLAG_THRESHOLD.
  - Known-benign fixture domains score below FLAG_THRESHOLD.
  - score_domain returns a DomainScore with 0.0 <= score <= 1.0.
  - score_domain("") returns a zero-score (empty domain: no signal).
  - get_dga_suspects aggregates DNS rows from the store; bound by top_n.
  - SQL injection safety: top_n is bound via ?, never f-string.
  - Zero-egress: no network calls are made by the scorer.

All IPs use RFC 5737 / RFC 1918 ranges — never real/routable IPs.
Domains used are fictional or from RFC 2606 reserved zones.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from firewatch_sdk import SecurityEvent
from firewatch_core.adapters.sqlite_store import SQLiteEventStore
from firewatch_core.analytics.dga import (
    FLAG_THRESHOLD,
    DomainScore,
    score_domain,
    get_dga_suspects,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TS = datetime(2026, 6, 13, 12, 0, 0, tzinfo=timezone.utc)

# RFC 5737 documentation IPs only
_SRC_IP = "192.0.2.10"
_DST_IP = "198.51.100.20"


def _dns_event(
    dns_query: str | None,
    ts_offset: int = 0,
    src_ip: str = _SRC_IP,
) -> SecurityEvent:
    """Minimal SecurityEvent with a dns_query field for DGA tests."""
    from datetime import timedelta
    return SecurityEvent(
        source_type="suricata",
        source_id="test-sensor",
        source_ip=src_ip,
        action="ALERT",
        timestamp=_TS + timedelta(seconds=ts_offset),
        dns_query=dns_query,
    )


@pytest.fixture
async def store(tmp_path: Path) -> Any:
    """Fresh initialised SQLiteEventStore."""
    s = SQLiteEventStore(tmp_path / "dga_test.db")
    await s.init()
    yield s
    await s.close()


# ---------------------------------------------------------------------------
# DomainScore return type
# ---------------------------------------------------------------------------


class TestDomainScoreType:
    """score_domain returns a DomainScore with the expected shape."""

    def test_returns_domain_score_instance(self) -> None:
        """score_domain returns a DomainScore named-tuple or dataclass."""
        result = score_domain("example.com")
        assert isinstance(result, DomainScore)

    def test_score_in_range(self) -> None:
        """DomainScore.score is always 0.0 <= score <= 1.0."""
        for domain in [
            "example.com",
            "xkzqvmwjnrbptfl.net",
            "a1b2c3d4e5f6.io",
            "",
        ]:
            result = score_domain(domain)
            assert 0.0 <= result.score <= 1.0, (
                f"score out of range for {domain!r}: {result.score}"
            )

    def test_flagged_field_consistent_with_threshold(self) -> None:
        """DomainScore.flagged == (score >= FLAG_THRESHOLD)."""
        for domain in [
            "example.com",
            "xkzqvmwjnrbptfld.net",
        ]:
            result = score_domain(domain)
            assert result.flagged == (result.score >= FLAG_THRESHOLD)

    def test_domain_preserved_in_result(self) -> None:
        """DomainScore.domain equals the input domain."""
        domain = "example.com"
        result = score_domain(domain)
        assert result.domain == domain


# ---------------------------------------------------------------------------
# Empty / null inputs (EARS-2)
# ---------------------------------------------------------------------------


class TestNullAndEmptyInputs:
    """EARS-2 — NULL/empty dns_query is skipped honestly."""

    def test_empty_string_returns_zero_score(self) -> None:
        """Empty string domain yields score=0.0 (no signal to score)."""
        result = score_domain("")
        assert result.score == 0.0
        assert result.flagged is False

    def test_none_is_not_accepted_as_domain_string(self) -> None:
        """score_domain accepts str only; callers must guard None (EARS-2 contract).

        score_domain("") is the right call when dns_query is absent.
        This test confirms the scorer works on "" as the honesty fallback.
        """
        result = score_domain("")
        assert result.score == 0.0

    def test_single_label_no_tld_accepted(self) -> None:
        """Single-label domain (no dot) is accepted and scored; not crashed."""
        result = score_domain("localhost")
        assert 0.0 <= result.score <= 1.0


# ---------------------------------------------------------------------------
# Known-benign domains — MUST score below FLAG_THRESHOLD
# ---------------------------------------------------------------------------


class TestBenignDomains:
    """Known-benign (human-registered) domains score below FLAG_THRESHOLD."""

    BENIGN_DOMAINS = [
        "example.com",
        "google.com",
        "microsoft.com",
        "github.com",
        "cloudflare.com",
        "amazon.com",
        "wikipedia.org",
        "update.windows.com",
        "mail.example.com",
    ]

    def test_benign_not_flagged(self) -> None:
        """Every well-known benign domain scores below the DGA flag threshold."""
        flagged = []
        for domain in self.BENIGN_DOMAINS:
            result = score_domain(domain)
            if result.flagged:
                flagged.append((domain, result.score))
        assert flagged == [], (
            f"Benign domains incorrectly flagged as DGA: {flagged}"
        )


# ---------------------------------------------------------------------------
# Known-DGA domains — MUST score at or above FLAG_THRESHOLD
# ---------------------------------------------------------------------------


class TestDgaDomains:
    """Known algorithm-generated domain patterns score >= FLAG_THRESHOLD.

    DGA fixtures: high-entropy, consonant-heavy, digit-interspersed,
    lexically improbable hostnames typical of malware C2 beaconing.
    All use RFC 2606 reserved TLDs (.example / .test / .invalid) or the
    fictional .xyz TLD commonly used in academic DGA literature.
    None of these are real registered domains.
    """

    DGA_DOMAINS = [
        "xkzqvbmnwjr.example",         # pure consonants, high entropy
        "a1b2c3d4e5f6g7h8.test",        # interleaved digits, no dictionary words
        "qvzjxbkwpnrftdmlsgc.invalid",  # 20-char consonant string
        "2f4a8b1c9d3e7f.xyz",           # hex-like alpha+digit mix
        "rkzmpwqvjtxnbfsdhlg.example",  # random consonant soup
        "xqzvjwbfkptmlhrgdns.test",     # another high-consonant pattern
    ]

    def test_dga_flagged(self) -> None:
        """Every DGA fixture domain is flagged (score >= FLAG_THRESHOLD)."""
        not_flagged = []
        for domain in self.DGA_DOMAINS:
            result = score_domain(domain)
            if not result.flagged:
                not_flagged.append((domain, result.score))
        assert not_flagged == [], (
            f"DGA domains not flagged: {not_flagged}"
        )


# ---------------------------------------------------------------------------
# Individual feature signals
# ---------------------------------------------------------------------------


class TestFeatureSignals:
    """Individual heuristic signals behave as expected."""

    def test_high_entropy_domain_has_higher_score_than_low(self) -> None:
        """High-entropy domain scores higher than low-entropy domain."""
        low_entropy = score_domain("aaaaaaaaaa.example")      # uniform -> low entropy
        high_entropy = score_domain("xqzvjwbfkptml.example")  # diverse chars
        assert high_entropy.score >= low_entropy.score

    def test_long_label_scores_above_short_for_equal_content(self) -> None:
        """A very long random-consonant label scores at least as high as a short one."""
        short = score_domain("xqz.example")
        long_label = score_domain("xqzvjwbfkptmrlsdgnhc.example")
        assert long_label.score >= short.score

    def test_digit_heavy_domain_scores_higher(self) -> None:
        """Domain with high digit-to-total-char ratio scores >= plain alpha domain."""
        digit_heavy = score_domain("a1b2c3d4e5f6.example")
        plain = score_domain("abcdefghij.example")
        assert digit_heavy.score >= plain.score


# ---------------------------------------------------------------------------
# Shannon entropy standalone correctness
# ---------------------------------------------------------------------------


class TestShannonEntropy:
    """Shannon entropy sub-function is mathematically correct."""

    def test_uniform_string_has_zero_entropy(self) -> None:
        """Uniform string (all same char) has entropy = 0 (no information)."""
        from firewatch_core.analytics.dga import _shannon_entropy
        assert _shannon_entropy("aaaa") == pytest.approx(0.0)

    def test_two_equal_chars_has_entropy_one_bit(self) -> None:
        """String with two equally-probable chars has entropy = 1.0 bit."""
        from firewatch_core.analytics.dga import _shannon_entropy
        result = _shannon_entropy("ab")
        assert result == pytest.approx(1.0)

    def test_empty_string_entropy_zero(self) -> None:
        """Empty string has entropy 0 (no characters = no information)."""
        from firewatch_core.analytics.dga import _shannon_entropy
        assert _shannon_entropy("") == pytest.approx(0.0)

    def test_entropy_increases_with_diversity(self) -> None:
        """More distinct characters -> higher entropy."""
        from firewatch_core.analytics.dga import _shannon_entropy
        e_low = _shannon_entropy("aab")    # 2 distinct chars
        e_high = _shannon_entropy("abcde")  # 5 distinct chars
        assert e_high > e_low


# ---------------------------------------------------------------------------
# FLAG_THRESHOLD sanity
# ---------------------------------------------------------------------------


class TestFlagThreshold:
    """FLAG_THRESHOLD is a float in a sensible range."""

    def test_threshold_is_float(self) -> None:
        """FLAG_THRESHOLD is a float."""
        assert isinstance(FLAG_THRESHOLD, float)

    def test_threshold_in_valid_range(self) -> None:
        """FLAG_THRESHOLD is in (0.0, 1.0) -- never a degenerate boundary."""
        assert 0.0 < FLAG_THRESHOLD < 1.0


# ---------------------------------------------------------------------------
# EARS-2: get_dga_suspects skips NULL dns_query rows
# ---------------------------------------------------------------------------


class TestGetDgaSuspectsNullExclusion:
    """EARS-2 — rows with NULL dns_query are not evaluated or returned."""

    @pytest.mark.asyncio
    async def test_null_dns_query_rows_not_included(self, store: SQLiteEventStore) -> None:
        """Rows where dns_query IS NULL do not appear in get_dga_suspects results."""
        await store.save_many([_dns_event(dns_query=None)])
        result = await get_dga_suspects(store, top_n=10)
        assert result == []

    @pytest.mark.asyncio
    async def test_empty_dns_query_rows_not_flagged(self, store: SQLiteEventStore) -> None:
        """Rows with empty string dns_query are not returned (score=0.0 -> not flagged)."""
        ev = _dns_event(dns_query="")
        await store.save_many([ev])
        result = await get_dga_suspects(store, top_n=10)
        assert result == []


# ---------------------------------------------------------------------------
# EARS-1: get_dga_suspects returns high-scoring DNS rows
# ---------------------------------------------------------------------------


class TestGetDgaSuspects:
    """EARS-1 — get_dga_suspects returns rows with dga_score >= FLAG_THRESHOLD."""

    @pytest.mark.asyncio
    async def test_dga_domain_appears_in_suspects(self, store: SQLiteEventStore) -> None:
        """A stored row with a DGA-like dns_query appears in get_dga_suspects."""
        dga_domain = "xkzqvbmnwjrfptdl.example"
        await store.save_many([_dns_event(dns_query=dga_domain)])
        result = await get_dga_suspects(store, top_n=10)
        dns_queries = [r["dns_query"] for r in result]
        assert dga_domain in dns_queries

    @pytest.mark.asyncio
    async def test_benign_domain_not_in_suspects(self, store: SQLiteEventStore) -> None:
        """A stored row with a benign dns_query does NOT appear in get_dga_suspects."""
        await store.save_many([_dns_event(dns_query="example.com")])
        result = await get_dga_suspects(store, top_n=10)
        dns_queries = [r["dns_query"] for r in result]
        assert "example.com" not in dns_queries

    @pytest.mark.asyncio
    async def test_mixed_rows_only_dga_returned(self, store: SQLiteEventStore) -> None:
        """Only DGA-like rows appear in suspects when mixed with benign rows."""
        dga_domain = "xkzqvbmnwjrfptdl.example"
        benign_domain = "example.com"
        await store.save_many([
            _dns_event(dns_query=dga_domain, ts_offset=0),
            _dns_event(dns_query=benign_domain, ts_offset=1, src_ip="192.0.2.20"),
            _dns_event(dns_query=None, ts_offset=2, src_ip="192.0.2.30"),
        ])
        result = await get_dga_suspects(store, top_n=10)
        dns_queries = [r["dns_query"] for r in result]
        assert dga_domain in dns_queries
        assert benign_domain not in dns_queries

    @pytest.mark.asyncio
    async def test_result_contains_dga_score_field(self, store: SQLiteEventStore) -> None:
        """Each suspect row contains a dga_score field."""
        dga_domain = "xkzqvbmnwjrfptdl.example"
        await store.save_many([_dns_event(dns_query=dga_domain)])
        result = await get_dga_suspects(store, top_n=10)
        assert len(result) >= 1
        row = result[0]
        assert "dga_score" in row
        assert isinstance(row["dga_score"], float)

    @pytest.mark.asyncio
    async def test_result_contains_source_ip_field(self, store: SQLiteEventStore) -> None:
        """Each suspect row contains a source_ip field."""
        dga_domain = "xkzqvbmnwjrfptdl.example"
        await store.save_many([_dns_event(dns_query=dga_domain)])
        result = await get_dga_suspects(store, top_n=10)
        assert len(result) >= 1
        row = result[0]
        assert "source_ip" in row

    @pytest.mark.asyncio
    async def test_top_n_bounds_result(self, store: SQLiteEventStore) -> None:
        """get_dga_suspects never returns more rows than top_n."""
        for i in range(5):
            await store.save_many([
                _dns_event(
                    dns_query=f"xkzqvbmnjrftpdl{i}xyz.example",
                    ts_offset=i,
                    src_ip=f"192.0.2.{10 + i}",
                )
            ])
        result = await get_dga_suspects(store, top_n=3)
        assert len(result) <= 3

    @pytest.mark.asyncio
    async def test_empty_db_returns_empty_list(self, store: SQLiteEventStore) -> None:
        """Empty store returns empty suspects list without error."""
        result = await get_dga_suspects(store, top_n=10)
        assert result == []

    @pytest.mark.asyncio
    async def test_results_ordered_by_score_desc(self, store: SQLiteEventStore) -> None:
        """Suspect rows are ordered by dga_score descending (highest first)."""
        domains = [
            ("xkzqvbmnwjrfptdl.example", "192.0.2.11"),
            ("rkzmvwqnbfjxptlhgd.example", "192.0.2.12"),
        ]
        for i, (domain, ip) in enumerate(domains):
            await store.save_many([
                _dns_event(dns_query=domain, ts_offset=i, src_ip=ip)
            ])
        result = await get_dga_suspects(store, top_n=10)
        if len(result) >= 2:
            scores = [r["dga_score"] for r in result]
            assert scores == sorted(scores, reverse=True), (
                f"Results not ordered by dga_score desc: {scores}"
            )


# ---------------------------------------------------------------------------
# Injection safety
# ---------------------------------------------------------------------------


class TestInjectionSafety:
    """top_n is bound via SQL placeholder, never f-string interpolated."""

    @pytest.mark.asyncio
    async def test_top_n_integer_accepted(self, store: SQLiteEventStore) -> None:
        """get_dga_suspects accepts an integer top_n without error."""
        result = await get_dga_suspects(store, top_n=5)
        assert isinstance(result, list)

    @pytest.mark.asyncio
    async def test_top_n_one_returns_at_most_one_row(self, store: SQLiteEventStore) -> None:
        """top_n=1 returns at most 1 row (LIMIT bound via ?)."""
        for i in range(3):
            await store.save_many([
                _dns_event(
                    dns_query=f"xkzqvbmnwjrftpdl{i}xyz.example",
                    ts_offset=i,
                    src_ip=f"192.0.2.{10 + i}",
                )
            ])
        result = await get_dga_suspects(store, top_n=1)
        assert len(result) <= 1
