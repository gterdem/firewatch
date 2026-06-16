"""Tests for ML-12 EARS-3 — DGA flag narration in AI prompts.

EARS-3  R3 SHALL narrate a DGA flag.

Verifies that format_concise and format_detailed include a DGA section
when dga_flags is supplied, and omit it when not supplied (backwards
compatibility).

All IPs use RFC 5737 / RFC 1918 ranges.
Domains used are RFC 2606 reserved (.example/.test/.invalid).
"""
from __future__ import annotations

from typing import Any

from firewatch_core.ai.prompts import format_concise, format_detailed, SENTINEL_OPEN

# RFC 5737 documentation IP
_IP = "192.0.2.10"
_TOTAL = 5
_BLOCKED = 3
_RULES = 2
_FIRST = "2026-06-13T10:00:00Z"
_LAST = "2026-06-13T11:00:00Z"
_SAMPLES: list[dict[str, Any]] = []

_DGA_FLAGS: list[dict[str, Any]] = [
    {"dns_query": "xkzqvbmnwjrfptdl.example", "dga_score": 0.754},
]


def _concise(**kw: Any) -> str:
    """Shorthand for format_concise with default fixture values."""
    return format_concise(
        ip=_IP,
        total_events=_TOTAL,
        blocked_events=_BLOCKED,
        rules_triggered=_RULES,
        first_seen=_FIRST,
        last_seen=_LAST,
        samples=_SAMPLES,
        **kw,
    )


def _detailed(**kw: Any) -> str:
    """Shorthand for format_detailed with default fixture values."""
    return format_detailed(
        ip=_IP,
        total_events=_TOTAL,
        blocked_events=_BLOCKED,
        rules_triggered=_RULES,
        first_seen=_FIRST,
        last_seen=_LAST,
        samples=_SAMPLES,
        **kw,
    )


class TestDgaFlagInConcisePrompt:
    """EARS-3 — format_concise narrates DGA flags when supplied."""

    def test_dga_section_present_when_flags_supplied(self) -> None:
        """DGA section appears in prompt when dga_flags is non-empty."""
        prompt = _concise(dga_flags=_DGA_FLAGS)
        assert "DGA" in prompt or "dga" in prompt.lower()

    def test_dga_domain_in_prompt_sentinel_wrapped(self) -> None:
        """DGA dns_query value is wrapped in <untrusted_data> sentinel (NB-1)."""
        prompt = _concise(dga_flags=_DGA_FLAGS)
        assert SENTINEL_OPEN in prompt

    def test_dga_score_in_prompt(self) -> None:
        """DGA score value appears in the prompt text."""
        prompt = _concise(dga_flags=_DGA_FLAGS)
        assert "0.75" in prompt

    def test_rule_provenance_noted(self) -> None:
        """Prompt explicitly states RULE provenance (not AI) for glass-box honesty."""
        prompt = _concise(dga_flags=_DGA_FLAGS)
        assert "RULE" in prompt or "heuristic" in prompt.lower()

    def test_no_dga_section_when_flags_none(self) -> None:
        """No DGA section appears when dga_flags is None (backwards compatible)."""
        prompt = _concise(dga_flags=None)
        assert "Possible DGA" not in prompt

    def test_no_dga_section_when_flags_empty(self) -> None:
        """No DGA section appears when dga_flags is an empty list."""
        prompt = _concise(dga_flags=[])
        assert "Possible DGA" not in prompt

    def test_dga_flags_default_none_backwards_compat(self) -> None:
        """Calling format_concise without dga_flags kwarg still works."""
        prompt = _concise()
        assert isinstance(prompt, str)
        assert len(prompt) > 0


class TestDgaFlagInDetailedPrompt:
    """EARS-3 — format_detailed narrates DGA flags when supplied."""

    def test_dga_section_present_when_flags_supplied(self) -> None:
        """DGA section appears in detailed prompt when dga_flags is non-empty."""
        prompt = _detailed(dga_flags=_DGA_FLAGS)
        assert "DGA" in prompt or "dga" in prompt.lower()

    def test_dga_domain_sentinel_wrapped_in_detailed(self) -> None:
        """DGA dns_query is NB-1 sentinel-wrapped in the detailed prompt."""
        prompt = _detailed(dga_flags=_DGA_FLAGS)
        assert SENTINEL_OPEN in prompt

    def test_no_dga_section_when_flags_none_detailed(self) -> None:
        """No DGA section when dga_flags is None in detailed prompt."""
        prompt = _detailed(dga_flags=None)
        assert "Possible DGA" not in prompt

    def test_dga_flags_default_none_detailed_backwards_compat(self) -> None:
        """Calling format_detailed without dga_flags still works."""
        prompt = _detailed()
        assert isinstance(prompt, str)
        assert len(prompt) > 0
