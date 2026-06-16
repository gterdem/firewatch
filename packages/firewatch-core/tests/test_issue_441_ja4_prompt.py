"""Tests for ML-13 — EARS-3: AI prompt narrates JA4 matches (issue #441).

Mapped 1:1 to EARS-3 from issue #441 (prompt layer).

EARS-3  R3 SHALL narrate a JA4 match: format_concise and format_detailed SHALL
        include a TLS Fingerprints section when tls_fingerprints is non-empty.
        - section is present in the prompt when fingerprints are provided
        - section is ABSENT when tls_fingerprints is None or empty (no fabrication)
        - each fingerprint is wrapped in the untrusted-data sentinel (NB-1)
        - sentinel-injection in a fingerprint string is escaped (NB-1 hardening)
        - multiple fingerprints are all included
        - format_detailed also includes the section

EARS-2  When tls_fingerprints is None/empty, NO TLS section is added — honest
        absence (consume-only).
"""
from __future__ import annotations

from firewatch_core.ai.prompts import (
    SENTINEL_CLOSE,
    SENTINEL_OPEN,
    format_concise,
    format_detailed,
)

# ---------------------------------------------------------------------------
# Shared fixture data
# ---------------------------------------------------------------------------

_SAMPLE = {
    "rule_id": "ET-1000001",
    "category": "ids_alert",
    "payload": "GET /probe HTTP/1.1",
    "count": 3,
}

_BASE_KWARGS: dict = dict(
    ip="192.0.2.50",
    total_events=10,
    blocked_events=5,
    rules_triggered=1,
    first_seen="2026-06-13T10:00:00",
    last_seen="2026-06-13T12:00:00",
    samples=[_SAMPLE],
    security_mode=True,
)

# Synthetic JA4 fingerprints — opaque strings, not real sensor captures
_FP_A = "t13d1516h2_8daaf6152771_02713d6af862"
_FP_B = "t13d201100h2_40348e13a07b_f11594a38c92"


# ---------------------------------------------------------------------------
# EARS-3: format_concise with JA4 fingerprints
# ---------------------------------------------------------------------------


class TestFormatConciseWithJa4:
    """EARS-3 — format_concise includes TLS Fingerprints section when provided."""

    def test_tls_section_present_when_fingerprints_provided(self) -> None:
        """TLS Fingerprints section appears in the prompt when fingerprints given."""
        prompt = format_concise(**_BASE_KWARGS, tls_fingerprints=[_FP_A])
        assert "TLS Fingerprints" in prompt

    def test_fingerprint_value_appears_in_prompt(self) -> None:
        """The fingerprint value is included in the prompt (sentinel-wrapped)."""
        prompt = format_concise(**_BASE_KWARGS, tls_fingerprints=[_FP_A])
        assert _FP_A in prompt

    def test_fingerprint_is_sentinel_wrapped(self) -> None:
        """Each fingerprint is enclosed in the untrusted-data sentinel (NB-1)."""
        prompt = format_concise(**_BASE_KWARGS, tls_fingerprints=[_FP_A])
        assert SENTINEL_OPEN in prompt
        assert SENTINEL_CLOSE in prompt
        # The sentinel must wrap the fingerprint
        assert f"{SENTINEL_OPEN}{_FP_A}{SENTINEL_CLOSE}" in prompt

    def test_multiple_fingerprints_all_present(self) -> None:
        """All provided fingerprints appear in the prompt."""
        prompt = format_concise(**_BASE_KWARGS, tls_fingerprints=[_FP_A, _FP_B])
        assert _FP_A in prompt
        assert _FP_B in prompt

    def test_tls_section_absent_when_no_fingerprints(self) -> None:
        """TLS Fingerprints section is ABSENT when tls_fingerprints is None."""
        prompt = format_concise(**_BASE_KWARGS, tls_fingerprints=None)
        assert "TLS Fingerprints" not in prompt

    def test_tls_section_absent_when_empty_list(self) -> None:
        """TLS Fingerprints section is ABSENT when tls_fingerprints is []."""
        prompt = format_concise(**_BASE_KWARGS, tls_fingerprints=[])
        assert "TLS Fingerprints" not in prompt

    def test_sentinel_injection_in_fingerprint_is_escaped(self) -> None:
        """A fingerprint containing sentinel tags has them escaped (NB-1).

        _wrap_payload escapes SENTINEL_OPEN/CLOSE inside the value before wrapping,
        so the injected sentinel tag appears as <!untrusted_data> (inert escape),
        not as a live <untrusted_data> boundary.
        """
        crafted = f"t13d{SENTINEL_OPEN}inject{SENTINEL_CLOSE}_00000000_00000000"
        prompt = format_concise(**_BASE_KWARGS, tls_fingerprints=[crafted])
        # The escaped form must appear — the injection attempt was neutralised
        assert "<!untrusted_data>" in prompt
        assert "</!untrusted_data>" in prompt
        # The raw injected sentinel OPEN must NOT appear unescaped inside a fingerprint.
        # It's safe to check that the literal crafted string is absent from the prompt
        # (the escaped version replaces both inner tags).
        assert crafted not in prompt

    def test_no_fingerprints_no_regression_on_existing_output(self) -> None:
        """When tls_fingerprints is omitted entirely, prompt is identical to before."""
        prompt_no_param = format_concise(**_BASE_KWARGS)
        prompt_none = format_concise(**_BASE_KWARGS, tls_fingerprints=None)
        assert prompt_no_param == prompt_none


# ---------------------------------------------------------------------------
# EARS-3: format_detailed with JA4 fingerprints
# ---------------------------------------------------------------------------

_DETAILED_SAMPLE = {
    **_SAMPLE,
    "description": "Suspicious outbound probe",
    "first_triggered": "2026-06-13T10:00:00",
    "last_triggered": "2026-06-13T12:00:00",
}


class TestFormatDetailedWithJa4:
    """EARS-3 — format_detailed includes TLS Fingerprints section when provided."""

    def test_tls_section_present_when_fingerprints_provided(self) -> None:
        """TLS Fingerprints section appears in the detailed prompt."""
        prompt = format_detailed(
            **{**_BASE_KWARGS, "samples": [_DETAILED_SAMPLE]},
            tls_fingerprints=[_FP_A],
        )
        assert "TLS Fingerprints" in prompt

    def test_fingerprint_sentinel_wrapped_in_detailed(self) -> None:
        """Fingerprint is sentinel-wrapped in the detailed prompt (NB-1)."""
        prompt = format_detailed(
            **{**_BASE_KWARGS, "samples": [_DETAILED_SAMPLE]},
            tls_fingerprints=[_FP_A],
        )
        assert f"{SENTINEL_OPEN}{_FP_A}{SENTINEL_CLOSE}" in prompt

    def test_tls_section_absent_when_none_in_detailed(self) -> None:
        """TLS Fingerprints section absent when tls_fingerprints is None."""
        prompt = format_detailed(
            **{**_BASE_KWARGS, "samples": [_DETAILED_SAMPLE]},
            tls_fingerprints=None,
        )
        assert "TLS Fingerprints" not in prompt

    def test_no_fingerprints_no_regression_in_detailed(self) -> None:
        """Omitting tls_fingerprints entirely matches passing None (no regression)."""
        prompt_no_param = format_detailed(
            **{**_BASE_KWARGS, "samples": [_DETAILED_SAMPLE]}
        )
        prompt_none = format_detailed(
            **{**_BASE_KWARGS, "samples": [_DETAILED_SAMPLE]},
            tls_fingerprints=None,
        )
        assert prompt_no_param == prompt_none
