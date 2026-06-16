"""Tests for issue #643 — OCSF serializer hardening caps (non-blocking security items).

EARS criteria covered:

  CAP-1  WHEN an adversarial source emits an oversized file hash value,
         _build_ocsf_file_object SHALL cap each hash to its natural digest
         length (SHA-256 → 64, MD5 → 32, SHA-1 → 40 hex chars) so unbounded
         strings cannot enter the authenticated OCSF export.

  CAP-2  WHEN an adversarial source emits an oversized file_name or
         file_mime_type, _build_ocsf_file_object SHALL cap both to 255 chars,
         matching the existing ``payload_snippet[:200]`` boundary pattern
         (security boundary precedent, issue #639).

  CAP-3  WHEN a SecurityEvent's dns_answer contains more than 50 comma-separated
         entries, event_to_ocsf SHALL emit at most 50 entries in answers[]
         (entry-count cap, defence-in-depth against excessively large exports).

  CAP-4  WHEN a SecurityEvent's dns_answer contains individual rdata values
         longer than 253 bytes, event_to_ocsf SHALL truncate each to 253 chars
         (RFC 1035 §3.1: a full domain name must not exceed 253 characters in
         presentation format — 255 wire-format octets minus two length bytes
         for the root label; we use 253 as the per-rdata cap).

  CAP-5  WHEN file hash, file_name or file_mime_type values are within the legal
         limits, the serializer SHALL emit the full value unchanged (no false
         truncation).

All IPs use RFC 5737 / RFC 1918 documentation ranges — no real/routable IPs.
"""
from __future__ import annotations

from datetime import datetime, timezone

from firewatch_sdk.models import SecurityEvent

from firewatch_api.ocsf import serializer
from firewatch_api.ocsf.serializer import _build_ocsf_file_object


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TS_UTC = datetime(2026, 6, 14, 12, 0, 0, tzinfo=timezone.utc)

# RFC 5737 documentation IP
_SRC_IP = "192.0.2.10"


def _ev(**kwargs) -> SecurityEvent:  # type: ignore[no-untyped-def]
    """Minimal SecurityEvent with RFC 5737 source IP."""
    return SecurityEvent(
        source_type="suricata",
        source_id="sensor-01",
        timestamp=_TS_UTC,
        source_ip=_SRC_IP,
        action="ALERT",  # type: ignore[arg-type]
        ocsf_class=4001,
        ocsf_category=4,
        **kwargs,
    )


# ---------------------------------------------------------------------------
# CAP-1 — Hash value caps (natural digest lengths)
# ---------------------------------------------------------------------------


class TestFileHashValueCaps:
    """CAP-1 — adversarial oversized hash values are capped to natural digest lengths.

    Natural digest lengths (hex chars):
      SHA-256 → 64  (256 bits / 4 bits per hex char)
      MD5     → 32  (128 bits / 4)
      SHA-1   → 40  (160 bits / 4)

    Capping at natural length is safe: a valid hash is exactly that length;
    an adversarial value is truncated to be indistinguishable from a valid one.
    """

    def test_sha256_oversized_is_capped_to_64(self) -> None:
        """An oversized file_sha256 value (>64 chars) is capped to 64 chars.

        SHA-256 hex digest is always 64 chars (256-bit / 4 bits-per-hex-char).
        An adversarial value longer than 64 chars is truncated at the boundary.
        """
        oversized = "a" * 200  # well beyond 64 chars
        ev = _ev(file_sha256=oversized)
        file_obj = _build_ocsf_file_object(ev)
        assert file_obj is not None
        sha256_entry = next(
            (h for h in file_obj["hashes"] if h["algorithm_id"] == 3), None
        )
        assert sha256_entry is not None
        assert len(sha256_entry["value"]) == 64, (
            f"SHA-256 hash must be capped to 64 chars; got {len(sha256_entry['value'])}"
        )

    def test_md5_oversized_is_capped_to_32(self) -> None:
        """An oversized file_md5 value (>32 chars) is capped to 32 chars.

        MD5 hex digest is always 32 chars (128-bit / 4 bits-per-hex-char).
        """
        oversized = "b" * 200
        ev = _ev(file_md5=oversized)
        file_obj = _build_ocsf_file_object(ev)
        assert file_obj is not None
        md5_entry = next(
            (h for h in file_obj["hashes"] if h["algorithm_id"] == 1), None
        )
        assert md5_entry is not None
        assert len(md5_entry["value"]) == 32, (
            f"MD5 hash must be capped to 32 chars; got {len(md5_entry['value'])}"
        )

    def test_sha1_oversized_is_capped_to_40(self) -> None:
        """An oversized file_sha1 value (>40 chars) is capped to 40 chars.

        SHA-1 hex digest is always 40 chars (160-bit / 4 bits-per-hex-char).
        """
        oversized = "c" * 200
        ev = _ev(file_sha1=oversized)
        file_obj = _build_ocsf_file_object(ev)
        assert file_obj is not None
        sha1_entry = next(
            (h for h in file_obj["hashes"] if h["algorithm_id"] == 2), None
        )
        assert sha1_entry is not None
        assert len(sha1_entry["value"]) == 40, (
            f"SHA-1 hash must be capped to 40 chars; got {len(sha1_entry['value'])}"
        )

    def test_sha256_at_natural_length_passes_through_unchanged(self) -> None:
        """A valid-length SHA-256 (64 chars) is emitted unchanged (no false truncation).

        CAP-5: values within legal limits must be emitted in full.
        """
        valid = "d" * 64
        ev = _ev(file_sha256=valid)
        file_obj = _build_ocsf_file_object(ev)
        assert file_obj is not None
        sha256_entry = next(
            (h for h in file_obj["hashes"] if h["algorithm_id"] == 3), None
        )
        assert sha256_entry is not None
        assert sha256_entry["value"] == valid

    def test_md5_at_natural_length_passes_through_unchanged(self) -> None:
        """A valid-length MD5 (32 chars) is emitted unchanged (CAP-5)."""
        valid = "e" * 32
        ev = _ev(file_md5=valid)
        file_obj = _build_ocsf_file_object(ev)
        assert file_obj is not None
        md5_entry = next(
            (h for h in file_obj["hashes"] if h["algorithm_id"] == 1), None
        )
        assert md5_entry is not None
        assert md5_entry["value"] == valid

    def test_sha1_at_natural_length_passes_through_unchanged(self) -> None:
        """A valid-length SHA-1 (40 chars) is emitted unchanged (CAP-5)."""
        valid = "f" * 40
        ev = _ev(file_sha1=valid)
        file_obj = _build_ocsf_file_object(ev)
        assert file_obj is not None
        sha1_entry = next(
            (h for h in file_obj["hashes"] if h["algorithm_id"] == 2), None
        )
        assert sha1_entry is not None
        assert sha1_entry["value"] == valid


# ---------------------------------------------------------------------------
# CAP-2 — file_name and file_mime_type caps (255 chars)
# ---------------------------------------------------------------------------


class TestFileNameMimeCaps:
    """CAP-2 — adversarial oversized file_name/file_mime_type capped at 255 chars.

    255 chars matches the POSIX NAME_MAX limit for filename length and the
    IANA media-type practical maximum, following the existing
    ``payload_snippet[:200]`` boundary-cap pattern (issue #639 precedent).
    """

    def test_file_name_oversized_is_capped_to_255(self) -> None:
        """Oversized file_name (>255 chars) is truncated to 255 in the OCSF output."""
        oversized = "X" * 500
        ev = _ev(file_name=oversized)
        file_obj = _build_ocsf_file_object(ev)
        assert file_obj is not None
        assert len(file_obj["name"]) == 255, (
            f"file_name must be capped to 255 chars; got {len(file_obj['name'])}"
        )

    def test_file_mime_type_oversized_is_capped_to_255(self) -> None:
        """Oversized file_mime_type (>255 chars) is truncated to 255 in the OCSF output."""
        oversized = "Y" * 500
        ev = _ev(file_mime_type=oversized)
        file_obj = _build_ocsf_file_object(ev)
        assert file_obj is not None
        assert len(file_obj["mime_type"]) == 255, (
            f"file_mime_type must be capped to 255 chars; got {len(file_obj['mime_type'])}"
        )

    def test_file_name_within_255_passes_through_unchanged(self) -> None:
        """A file_name <= 255 chars is emitted unchanged (CAP-5: no false truncation)."""
        short = "malware.exe"
        ev = _ev(file_name=short)
        file_obj = _build_ocsf_file_object(ev)
        assert file_obj is not None
        assert file_obj["name"] == short

    def test_file_mime_type_within_255_passes_through_unchanged(self) -> None:
        """A file_mime_type <= 255 chars is emitted unchanged (CAP-5)."""
        mime = "application/x-dosexec"
        ev = _ev(file_mime_type=mime)
        file_obj = _build_ocsf_file_object(ev)
        assert file_obj is not None
        assert file_obj["mime_type"] == mime

    def test_file_name_exactly_255_passes_through_unchanged(self) -> None:
        """A file_name of exactly 255 chars is emitted unchanged (boundary case)."""
        exact = "A" * 255
        ev = _ev(file_name=exact)
        file_obj = _build_ocsf_file_object(ev)
        assert file_obj is not None
        assert file_obj["name"] == exact


# ---------------------------------------------------------------------------
# CAP-3 — dns_answer entry count cap ([:50])
# ---------------------------------------------------------------------------


class TestDnsAnswerEntryCountCap:
    """CAP-3 — answers[] entry count capped at 50.

    A comma-joined dns_answer with more than 50 entries is truncated to 50
    in the OCSF output. This bounds the response size for adversarial inputs.
    """

    def test_51_dns_entries_capped_to_50(self) -> None:
        """A dns_answer with 51 entries emits exactly 50 answers[] entries."""
        # Use RFC 1918 IPs; format as sequential last-octet
        entries = [f"10.0.0.{i}" for i in range(1, 52)]  # 51 entries
        dns_answer = ",".join(entries)
        ev = _ev(dns_answer=dns_answer)
        result = serializer.event_to_ocsf(ev)
        assert "answers" in result
        assert len(result["answers"]) == 50, (
            f"Expected 50 answers entries; got {len(result['answers'])}"
        )

    def test_100_dns_entries_capped_to_50(self) -> None:
        """A dns_answer with 100 entries is also capped at 50."""
        entries = [f"10.0.1.{i % 256}" for i in range(100)]
        dns_answer = ",".join(entries)
        ev = _ev(dns_answer=dns_answer)
        result = serializer.event_to_ocsf(ev)
        assert len(result["answers"]) == 50

    def test_50_dns_entries_passes_through_unchanged(self) -> None:
        """Exactly 50 entries are emitted in full (no truncation at the boundary)."""
        entries = [f"10.0.2.{i}" for i in range(1, 51)]  # exactly 50
        dns_answer = ",".join(entries)
        ev = _ev(dns_answer=dns_answer)
        result = serializer.event_to_ocsf(ev)
        assert len(result["answers"]) == 50

    def test_5_dns_entries_all_emitted(self) -> None:
        """Fewer than 50 entries are all emitted (CAP-5: no false truncation)."""
        entries = ["192.0.2.1", "192.0.2.2", "192.0.2.3"]
        ev = _ev(dns_answer=",".join(entries))
        result = serializer.event_to_ocsf(ev)
        assert len(result["answers"]) == 3
        rdatas = {a["rdata"] for a in result["answers"]}
        assert rdatas == {"192.0.2.1", "192.0.2.2", "192.0.2.3"}


# ---------------------------------------------------------------------------
# CAP-4 — dns_answer per-rdata length cap ([:253], RFC 1035)
# ---------------------------------------------------------------------------


class TestDnsAnswerRdataLengthCap:
    """CAP-4 — each rdata value in answers[] is capped at 253 chars.

    RFC 1035 §3.1: a full domain name must not exceed 255 octets in wire
    format. The practical presentation-format limit is 253 chars (255 minus
    the two length bytes for the root label). We cap each rdata at 253 chars
    to match this standard limit.
    Source: RFC 1035 §3.1, §3.3.
    """

    def test_oversized_rdata_capped_to_253(self) -> None:
        """An rdata value longer than 253 chars is truncated to 253."""
        long_rdata = "a" * 300  # beyond RFC 1035 limit
        ev = _ev(dns_answer=long_rdata)
        result = serializer.event_to_ocsf(ev)
        assert "answers" in result
        assert len(result["answers"]) == 1
        assert len(result["answers"][0]["rdata"]) == 253, (
            f"Oversized rdata must be capped to 253; got {len(result['answers'][0]['rdata'])}"
        )

    def test_multiple_oversized_rdatas_each_capped(self) -> None:
        """Each oversized rdata in a multi-entry answer is individually capped to 253."""
        long_rdata = "b" * 300
        dns_answer = f"{long_rdata},{long_rdata}"
        ev = _ev(dns_answer=dns_answer)
        result = serializer.event_to_ocsf(ev)
        for entry in result["answers"]:
            assert len(entry["rdata"]) == 253, (
                f"Each rdata must be capped to 253; got {len(entry['rdata'])}"
            )

    def test_rdata_within_253_passes_through_unchanged(self) -> None:
        """An rdata value <= 253 chars is emitted unchanged (CAP-5)."""
        valid_domain = "www.example.com"  # well within 253 chars
        ev = _ev(dns_answer=valid_domain)
        result = serializer.event_to_ocsf(ev)
        assert result["answers"][0]["rdata"] == valid_domain

    def test_rdata_exactly_253_passes_through_unchanged(self) -> None:
        """An rdata value of exactly 253 chars is emitted unchanged (boundary case)."""
        exact = "x" * 253
        ev = _ev(dns_answer=exact)
        result = serializer.event_to_ocsf(ev)
        assert result["answers"][0]["rdata"] == exact

    def test_combined_count_and_length_caps(self) -> None:
        """Both caps apply simultaneously: 60 entries of 300-char rdatas → 50 entries of 253 chars."""
        long_rdata = "z" * 300
        # 60 entries, each oversized
        dns_answer = ",".join([long_rdata] * 60)
        ev = _ev(dns_answer=dns_answer)
        result = serializer.event_to_ocsf(ev)
        # Entry count capped at 50
        assert len(result["answers"]) == 50
        # Each rdata capped at 253
        for entry in result["answers"]:
            assert len(entry["rdata"]) == 253


# ---------------------------------------------------------------------------
# Regression guard: existing valid inputs unchanged after hardening
# ---------------------------------------------------------------------------


class TestHardeningRegressionGuard:
    """Ensure hardening caps do NOT change the serializer output for valid inputs."""

    def test_normal_file_object_shape_unchanged(self) -> None:
        """Valid file fields (all within limits) produce the same output as before hardening."""
        ev = _ev(
            file_sha256="a" * 64,
            file_md5="b" * 32,
            file_sha1="c" * 40,
            file_name="malware.exe",
            file_mime_type="application/x-dosexec",
        )
        result = serializer.event_to_ocsf(ev)
        assert "file" in result
        file_obj = result["file"]
        assert file_obj["name"] == "malware.exe"
        assert file_obj["mime_type"] == "application/x-dosexec"
        hashes = {h["algorithm_id"]: h["value"] for h in file_obj["hashes"]}
        assert hashes[1] == "b" * 32
        assert hashes[2] == "c" * 40
        assert hashes[3] == "a" * 64

    def test_normal_dns_answers_unchanged(self) -> None:
        """A valid dns_answer (<=50 entries, each <=253 chars) produces unchanged output."""
        # Two RFC 5737 IPs (far below both caps)
        ev = _ev(dns_answer="192.0.2.100,192.0.2.101")
        result = serializer.event_to_ocsf(ev)
        rdatas = [a["rdata"] for a in result["answers"]]
        assert rdatas == ["192.0.2.100", "192.0.2.101"]

    def test_serializer_does_not_mutate_event(self) -> None:
        """Hardening caps must not mutate the original SecurityEvent (ADR-0020)."""
        long_sha256 = "a" * 200
        long_dns = ",".join(["192.0.2.1"] * 100)
        ev = _ev(file_sha256=long_sha256, dns_answer=long_dns)
        original_sha256 = ev.file_sha256
        original_dns = ev.dns_answer
        serializer.event_to_ocsf(ev)
        assert ev.file_sha256 == original_sha256, "file_sha256 must not be mutated"
        assert ev.dns_answer == original_dns, "dns_answer must not be mutated"
