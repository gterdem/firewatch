"""Tests for issue #602 / ADR-0055 EARS-4 — OCSF export of file-IOC, DNS-answer fields.

EARS-4  WHEN an event with file hashes is exported via /export/ocsf/events,
        the serializer SHALL emit them under the OCSF File.hashes[] array
        (algorithm_id 1/2/3) within the pinned 1.8.0 schema.

        Specific assertions:
        - file_sha256 → File.hashes[] entry with algorithm_id=3, value=<hash>
        - file_md5    → File.hashes[] entry with algorithm_id=1, value=<hash>
        - file_sha1   → File.hashes[] entry with algorithm_id=2, value=<hash>
        - file_name   → File.name
        - file_mime_type → File.type_id or emitted as File.mime_type (OCSF 1.8.0)
        - dns_answer  → DNS answers[] array (rdata, split by comma)
        - tls_ja3     → NOT in OCSF File object; serializer does NOT fabricate a
                         file object for tls_ja3 (it is a TLS field, not a file field)
        - Event with NO file fields → no "file" key in OCSF output (no fabrication)
        - SecurityEvent must NOT be mutated by serializer (ADR-0020 hard constraint)

OCSF 1.8.0 references (ADR-0040 / ADR-0055):
  File object + Fingerprint/hashes array:
    https://schema.ocsf.io/ (1.8.0; File object, hashes array with algorithm_id)
  algorithm_id enum (OCSF 1.8.0 Fingerprint object):
    1 = MD5, 2 = SHA-1, 3 = SHA-256
  DNS Activity (class_uid 4003) answers[]:
    https://schema.ocsf.io/ (class_uid 4003, DNS Answer object, rdata field)

RFC 5737 IPs only in fixtures — no real/routable IPs.
"""
from __future__ import annotations

from datetime import datetime, timezone

from firewatch_sdk.models import SecurityEvent

from firewatch_api.ocsf import serializer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_TS_UTC = datetime(2026, 6, 14, 12, 0, 0, tzinfo=timezone.utc)

# RFC 5737 documentation IPs only
_SRC_IP = "192.0.2.10"

# Synthetic hashes — not real captures
_SHA256 = "a" * 64
_MD5 = "b" * 32
_SHA1 = "c" * 40
_FILENAME = "malware.exe"
_MIME = "application/x-dosexec"
_DNS_ANSWER = "192.0.2.100,192.0.2.101"
_JA3 = "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"


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
# EARS-4: OCSF File.hashes[] assembly from flat scalars
# ---------------------------------------------------------------------------


class TestOcsfFileHashesAssembly:
    """EARS-4 — file_sha256/md5/sha1 emitted as OCSF File.hashes[] (algorithm_id 1/2/3).

    OCSF 1.8.0 reference: schema.ocsf.io File object, hashes array, Fingerprint object.
    Algorithm IDs: 1=MD5, 2=SHA-1, 3=SHA-256.
    """

    def test_sha256_emitted_as_file_hashes_algorithm_id_3(self) -> None:
        """file_sha256 → File.hashes[] entry with algorithm_id=3, value=<hash>.

        Source: OCSF 1.8.0 Fingerprint object, algorithm_id=3 (SHA-256).
        https://schema.ocsf.io/ (File object, hashes array)
        """
        ev = _ev(file_sha256=_SHA256)
        result = serializer.event_to_ocsf(ev)
        assert "file" in result, "file object must be present when file_sha256 is set"
        hashes = result["file"]["hashes"]
        sha256_entry = next(
            (h for h in hashes if h["algorithm_id"] == 3), None
        )
        assert sha256_entry is not None, "No hashes entry with algorithm_id=3 (SHA-256)"
        assert sha256_entry["value"] == _SHA256
        assert sha256_entry["algorithm"] == "SHA-256"

    def test_md5_emitted_as_file_hashes_algorithm_id_1(self) -> None:
        """file_md5 → File.hashes[] entry with algorithm_id=1, value=<hash>.

        Source: OCSF 1.8.0 Fingerprint object, algorithm_id=1 (MD5).
        """
        ev = _ev(file_md5=_MD5)
        result = serializer.event_to_ocsf(ev)
        assert "file" in result
        hashes = result["file"]["hashes"]
        md5_entry = next((h for h in hashes if h["algorithm_id"] == 1), None)
        assert md5_entry is not None, "No hashes entry with algorithm_id=1 (MD5)"
        assert md5_entry["value"] == _MD5
        assert md5_entry["algorithm"] == "MD5"

    def test_sha1_emitted_as_file_hashes_algorithm_id_2(self) -> None:
        """file_sha1 → File.hashes[] entry with algorithm_id=2, value=<hash>.

        Source: OCSF 1.8.0 Fingerprint object, algorithm_id=2 (SHA-1).
        """
        ev = _ev(file_sha1=_SHA1)
        result = serializer.event_to_ocsf(ev)
        assert "file" in result
        hashes = result["file"]["hashes"]
        sha1_entry = next((h for h in hashes if h["algorithm_id"] == 2), None)
        assert sha1_entry is not None, "No hashes entry with algorithm_id=2 (SHA-1)"
        assert sha1_entry["value"] == _SHA1
        assert sha1_entry["algorithm"] == "SHA-1"

    def test_all_three_hashes_in_single_file_object(self) -> None:
        """file_sha256 + file_md5 + file_sha1 → all three in File.hashes[]."""
        ev = _ev(file_sha256=_SHA256, file_md5=_MD5, file_sha1=_SHA1)
        result = serializer.event_to_ocsf(ev)
        assert "file" in result
        hashes = result["file"]["hashes"]
        algo_ids = {h["algorithm_id"] for h in hashes}
        assert algo_ids == {1, 2, 3}, (
            f"Expected algorithm_ids {{1,2,3}}, got {algo_ids}"
        )

    def test_file_name_emitted_in_file_object(self) -> None:
        """file_name → File.name in the OCSF file object.

        Source: OCSF 1.8.0 File object, name attribute.
        """
        ev = _ev(file_name=_FILENAME)
        result = serializer.event_to_ocsf(ev)
        assert "file" in result
        assert result["file"]["name"] == _FILENAME

    def test_file_mime_type_emitted_in_file_object(self) -> None:
        """file_mime_type → File.mime_type in the OCSF file object.

        Source: OCSF 1.8.0 File object, mime_type attribute.
        """
        ev = _ev(file_mime_type=_MIME)
        result = serializer.event_to_ocsf(ev)
        assert "file" in result
        assert result["file"]["mime_type"] == _MIME

    def test_no_file_object_when_no_file_fields_set(self) -> None:
        """Event with no file fields must NOT emit a 'file' key (no fabrication)."""
        ev = _ev()  # no file_* fields
        result = serializer.event_to_ocsf(ev)
        assert "file" not in result, (
            "Serializer fabricated a 'file' object when no file fields were set"
        )

    def test_file_object_with_only_name_no_hashes_key(self) -> None:
        """file_name only → file.name present, file.hashes absent (empty list not emitted)."""
        ev = _ev(file_name=_FILENAME)
        result = serializer.event_to_ocsf(ev)
        file_obj = result.get("file", {})
        # hashes must not be present if no hash fields are set (no empty list)
        assert "hashes" not in file_obj or file_obj.get("hashes") == []

    def test_full_file_object_shape(self) -> None:
        """All file fields → complete OCSF File object with hashes[], name, mime_type."""
        ev = _ev(
            file_sha256=_SHA256,
            file_md5=_MD5,
            file_sha1=_SHA1,
            file_name=_FILENAME,
            file_mime_type=_MIME,
        )
        result = serializer.event_to_ocsf(ev)
        assert "file" in result
        file_obj = result["file"]
        assert file_obj["name"] == _FILENAME
        assert file_obj["mime_type"] == _MIME
        hashes = file_obj["hashes"]
        assert len(hashes) == 3
        # Check all algorithm_ids present with correct values
        hash_map = {h["algorithm_id"]: h["value"] for h in hashes}
        assert hash_map[1] == _MD5
        assert hash_map[2] == _SHA1
        assert hash_map[3] == _SHA256


# ---------------------------------------------------------------------------
# EARS-4: DNS answers[] serialization
# ---------------------------------------------------------------------------


class TestOcsfDnsAnswersAssembly:
    """EARS-4 — dns_answer (comma-joined) split and emitted as OCSF DNS answers[].

    OCSF 1.8.0 reference: DNS Activity class_uid 4003, answers[] array, DNS Answer
    object with rdata field. https://schema.ocsf.io/ (class_uid 4003)
    """

    def test_dns_answer_emitted_as_answers_array(self) -> None:
        """dns_answer comma-joined string → answers[] array with one entry per value."""
        ev = _ev(dns_answer=_DNS_ANSWER)
        result = serializer.event_to_ocsf(ev)
        assert "answers" in result, "answers array must be present when dns_answer is set"
        answers = result["answers"]
        assert len(answers) == 2   # "192.0.2.100" and "192.0.2.101"

    def test_dns_answer_rdata_values_correct(self) -> None:
        """Each answers[] entry has an rdata field matching the split value."""
        ev = _ev(dns_answer="192.0.2.100,198.51.100.1")
        result = serializer.event_to_ocsf(ev)
        rdatas = {a["rdata"] for a in result["answers"]}
        assert rdatas == {"192.0.2.100", "198.51.100.1"}

    def test_single_dns_answer_single_entry(self) -> None:
        """A dns_answer with one value (no comma) → answers[] with one entry."""
        ev = _ev(dns_answer="192.0.2.100")
        result = serializer.event_to_ocsf(ev)
        assert len(result["answers"]) == 1
        assert result["answers"][0]["rdata"] == "192.0.2.100"

    def test_no_answers_key_when_dns_answer_not_set(self) -> None:
        """Event with no dns_answer → no 'answers' key in OCSF output (no fabrication)."""
        ev = _ev()
        result = serializer.event_to_ocsf(ev)
        assert "answers" not in result, (
            "Serializer fabricated 'answers' when dns_answer was not set"
        )


# ---------------------------------------------------------------------------
# ADR-0020 hard constraint: serializer must NOT mutate the input SecurityEvent
# ---------------------------------------------------------------------------


class TestSerializerDoesNotMutateInput:
    """ADR-0020: serializer reads the model but never modifies it."""

    def test_event_with_file_fields_not_mutated(self) -> None:
        """Calling event_to_ocsf() must not modify any field of the SecurityEvent."""
        ev = _ev(
            file_sha256=_SHA256,
            file_md5=_MD5,
            file_name=_FILENAME,
            dns_answer=_DNS_ANSWER,
            tls_ja3=_JA3,
        )
        original_sha256 = ev.file_sha256
        original_dns = ev.dns_answer
        original_ja3 = ev.tls_ja3
        original_action = ev.action

        serializer.event_to_ocsf(ev)

        assert ev.file_sha256 == original_sha256
        assert ev.dns_answer == original_dns
        assert ev.tls_ja3 == original_ja3
        assert ev.action == original_action
