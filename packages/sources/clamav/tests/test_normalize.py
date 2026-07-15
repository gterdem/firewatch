"""Golden normalization tests — ClamAV FOUND-detection RawEvent → SecurityEvent.

Mapped 1:1 to issue #2's acceptance criteria:

AC2  normalize() emits category="malware", severity="high", the signature as
     rule_name/rule_id, the file path in payload_snippet, action mapped honestly
     (detect-only → ALERT; a companion remove/quarantine outcome → BLOCK), and
     MITRE technique/tactic where derivable (here: nowhere — left None, never
     fabricated).
AC3  EICAR-style fixture: category=malware + severity=high is the load-bearing pair
     the severity gate (ADR-0067 D1b/D4) consumes to escalate to Tier 2 — this
     package's contribution stops at emitting an honest SecurityEvent; escalation
     itself is core's concern.
AC4  Golden fixtures pinned here are additive; no existing golden expectation
     (other packages' tests) is touched.

Fixture shape mirrors exactly what firewatch_clamav.collector builds:
``{"path": str, "signature": str, "outcome": "removed" | "moved" | None}``.
"""
from __future__ import annotations

from datetime import datetime, timezone

from firewatch_sdk import RawEvent
from firewatch_clamav.normalize import normalize

_RECEIVED_AT = datetime(2026, 7, 15, 12, 0, 0, tzinfo=timezone.utc)


def _raw(path: str, signature: str, outcome: str | None = None) -> RawEvent:
    return RawEvent(
        source_type="clamav",
        received_at=_RECEIVED_AT,
        data={"path": path, "signature": signature, "outcome": outcome},
    )


class TestGoldenDetectOnly:
    """EICAR-style detect-only FOUND line (no on-access remove/quarantine configured)."""

    def setup_method(self) -> None:
        self.raw = _raw("/home/user/eicar.com", "Win.Test.EICAR_HDB-1")
        self.event = normalize(self.raw, "laptop")

    def test_action_is_alert(self) -> None:
        assert self.event.action == "ALERT"

    def test_category_is_malware(self) -> None:
        assert self.event.category == "malware"

    def test_severity_is_high(self) -> None:
        """ADR-0067 D4 / ADR-0069 — load-bearing for the severity-gate escalation."""
        assert self.event.severity == "high"

    def test_rule_name_is_signature(self) -> None:
        assert self.event.rule_name == "Win.Test.EICAR_HDB-1"

    def test_rule_id_is_also_signature(self) -> None:
        """ClamAV has no separate numeric ID — the signature IS the identifier."""
        assert self.event.rule_id == "Win.Test.EICAR_HDB-1"

    def test_payload_snippet_is_file_path(self) -> None:
        assert self.event.payload_snippet == "/home/user/eicar.com"

    def test_file_name_is_basename(self) -> None:
        assert self.event.file_name == "eicar.com"

    def test_source_ip_is_empty_not_fabricated(self) -> None:
        """Host-based detection: no network source IP exists — never invented."""
        assert self.event.source_ip == ""

    def test_ocsf_detection_finding(self) -> None:
        """OCSF class_uid 2004 (Detection Finding) / category_uid 2 (Findings).

        https://schema.ocsf.io/1.8.0/classes/detection_finding — matches the same
        class firewatch_aws_nfw's Suricata-derived alerts anchor to.
        """
        assert self.event.ocsf_class == 2004
        assert self.event.ocsf_category == 2

    def test_mitre_fields_left_none_not_fabricated(self) -> None:
        """ADR-0014 extracts MITRE from source-specific metadata; ClamAV signature
        names carry none — nothing here is fabricated."""
        assert self.event.attack_technique is None
        assert self.event.attack_tactic is None
        assert self.event.kill_chain_phase is None
        assert self.event.capec_id is None

    def test_raw_log_preserves_full_data(self) -> None:
        assert self.event.raw_log == self.raw.data

    def test_timestamp_from_received_at(self) -> None:
        assert self.event.timestamp == _RECEIVED_AT


class TestGoldenRemovedOutcome:
    """A configured --remove outcome observed in the log stream → BLOCK."""

    def setup_method(self) -> None:
        self.raw = _raw("/tmp/malware.exe", "Win.Trojan.Generic-1", outcome="removed")
        self.event = normalize(self.raw, "laptop")

    def test_action_is_block(self) -> None:
        assert self.event.action == "BLOCK"

    def test_severity_still_high(self) -> None:
        assert self.event.severity == "high"

    def test_category_still_malware(self) -> None:
        assert self.event.category == "malware"


class TestGoldenMovedOutcome:
    """A configured --move=DIRECTORY outcome observed in the log stream → BLOCK."""

    def setup_method(self) -> None:
        self.raw = _raw("/tmp/malware.exe", "Win.Trojan.Generic-1", outcome="moved")
        self.event = normalize(self.raw, "laptop")

    def test_action_is_block(self) -> None:
        assert self.event.action == "BLOCK"


class TestSourceIdentity:
    """ADR-0016 / Flag B — source_type is the plugin's constant; source_id passes
    through untouched and is never branched on."""

    def test_source_type_is_constant_clamav(self) -> None:
        event = normalize(_raw("/a", "Sig-1"), "any-instance-name")
        assert event.source_type == "clamav"

    def test_source_id_passes_through(self) -> None:
        event = normalize(_raw("/a", "Sig-1"), "desktop-01")
        assert event.source_id == "desktop-01"

    def test_normalize_result_identical_across_source_ids_except_identity(self) -> None:
        """Flag B: normalize() must not branch on source_id for detection logic."""
        raw = _raw("/a", "Sig-1")
        event_a = normalize(raw, "instance-a")
        event_b = normalize(raw, "instance-b")

        a = event_a.model_dump(exclude={"source_id"})
        b = event_b.model_dump(exclude={"source_id"})
        assert a == b


class TestEmptyOrMissingFields:
    """Defensive mapping when collector-supplied fields are missing/blank."""

    def test_missing_path_leaves_payload_snippet_and_file_name_none(self) -> None:
        raw = RawEvent(
            source_type="clamav",
            received_at=_RECEIVED_AT,
            data={"path": "", "signature": "Sig-1", "outcome": None},
        )
        event = normalize(raw, "laptop")
        assert event.payload_snippet is None
        assert event.file_name is None

    def test_missing_signature_leaves_rule_fields_none(self) -> None:
        raw = RawEvent(
            source_type="clamav",
            received_at=_RECEIVED_AT,
            data={"path": "/a", "signature": "", "outcome": None},
        )
        event = normalize(raw, "laptop")
        assert event.rule_id is None
        assert event.rule_name is None
