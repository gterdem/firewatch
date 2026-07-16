"""Tests for OCSF 1.8.0 per-class activity_id resolution (issue #80).

Bug fixed: `_resolve_activity_id` special-cased only HTTP Activity (4002) and
Detection Finding (2004); every other class — including Authentication (3002),
Account Change (3001), and Base Event (0), all live-firing since linux_auth
(#73) and the OCSF class correction (#76/#79) — fell through to Network
Activity's `NETWORK_ACTIVITY_TRAFFIC` (6). That value is schema-valid-but-false
for 3002 ("Preauth"), schema-valid-but-inverted for 3001 ("Delete" instead of
"Create"), and out-of-enum for class 0 (Base Event only defines 0/99).

EARS acceptance criteria → test mapping (1:1):

  AC-1 — WHEN ocsf_class=3002 is exported, activity_id SHALL be 1 (Logon),
         type_uid SHALL be 300201.
         → test_authentication_activity_id_is_logon
         → test_authentication_type_uid

  AC-2 — WHEN ocsf_class=3001 is exported, activity_id SHALL be 1 (Create),
         type_uid SHALL be 300101.
         → test_account_change_activity_id_is_create
         → test_account_change_type_uid

  AC-3 — WHEN ocsf_class=0 is exported, activity_id SHALL be 0 (Unknown),
         type_uid SHALL be 0.
         → test_base_event_activity_id_is_unknown
         → test_base_event_type_uid

  AC-4 — WHEN ocsf_class has no explicit branch, activity_id SHALL be 0
         (Unknown) — never a value borrowed from another class's enum.
         → test_unbranched_class_falls_back_to_unknown_not_traffic

  Must-NOT (regression — correct today, must stay byte-identical):
         → test_http_activity_still_resolves_from_method (4002)
         → test_http_activity_unknown_method_still_zero (4002)
         → test_detection_finding_still_create (2004)
         → test_network_activity_still_traffic_via_explicit_branch (4001)

  Conformance guard (would have caught this bug):
         → test_activity_id_is_member_of_class_enum[...]  (parametrized over
           every ocsf_class value emitted by a shipped normalizer)

RFC-5737 IPs only: 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24.
"""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from firewatch_sdk.models import SecurityEvent

from firewatch_api.ocsf import mapping, serializer

_TS_UTC = datetime(2026, 6, 12, 10, 0, 0, tzinfo=timezone.utc)

# RFC-5737 documentation IPs only (gitleaks public-ipv4 rule enforced by CI).
_HOST_IP = "198.51.100.20"
_WAF_IP = "198.51.100.10"
_SURICATA_IP = "203.0.113.5"

# ---------------------------------------------------------------------------
# Per-class activity_id enums, PINNED FROM THE LIVE OCSF 1.8.0 SCHEMA
# (fetched 2026-07-16 via https://schema.ocsf.io/api/1.8.0/classes/<name>),
# NOT derived from mapping.py / serializer.py. This is the independent oracle
# the conformance-guard test checks the code under test against.
# ---------------------------------------------------------------------------

# https://schema.ocsf.io/api/1.8.0/classes/authentication (class_uid 3002)
_AUTHENTICATION_ENUM: frozenset[int] = frozenset({0, 1, 2, 3, 4, 5, 6, 7, 99})

# https://schema.ocsf.io/api/1.8.0/classes/account_change (class_uid 3001)
_ACCOUNT_CHANGE_ENUM: frozenset[int] = frozenset(
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
)

# https://schema.ocsf.io/api/1.8.0/classes/base_event (class_uid 0)
_BASE_EVENT_ENUM: frozenset[int] = frozenset({0, 99})

# https://schema.ocsf.io/api/1.8.0/classes/network_activity (class_uid 4001)
_NETWORK_ACTIVITY_ENUM: frozenset[int] = frozenset({0, 1, 2, 3, 4, 5, 6, 7, 99})

# https://schema.ocsf.io/api/1.8.0/classes/http_activity (class_uid 4002)
_HTTP_ACTIVITY_ENUM: frozenset[int] = frozenset({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 99})

# https://schema.ocsf.io/api/1.8.0/classes/detection_finding (class_uid 2004)
_DETECTION_FINDING_ENUM: frozenset[int] = frozenset({0, 1, 2, 3, 99})

_CLASS_ENUMS: dict[int, frozenset[int]] = {
    3002: _AUTHENTICATION_ENUM,
    3001: _ACCOUNT_CHANGE_ENUM,
    0: _BASE_EVENT_ENUM,
    4001: _NETWORK_ACTIVITY_ENUM,
    4002: _HTTP_ACTIVITY_ENUM,
    2004: _DETECTION_FINDING_ENUM,
}


def _make_event(
    *,
    ocsf_class: int | None,
    ocsf_category: int | None,
    source_type: str = "linux_auth",
    action: str = "LOG",
    severity: str = "info",
    raw_log: dict | None = None,
) -> SecurityEvent:
    """Build a minimal SecurityEvent carrying the given ocsf_class/category.

    Shape matches what each shipped normalizer sets at normalize-time
    (ADR-0020): linux_auth/syslog/syslog_cef emit 3002/3001/0; azure_waf emits
    4002; suricata emits 4001/2004.
    """
    return SecurityEvent(
        source_type=source_type,
        source_id="host-01",
        timestamp=_TS_UTC,
        source_ip=_HOST_IP,
        action=action,  # type: ignore[arg-type]
        severity=severity,  # type: ignore[arg-type]
        ocsf_class=ocsf_class,
        ocsf_category=ocsf_category,
        raw_log=raw_log,
    )


# ---------------------------------------------------------------------------
# AC-1: Authentication (3002) → activity_id=1 (Logon), type_uid=300201
# ---------------------------------------------------------------------------


class TestAuthenticationActivityId:
    """class_uid=3002 (linux_auth sshd/PAM/sudo, syslog, syslog_cef)."""

    def test_authentication_activity_id_is_logon(self) -> None:
        """sshd login failure exports as Logon (1), not Preauth (6).

        Source: https://schema.ocsf.io/api/1.8.0/classes/authentication
        activity_id 1 = "Logon" ("A new logon session was requested.").
        Success/failure is status_id (ADR-0071 D2, #77), not activity_id —
        so a FAILED auth attempt is still activity_id=1.
        """
        ev = _make_event(ocsf_class=3002, ocsf_category=3, action="ALERT", severity="low")
        result = serializer.event_to_ocsf(ev)
        assert result["class_uid"] == 3002
        assert result["activity_id"] == 1

    def test_authentication_type_uid(self) -> None:
        """type_uid = 3002 * 100 + 1 = 300201."""
        ev = _make_event(ocsf_class=3002, ocsf_category=3)
        result = serializer.event_to_ocsf(ev)
        assert result["type_uid"] == 300201

    def test_authentication_activity_id_is_logon_on_success(self) -> None:
        """sshd login SUCCESS also exports Logon (1) — activity is the same
        regardless of outcome; outcome belongs to status_id, not activity_id."""
        ev = _make_event(ocsf_class=3002, ocsf_category=3, action="LOG", severity="info")
        result = serializer.event_to_ocsf(ev)
        assert result["activity_id"] == 1


# ---------------------------------------------------------------------------
# AC-2: Account Change (3001) → activity_id=1 (Create), type_uid=300101
# ---------------------------------------------------------------------------


class TestAccountChangeActivityId:
    """class_uid=3001 (linux_auth useradd_new_user)."""

    def test_account_change_activity_id_is_create(self) -> None:
        """useradd_new_user exports as Create (1), not Delete (6).

        Source: https://schema.ocsf.io/api/1.8.0/classes/account_change
        activity_id 1 = "Create" ("A user/role was created."); 6 = "Delete"
        ("A user/role was deleted.") — the pre-fix bug inverted this.
        """
        ev = _make_event(ocsf_class=3001, ocsf_category=3, action="LOG", severity="medium")
        result = serializer.event_to_ocsf(ev)
        assert result["class_uid"] == 3001
        assert result["activity_id"] == 1

    def test_account_change_type_uid(self) -> None:
        """type_uid = 3001 * 100 + 1 = 300101."""
        ev = _make_event(ocsf_class=3001, ocsf_category=3)
        result = serializer.event_to_ocsf(ev)
        assert result["type_uid"] == 300101


# ---------------------------------------------------------------------------
# AC-3: Base Event (0) → activity_id=0 (Unknown), type_uid=0
# ---------------------------------------------------------------------------


class TestBaseEventActivityId:
    """class_uid=0 (linux_auth/syslog/syslog_cef unclassified-line fallback)."""

    def test_base_event_activity_id_is_unknown(self) -> None:
        """Unclassified fallback row exports activity_id=0 (Unknown), not 6.

        Source: https://schema.ocsf.io/api/1.8.0/classes/base_event —
        activity_id enum is ONLY {0 Unknown, 99 Other}; 6 is out-of-enum for
        this class.
        """
        ev = _make_event(ocsf_class=0, ocsf_category=0, action="LOG", severity="low")
        result = serializer.event_to_ocsf(ev)
        assert result["class_uid"] == 0
        assert result["activity_id"] == 0

    def test_base_event_type_uid(self) -> None:
        """type_uid = 0 * 100 + 0 = 0 ("Base Event: Unknown")."""
        ev = _make_event(ocsf_class=0, ocsf_category=0)
        result = serializer.event_to_ocsf(ev)
        assert result["type_uid"] == 0


# ---------------------------------------------------------------------------
# AC-4: No explicit branch → activity_id=0 (Unknown), never borrowed
# ---------------------------------------------------------------------------


class TestUnbranchedClassFallback:
    def test_unbranched_class_falls_back_to_unknown_not_traffic(self) -> None:
        """An ocsf_class with no explicit branch (e.g. a future/unmapped
        class) SHALL get activity_id=0 (Unknown) — 0 is valid in EVERY OCSF
        class's activity_id enum — never Network Activity's 6 (Traffic),
        which is meaningless (or false) outside class_uid 4001.
        """
        ev = _make_event(ocsf_class=9999, ocsf_category=0)
        result = serializer.event_to_ocsf(ev)
        assert result["class_uid"] == 9999
        assert result["activity_id"] == 0
        assert result["activity_id"] != mapping.NETWORK_ACTIVITY_TRAFFIC


# ---------------------------------------------------------------------------
# Must-NOT: existing correct behavior stays byte-identical
# ---------------------------------------------------------------------------


class TestMustNotRegress:
    def test_http_activity_still_resolves_from_method(self) -> None:
        """4002 HTTP Activity: activity_id still resolved from HTTP method."""
        ev = _make_event(
            ocsf_class=4002,
            ocsf_category=4,
            source_type="azure_waf",
            action="BLOCK",
            severity="high",
            raw_log={"properties": {"httpMethod": "GET"}},
        )
        result = serializer.event_to_ocsf(ev)
        assert result["activity_id"] == 3  # GET
        assert result["type_uid"] == 400203

    def test_http_activity_unknown_method_still_zero(self) -> None:
        """4002 with no resolvable HTTP method → activity_id=0 (unchanged)."""
        ev = _make_event(
            ocsf_class=4002, ocsf_category=4, source_type="azure_waf", raw_log={}
        )
        result = serializer.event_to_ocsf(ev)
        assert result["activity_id"] == 0

    def test_detection_finding_still_create(self) -> None:
        """2004 Detection Finding: activity_id=1, type_uid=200401 (unchanged)."""
        ev = _make_event(
            ocsf_class=2004, ocsf_category=2, source_type="suricata", action="ALERT"
        )
        result = serializer.event_to_ocsf(ev)
        assert result["activity_id"] == 1
        assert result["type_uid"] == 200401

    def test_network_activity_still_traffic_via_explicit_branch(self) -> None:
        """4001 Network Activity: activity_id=6 (Traffic), via an explicit
        branch — not the (now-removed) fallthrough."""
        ev = _make_event(
            ocsf_class=4001, ocsf_category=4, source_type="suricata", action="ALERT"
        )
        result = serializer.event_to_ocsf(ev)
        assert result["activity_id"] == 6
        assert result["type_uid"] == 400106


# ---------------------------------------------------------------------------
# Conformance guard — would have caught this bug, and the next one
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ocsf_class", sorted(_CLASS_ENUMS))
def test_activity_id_is_member_of_class_enum(ocsf_class: int) -> None:
    """For every ocsf_class value emitted by a shipped normalizer, the
    resolved activity_id MUST be a member of THAT class's OCSF 1.8.0
    activity_id enum — pinned above from the live schema, independent of the
    code under test. This is what the old identity-only assertion
    (`type_uid == class_uid*100 + activity_id`, true by construction) could
    never detect.
    """
    ev = _make_event(ocsf_class=ocsf_class, ocsf_category=0)
    result = serializer.event_to_ocsf(ev)
    allowed = _CLASS_ENUMS[ocsf_class]
    assert result["activity_id"] in allowed, (
        f"class_uid={ocsf_class}: activity_id={result['activity_id']} is not in "
        f"the OCSF 1.8.0 enum {sorted(allowed)}"
    )
