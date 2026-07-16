"""Golden normalization tests — sample auth lines (multi-distro / journald) →
pinned expected SecurityEvent fields (issue #3 EARS: golden fixtures).

Fixture IPs are RFC 5737 documentation ranges (203.0.113.0/24, 198.51.100.0/24)
— never real/routable IPs (testing-conventions skill).
"""
from datetime import datetime, timezone

from firewatch_sdk import RawEvent

from firewatch_linux_auth.normalize import normalize

_RECEIVED_AT = datetime(2026, 6, 15, 8, 0, 0, tzinfo=timezone.utc)
_SOURCE_ID = "workstation-1"


def _raw(message: str, timestamp: str | None = None, reader: str = "file") -> RawEvent:
    data: dict[str, object] = {"message": message, "reader": reader}
    if timestamp is not None:
        data["timestamp"] = timestamp
    return RawEvent(source_type="linux_auth", received_at=_RECEIVED_AT, data=data)


class TestSshLoginFailureGolden:
    """AC2/ADR-0069 D4(e): sshd failed password/publickey →
    SecurityEvent(action=ALERT, severity=low, ...). Corrected 2026-07-15 from
    action=LOG: ADR-0070 D1's hostile-attempt predicate counts ALERT, never
    LOG; severity=low (not high/critical) means this alone never qualifies
    the ADR-0067 D1(b) gate — escalation rides the burst correlation only."""

    def test_debian_auth_log_style(self):
        raw = _raw(
            "Jun 15 08:00:00 host sshd[1234]: Failed password for admin "
            "from 203.0.113.5 port 51234 ssh2",
        )
        event = normalize(raw, _SOURCE_ID)

        assert event.source_type == "linux_auth"
        assert event.source_id == _SOURCE_ID
        assert event.source_ip == "203.0.113.5"
        assert event.action == "ALERT"
        assert event.category == "SSH Login Failure"
        assert event.rule_id == "sshd_login_failure"
        assert event.severity == "low"
        assert event.attack_technique == "T1110"
        assert event.attack_tactic == "TA0006"
        assert event.kill_chain_phase == "credential-access"
        # Authentication (OCSF 1.8.0), not Network Activity — PR #73 held
        # batch correction (was wrongly 4001/4).
        assert event.ocsf_class == 3002
        assert event.ocsf_category == 3

    def test_journald_json_style(self):
        raw = _raw(
            "Failed password for root from 198.51.100.9 port 22013 ssh2",
            timestamp="2026-06-15T08:05:00+00:00",
            reader="journald",
        )
        event = normalize(raw, _SOURCE_ID)

        assert event.source_ip == "198.51.100.9"
        assert event.action == "ALERT"
        assert event.severity == "low"
        assert event.category == "SSH Login Failure"
        assert event.timestamp == datetime(2026, 6, 15, 8, 5, 0, tzinfo=timezone.utc)


class TestSshLoginSuccessGolden:
    def test_accepted_password(self):
        raw = _raw("Accepted password for alice from 203.0.113.10 port 55000 ssh2")
        event = normalize(raw, _SOURCE_ID)

        assert event.action == "LOG"
        assert event.category == "SSH Login Success"
        assert event.rule_id == "sshd_login_success"
        assert event.severity == "info"
        assert event.attack_technique is None
        assert event.ocsf_class == 3002
        assert event.ocsf_category == 3


class TestSudoAuthFailureGolden:
    """AC3: sudo failures map to a distinct rule identity."""

    def test_sudo_failure_local_no_ip(self):
        raw = _raw("pam_unix(sudo:auth): authentication failure; user=bob")
        event = normalize(raw, _SOURCE_ID)

        assert event.action == "ALERT"
        assert event.category == "Sudo Authentication Failure"
        assert event.rule_id == "sudo_auth_failure"
        assert event.severity == "medium"
        assert event.attack_technique == "T1548.003"
        assert event.attack_tactic == "TA0004"
        assert event.ocsf_class == 3002
        assert event.ocsf_category == 3
        # No network origin recorded in the line → local-host sentinel.
        assert event.source_ip == "127.0.0.1"

    def test_sudo_failure_with_rhost(self):
        raw = _raw(
            "pam_unix(sudo:auth): authentication failure; rhost=203.0.113.9 user=bob"
        )
        event = normalize(raw, _SOURCE_ID)
        assert event.source_ip == "203.0.113.9"


class TestPamAuthFailureGolden:
    """AC3: generic PAM auth failures map to a distinct rule identity."""

    def test_su_failure(self):
        raw = _raw("pam_unix(su:auth): authentication failure; user=alice")
        event = normalize(raw, _SOURCE_ID)

        assert event.action == "ALERT"
        assert event.category == "PAM Authentication Failure"
        assert event.rule_id == "pam_auth_failure"
        assert event.severity == "medium"
        assert event.attack_technique == "T1110"
        assert event.ocsf_class == 3002
        assert event.ocsf_category == 3
        assert event.source_ip == "127.0.0.1"


class TestUserAccountCreatedGolden:
    """AC3: new-user creation maps to a distinct rule identity (T1136)."""

    def test_useradd_new_user(self):
        raw = _raw(
            "useradd[5678]: new user: name=deploy, UID=1002, GID=1002, "
            "home=/home/deploy, shell=/bin/bash",
        )
        event = normalize(raw, _SOURCE_ID)

        assert event.action == "LOG"
        assert event.category == "User Account Created"
        assert event.rule_id == "useradd_new_user"
        assert event.severity == "medium"
        assert event.attack_technique == "T1136"
        assert event.attack_tactic == "TA0003"
        assert event.kill_chain_phase == "persistence"
        assert event.ocsf_class == 3001
        assert event.ocsf_category == 3
        assert event.source_ip == "127.0.0.1"


class TestUnclassifiedFallback:
    def test_unmatched_line_falls_back_honestly(self):
        raw = _raw("pam_unix(sshd:session): session opened for user bob by (uid=0)")
        event = normalize(raw, _SOURCE_ID)

        assert event.action == "LOG"
        assert event.category == "Auth Activity"
        assert event.rule_id is None
        # Fail-quiet (ADR-0069 D3 rule 4): missing/unparseable classification
        # maps to low (telemetry-grade), never a gate-qualifying level.
        assert event.severity == "low"
        # Base Event (OCSF 1.8.0), not Network Activity — PR #73 held batch
        # correction (was wrongly 4001/4). This asserts the *normalize-level*
        # value; a known serializer landmine (firewatch_api/ocsf/serializer.py,
        # `event.ocsf_class or ...` — falsy-zero bug) rewrites this to 4001/4
        # on export until issue #76 lands, deliberately out of scope here.
        assert event.ocsf_class == 0
        assert event.ocsf_category == 0
        assert event.source_ip == "127.0.0.1"

    def test_missing_timestamp_falls_back_to_received_at(self):
        raw = _raw("Failed password for root from 203.0.113.1 port 1 ssh2")
        event = normalize(raw, _SOURCE_ID)
        assert event.timestamp == _RECEIVED_AT


class TestPayloadSnippetTruncation:
    def test_long_message_truncated_to_500_chars(self):
        raw = _raw("Failed password for x from 203.0.113.1 port 1 ssh2 " + ("A" * 600))
        event = normalize(raw, _SOURCE_ID)
        assert event.payload_snippet is not None
        assert len(event.payload_snippet) == 500


class TestRawLogRetained:
    def test_raw_log_carries_original_data(self):
        raw = _raw("Accepted password for alice from 203.0.113.10 port 55000 ssh2")
        event = normalize(raw, _SOURCE_ID)
        assert event.raw_log is not None
        assert event.raw_log["message"] == raw.data["message"]


class TestSeverityNeverExceedsMedium:
    """ADR-0069 D1 ambient-mass corollary: every category this plugin emits
    must map to at most 'medium' — only the correlation rule (not a per-event
    severity) may assert a Tier-2-qualifying signal (issue #3 Must-NOT)."""

    def test_no_category_maps_above_medium(self):
        from firewatch_linux_auth.normalize import _CATEGORY_META

        non_qualifying = {"info", "low", "medium", None}
        for category, meta in _CATEGORY_META.items():
            severity = meta[2]
            assert severity in non_qualifying, (
                f"{category!r} maps to severity={severity!r}, which would "
                f"qualify the ADR-0067 D1(b) gate directly — auth-failure "
                f"escalation must ride the correlation rule alone"
            )


class TestOcsfClassCategoryCorrection:
    """PR #73 held batch (architect ruling, 2026-07-16): the four authentication
    categories were wrongly mapped to class_uid 4001 (Network Activity,
    category_uid 4) — an inherited copy-paste error from syslog's own wrong
    comment. Verified against the published OCSF schema (schema.ocsf.io,
    v1.8.0): Authentication is class_uid 3002, category_uid 3 (Identity &
    Access Management); 4001/4 is Network Activity, which no event this
    plugin emits actually is."""

    def test_no_auth_event_emits_network_activity(self):
        """Must-NOT: no category this plugin emits maps to 4001/4 — that
        class_uid belongs to Suricata's network-layer telemetry alone."""
        from firewatch_linux_auth.normalize import _CATEGORY_META

        for category, meta in _CATEGORY_META.items():
            ocsf_class, ocsf_category = meta[6], meta[7]
            assert (ocsf_class, ocsf_category) != (4001, 4), (
                f"{category!r} maps to (4001, 4) — Network Activity — which "
                f"this plugin (host auth logs) never genuinely is"
            )

    def test_classified_auth_categories_map_to_authentication(self):
        """The four classified authentication categories (SSH login
        failure/success, sudo failure, PAM failure) all map to Authentication
        (3002, 3)."""
        from firewatch_linux_auth import parsers
        from firewatch_linux_auth.normalize import _CATEGORY_META

        auth_categories = (
            parsers.CAT_SSH_LOGIN_FAILURE,
            parsers.CAT_SSH_LOGIN_SUCCESS,
            parsers.CAT_SUDO_AUTH_FAILURE,
            parsers.CAT_PAM_AUTH_FAILURE,
        )
        for category in auth_categories:
            ocsf_class, ocsf_category = _CATEGORY_META[category][6:8]
            assert (ocsf_class, ocsf_category) == (3002, 3), (
                f"{category!r} maps to ({ocsf_class}, {ocsf_category}), "
                f"expected Authentication (3002, 3)"
            )

    def test_account_created_stays_account_change(self):
        """Regression pin: this row was already correct — must NOT be
        touched by the auth-categories correction above."""
        from firewatch_linux_auth import parsers
        from firewatch_linux_auth.normalize import _CATEGORY_META

        ocsf_class, ocsf_category = _CATEGORY_META[parsers.CAT_USER_ACCOUNT_CREATED][6:8]
        assert (ocsf_class, ocsf_category) == (3001, 3)

    def test_unclassified_fallback_maps_to_base_event(self):
        """The fallback row honestly reports Base Event (0, 0), not a
        borrowed Network Activity identity — normalize-level value; see the
        serializer-landmine note beside ``_CATEGORY_META`` for why this is
        NOT the same as the OCSF-exported value until issue #76 lands."""
        from firewatch_linux_auth.normalize import _CAT_UNCLASSIFIED, _CATEGORY_META

        ocsf_class, ocsf_category = _CATEGORY_META[_CAT_UNCLASSIFIED][6:8]
        assert (ocsf_class, ocsf_category) == (0, 0)
