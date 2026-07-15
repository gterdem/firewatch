"""Table-driven parser tests — one class per concern (issue #3 module sketch).

Fixture IPs use RFC 5737 documentation ranges (203.0.113.0/24, 192.0.2.0/24) —
never real/routable IPs (testing-conventions skill / gitleaks public-ipv4 rule).
"""
from firewatch_linux_auth import parsers


class TestSshdFailure:
    def test_failed_password_debian_style(self):
        line = (
            "Jun 15 08:00:00 host sshd[1234]: Failed password for admin "
            "from 203.0.113.5 port 51234 ssh2"
        )
        parsed = parsers.parse_line(line)
        assert parsed is not None
        assert parsed.category == parsers.CAT_SSH_LOGIN_FAILURE
        assert parsed.source_ip == "203.0.113.5"
        assert parsed.user == "admin"

    def test_failed_password_bare_journald_message(self):
        # journald's MESSAGE field has no "host process[pid]:" envelope.
        line = "Failed password for root from 198.51.100.9 port 22013 ssh2"
        parsed = parsers.parse_line(line)
        assert parsed is not None
        assert parsed.category == parsers.CAT_SSH_LOGIN_FAILURE
        assert parsed.source_ip == "198.51.100.9"

    def test_failed_password_invalid_user(self):
        line = "Failed password for invalid user oracle from 203.0.113.7 port 4444 ssh2"
        parsed = parsers.parse_line(line)
        assert parsed is not None
        assert parsed.category == parsers.CAT_SSH_LOGIN_FAILURE
        assert parsed.user == "oracle"
        assert parsed.source_ip == "203.0.113.7"

    def test_failed_publickey(self):
        line = "Failed publickey for git from 192.0.2.44 port 12345 ssh2"
        parsed = parsers.parse_line(line)
        assert parsed is not None
        assert parsed.category == parsers.CAT_SSH_LOGIN_FAILURE


class TestSshdSuccess:
    def test_accepted_password(self):
        line = "Accepted password for alice from 203.0.113.10 port 55000 ssh2"
        parsed = parsers.parse_line(line)
        assert parsed is not None
        assert parsed.category == parsers.CAT_SSH_LOGIN_SUCCESS
        assert parsed.source_ip == "203.0.113.10"
        assert parsed.user == "alice"

    def test_accepted_publickey(self):
        line = "Accepted publickey for deploy from 198.51.100.20 port 33221 ssh2"
        parsed = parsers.parse_line(line)
        assert parsed is not None
        assert parsed.category == parsers.CAT_SSH_LOGIN_SUCCESS


class TestSudoFailure:
    def test_sudo_auth_failure(self):
        line = (
            "Jun 15 08:01:00 host sudo: pam_unix(sudo:auth): authentication "
            "failure; logname=bob uid=1000 euid=0 tty=/dev/pts/0 ruser=bob "
            "rhost=  user=bob"
        )
        parsed = parsers.parse_line(line)
        assert parsed is not None
        assert parsed.category == parsers.CAT_SUDO_AUTH_FAILURE
        assert parsed.user == "bob"

    def test_sudo_auth_failure_bare_message(self):
        line = "pam_unix(sudo:auth): authentication failure; user=root"
        parsed = parsers.parse_line(line)
        assert parsed is not None
        assert parsed.category == parsers.CAT_SUDO_AUTH_FAILURE

    def test_sudo_with_rhost_extracted(self):
        line = (
            "pam_unix(sudo:auth): authentication failure; rhost=203.0.113.9 "
            "user=bob"
        )
        parsed = parsers.parse_line(line)
        assert parsed is not None
        assert parsed.source_ip == "203.0.113.9"


class TestPamGenericFailure:
    def test_login_service_failure(self):
        line = "pam_unix(login:auth): authentication failure; user=root"
        parsed = parsers.parse_line(line)
        assert parsed is not None
        assert parsed.category == parsers.CAT_PAM_AUTH_FAILURE
        assert parsed.user == "root"

    def test_su_service_failure(self):
        line = "pam_unix(su:auth): authentication failure; user=alice"
        parsed = parsers.parse_line(line)
        assert parsed is not None
        assert parsed.category == parsers.CAT_PAM_AUTH_FAILURE

    def test_sudo_is_not_classified_as_generic_pam(self):
        """Sudo must resolve to CAT_SUDO_AUTH_FAILURE, never the generic bucket."""
        line = "pam_unix(sudo:auth): authentication failure; user=bob"
        parsed = parsers.parse_line(line)
        assert parsed is not None
        assert parsed.category == parsers.CAT_SUDO_AUTH_FAILURE
        assert parsed.category != parsers.CAT_PAM_AUTH_FAILURE


class TestUserAccountCreated:
    def test_useradd_new_user(self):
        line = (
            "Jun 15 09:00:00 host useradd[5678]: new user: name=deploy, "
            "UID=1002, GID=1002, home=/home/deploy, shell=/bin/bash"
        )
        parsed = parsers.parse_line(line)
        assert parsed is not None
        assert parsed.category == parsers.CAT_USER_ACCOUNT_CREATED
        assert parsed.user == "deploy"

    def test_useradd_bare_journald_message(self):
        line = "new user: name=bob, UID=1003, GID=1003, home=/home/bob, shell=/bin/sh"
        parsed = parsers.parse_line(line)
        assert parsed is not None
        assert parsed.category == parsers.CAT_USER_ACCOUNT_CREATED


class TestUnmatchedLines:
    def test_empty_string_returns_none(self):
        assert parsers.parse_line("") is None

    def test_unrelated_session_line_returns_none(self):
        line = "pam_unix(sshd:session): session opened for user bob by (uid=0)"
        assert parsers.parse_line(line) is None

    def test_random_text_returns_none(self):
        assert parsers.parse_line("systemd[1]: Started Session 42 of user bob.") is None


class TestCategoriesAreDistinct:
    """Guard against a regression to one generic 'auth event' bucket
    (issue #3 EARS: distinct rule identities)."""

    def test_all_named_categories_are_pairwise_distinct(self):
        categories = [
            parsers.CAT_SSH_LOGIN_FAILURE,
            parsers.CAT_SSH_LOGIN_SUCCESS,
            parsers.CAT_SUDO_AUTH_FAILURE,
            parsers.CAT_PAM_AUTH_FAILURE,
            parsers.CAT_USER_ACCOUNT_CREATED,
        ]
        assert len(categories) == len(set(categories))
