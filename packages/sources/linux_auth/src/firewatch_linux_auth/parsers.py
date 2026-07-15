"""Table-driven line parsers for Linux auth & intrusion signals.

One parser per concern (sshd, sudo, useradd/usermod/groupadd/userdel, generic
PAM) — issue #3's module sketch. Each parser classifies one *message* string
and returns a ``ParsedAuthEvent`` (or ``None`` if it doesn't match).

Multi-distro coverage, by design: every regex here targets wording owned by
upstream source (OpenSSH, Linux-PAM, shadow-utils), not a distro's syslog
formatting —

  - sshd ``Failed``/``Accepted password|publickey`` — OpenSSH's own log
    wording (sshd/auth.c), identical whether the line reached us via
    journald's ``MESSAGE`` field or a classic ``/var/log/auth.log`` line.
  - ``pam_unix(SERVICE:auth): authentication failure`` — Linux-PAM's
    ``pam_unix`` module logs this verbatim on every mainstream distro (same
    upstream C source); ``SERVICE`` names the PAM-aware caller (``sudo``,
    ``su``, ``login``, …), so the module doesn't need identifier metadata to
    disambiguate the sudo case from any other PAM consumer.
  - shadow-utils ``new user: name=…, UID=…`` — shadow-utils' own
    ``useradd.c`` logging, consistent across every distro that ships it.

All regexes use ``.search()`` (not ``.match()``), so a parser matches whether
*message* is a bare journald ``MESSAGE`` field value or a full classic syslog
line still carrying its ``"timestamp host process[pid]:"`` envelope
(auth.log / rsyslog style) — the substantive pattern is a substring either way,
so ``collector.py`` can hand both reader shapes to the SAME parser table.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

_IPV4_RE = r"\d{1,3}(?:\.\d{1,3}){3}"

# Rule identities (issue #3 EARS: "distinct rule identities, not one generic
# 'auth event'"). Kept here (not normalize.py) so a parser's category and its
# matching logic can never drift apart.
CAT_SSH_LOGIN_FAILURE = "SSH Login Failure"
CAT_SSH_LOGIN_SUCCESS = "SSH Login Success"
CAT_SUDO_AUTH_FAILURE = "Sudo Authentication Failure"
CAT_PAM_AUTH_FAILURE = "PAM Authentication Failure"
CAT_USER_ACCOUNT_CREATED = "User Account Created"


@dataclass(frozen=True)
class ParsedAuthEvent:
    """One classified auth log line.

    ``source_ip`` is ``None`` when the event has no network origin (a local
    sudo prompt, a local useradd invocation) or none could be extracted —
    ``normalize()`` owns the local-host IP fallback (PLUGIN_CONTRACT.md: a
    parser must not fabricate data it doesn't have).
    """

    category: str
    source_ip: str | None = None
    user: str | None = None


# ---------------------------------------------------------------------------
# sshd
# ---------------------------------------------------------------------------

_SSH_FAILED_RE = re.compile(
    rf"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) "
    rf"from (?P<ip>{_IPV4_RE}) port \d+",
    re.IGNORECASE,
)
_SSH_ACCEPTED_RE = re.compile(
    rf"Accepted (?:password|publickey) for (?P<user>\S+) "
    rf"from (?P<ip>{_IPV4_RE}) port \d+",
    re.IGNORECASE,
)


def _parse_sshd(message: str) -> ParsedAuthEvent | None:
    m = _SSH_FAILED_RE.search(message)
    if m:
        return ParsedAuthEvent(CAT_SSH_LOGIN_FAILURE, m.group("ip"), m.group("user"))
    m = _SSH_ACCEPTED_RE.search(message)
    if m:
        return ParsedAuthEvent(CAT_SSH_LOGIN_SUCCESS, m.group("ip"), m.group("user"))
    return None


# ---------------------------------------------------------------------------
# sudo (a specific PAM service — checked BEFORE the generic PAM parser below)
# ---------------------------------------------------------------------------

_SUDO_FAIL_RE = re.compile(
    r"pam_unix\(sudo:auth\):\s*authentication failure(?:.*?\buser=(?P<user>\S+))?",
    re.IGNORECASE,
)


def _parse_sudo(message: str) -> ParsedAuthEvent | None:
    m = _SUDO_FAIL_RE.search(message)
    if m:
        return ParsedAuthEvent(
            CAT_SUDO_AUTH_FAILURE, _extract_rhost(message), m.group("user")
        )
    return None


# ---------------------------------------------------------------------------
# Generic PAM (any other pam_unix-backed service: login, su, cron, …)
# ---------------------------------------------------------------------------

_PAM_GENERIC_RE = re.compile(
    r"pam_unix\((?P<service>[\w-]+):auth\):\s*authentication failure"
    r"(?:.*?\buser=(?P<user>\S+))?",
    re.IGNORECASE,
)


def _parse_pam_generic(message: str) -> ParsedAuthEvent | None:
    m = _PAM_GENERIC_RE.search(message)
    if m and m.group("service").lower() != "sudo":
        return ParsedAuthEvent(
            CAT_PAM_AUTH_FAILURE, _extract_rhost(message), m.group("user")
        )
    return None


# ---------------------------------------------------------------------------
# useradd / usermod / groupadd / userdel (shadow-utils "new user" logging)
# ---------------------------------------------------------------------------

_NEW_USER_RE = re.compile(
    r"new user:\s*name=(?P<user>[\w.-]+)\s*,\s*UID=(?P<uid>\d+)",
    re.IGNORECASE,
)


def _parse_useradd(message: str) -> ParsedAuthEvent | None:
    m = _NEW_USER_RE.search(message)
    if m:
        return ParsedAuthEvent(CAT_USER_ACCOUNT_CREATED, None, m.group("user"))
    return None


# ---------------------------------------------------------------------------
# rhost= best-effort extraction (PAM sometimes carries the remote host that
# triggered the auth attempt, e.g. via the SSH PAM stack)
# ---------------------------------------------------------------------------

_RHOST_RE = re.compile(rf"\brhost=(?P<ip>{_IPV4_RE})\b")


def _extract_rhost(message: str) -> str | None:
    m = _RHOST_RE.search(message)
    return m.group("ip") if m else None


# ---------------------------------------------------------------------------
# Dispatch table — order matters: more specific parsers first (sudo before
# the generic PAM catch-all).
# ---------------------------------------------------------------------------

_PARSERS = (
    _parse_sshd,
    _parse_sudo,
    _parse_pam_generic,
    _parse_useradd,
)


def parse_line(message: str) -> ParsedAuthEvent | None:
    """Classify one auth log message. Returns ``None`` if no known pattern matches."""
    if not message:
        return None
    for parser in _PARSERS:
        result = parser(message)
        if result is not None:
            return result
    return None
