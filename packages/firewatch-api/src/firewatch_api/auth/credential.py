"""Bearer credential extraction and constant-time verification (RFC 6750).

Two public functions:

extract_bearer_token(header)
    Parse the ``Authorization`` request header and return the bearer token
    string, or None if the header is absent, uses a non-Bearer scheme, or
    carries an empty/whitespace-only token.  RFC 6750 §2.1 / RFC 9110 §11.6.2.

verify_bearer_token(provided, configured)
    Constant-time comparison of the extracted token against the configured key.
    Uses ``hmac.compare_digest`` to prevent timing-oracle attacks (OWASP API2,
    NIST SP 800-63B §5.2.7).  Returns False in all failure cases — never raises.

Security invariants:
- ``hmac.compare_digest`` is the ONLY comparison used; direct ``==`` on secrets
  is absent from this module.
- The configured key value is NEVER logged or included in any return value or
  exception message.
- An empty/whitespace token is treated as unauthenticated (not as any token).
- ALL code paths run ``hmac.compare_digest`` so that absent/empty inputs are
  indistinguishable from wrong inputs by timing (Django UNUSABLE_PASSWORD pattern;
  NIST SP 800-63B §5.2.7).

No FastAPI imports — this module is testable in isolation.
"""
from __future__ import annotations

import hmac

from pydantic import SecretStr

# The literal scheme name (RFC 6750 §2.1).  Comparison is case-insensitive per
# RFC 9110 §11.1 (scheme names are case-insensitive).
_BEARER_SCHEME = "bearer"

# A dummy constant used as the second operand of hmac.compare_digest when the
# provided token or configured key is absent/empty.  Running compare_digest
# against this constant instead of short-circuiting ensures that all code
# paths take equal time, preventing timing-oracle attacks on the presence or
# absence of a configured key (NIST SP 800-63B §5.2.7, Django UNUSABLE_PASSWORD
# pattern).  The value is arbitrary; it will never produce a True result because
# the caller returns False unconditionally after the compare.
_DUMMY_CONSTANT = "firewatch-auth-dummy-constant-do-not-compare"  # noqa: S105


def extract_bearer_token(authorization_header: str | None) -> str | None:
    """Extract the bearer token from an Authorization header value.

    Args:
        authorization_header: The raw value of the ``Authorization`` HTTP header,
            e.g. ``Bearer abc123``.  Pass ``None`` when the header is absent.

    Returns:
        The token string (stripped) if the header is present and well-formed,
        ``None`` otherwise.

    RFC 6750 §2.1 format: ``Authorization: Bearer <token>``
    RFC 9110 §11.1: scheme names are case-insensitive.
    """
    if authorization_header is None:
        return None

    # Split into at most two parts: scheme + credentials.
    parts = authorization_header.split(" ", maxsplit=1)
    if len(parts) != 2:
        return None

    scheme, credentials = parts
    if scheme.lower() != _BEARER_SCHEME:
        return None

    token = credentials.strip()
    return token if token else None


def verify_bearer_token(
    provided: str | None,
    configured: SecretStr | None,
) -> bool:
    """Constant-time comparison of a provided token against the configured key.

    ALL code paths run ``hmac.compare_digest`` so that absent/empty inputs are
    indistinguishable from wrong inputs by timing.  When the provided token or
    the configured key is absent/empty, compare_digest runs against a dummy
    constant and the function returns False — the dummy compare result is
    discarded (Django UNUSABLE_PASSWORD pattern; NIST SP 800-63B §5.2.7).

    Args:
        provided:   The extracted bearer token from the request (may be None).
        configured: The ``api_key`` from ``RuntimeConfig`` (may be None if not set).

    Returns:
        True  — the provided token matches the configured key (non-empty, correct).
        False — mismatch, missing token, empty token, or no key configured.

    Security:
        Uses ``hmac.compare_digest`` for constant-time comparison on every path.
        The configured key value is never included in any log or return value.

    NIST SP 800-63B §5.2.7 — verifiers shall not disclose timing information
    that could be used to enumerate or verify individual credentials.
    """
    provided_bytes = (provided or "").strip().encode("utf-8")
    dummy_bytes = _DUMMY_CONSTANT.encode("utf-8")

    key_value = configured.get_secret_value() if configured is not None else ""
    configured_bytes = key_value.encode("utf-8") if key_value else dummy_bytes

    # Always call compare_digest — even on absent/empty inputs — to equalise timing.
    # When provided or configured is absent/empty we compare against dummy_bytes so
    # the path length is the same as a real comparison.  The boolean result is only
    # used when BOTH sides are non-empty; otherwise we return False unconditionally.
    digest_match = hmac.compare_digest(provided_bytes, configured_bytes)

    # Guard: return False if either side was absent/empty (the dummy path).
    # The ordering — digest first, guards second — ensures compare_digest always runs.
    provided_ok = bool(provided_bytes)
    configured_ok = bool(key_value)

    return digest_match and provided_ok and configured_ok
