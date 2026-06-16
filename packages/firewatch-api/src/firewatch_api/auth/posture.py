"""Pure auth posture policy (ADR-0026 Decisions 2-3 + Amendment 1).

This module has no I/O and no HTTP framework imports.  It encodes exactly one
rule:

    api_key is set (non-None, non-empty, non-whitespace)
        => gate ALL routes (classes A, B, and C)
    api_key is not set
        => no-op (loopback trust boundary applies -- ADR-0026 Decision 1)

The bind address is intentionally NOT a parameter.  ADR-0026 Amendment 1
(2026-06-13) resolves the loopback-with-key corner as enforce-when-set:
the auth check keys only on "is a key configured?", never on "where are we
bound?".  The bind guard (MP.2 / server.py) is the separate concern that
refuses to start a non-loopback socket without a key.

No HTTP framework imports -- this module can be unit-tested in isolation
without an HTTP server.

Standards: OWASP secure-by-default, NIST SP 800-63B, ADR-0026 Amendment 1.
"""
from __future__ import annotations

from pydantic import SecretStr

from firewatch_api.auth.classes import RouteClass
from firewatch_api.server import _is_key_set


class AuthPosture:
    """Policy: given a configured api_key and a route class, decide gate vs no-op.

    All methods are class-level (no instance state) — the policy is stateless.
    """

    @classmethod
    def should_gate(
        cls,
        api_key: SecretStr | None,
        route_class: RouteClass,
    ) -> bool:
        """Return True if the request should be gated (bearer required).

        Args:
            api_key:      The configured key from ``RuntimeConfig.api_key``.
                          None or a whitespace-only value means "not set".
            route_class:  The declared class of the route being accessed
                          (A, B, or C — see ``RouteClass``).

        Returns:
            True  — gate the route; ``require_auth`` will enforce the bearer.
            False — no-op; request proceeds without a credential check.

        Policy (ADR-0026 Amendment 1 / enforce-when-set):
            - key set   → gate ALL classes (A, B, C) regardless of bind address
            - key unset → no-op for ALL classes (loopback trust boundary)

        The ``route_class`` parameter is accepted so future policy changes
        (e.g. an explicit opt-out for C) can be added here in one place
        without touching the dependency wiring.  Currently the class does not alter
        the decision — gating is uniform across A/B/C when a key is set.
        """
        # Intentionally ignore route_class in the gate/no-op decision for now:
        # ADR-0026 Decision 3 gates A+B+C uniformly when a key is set.
        # The parameter exists so a future amendment can tighten per-class
        # without a signature change in the dependency wiring.
        _ = route_class  # accepted for future use; currently uniform
        return _is_key_set(api_key)
