"""FireWatch REST API package.

This package is a *consumer* of ``firewatch-core`` and ``firewatch-sdk``.
It must never be imported by firewatch-core or firewatch-sdk (dependency rule,
CLAUDE.md non-negotiable #2).

MA scope (issue #32, ADR-0026):
  - Binds loopback (127.0.0.1) by default — no app auth for MA.
  - Exposes ``GET /sources/types`` (plugin discovery endpoint).
  - Auth/key seam is documented in ``firewatch_api.server`` and will be wired
    in a future MB milestone once ADR-0026's key + guard are implemented.
"""
