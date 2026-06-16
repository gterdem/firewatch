"""Auth dependency module (ADR-0026 Decisions 2-3 + Amendment 1).

NOTE: Per-route ``Depends`` auth is NOT used in FireWatch API.  After evaluating
both approaches (see ADR-0026 and the wiring.py comment), auth is enforced by
``AuthMiddleware`` (middleware.py) registered via ``wire_auth(app)`` in wiring.py.

Why middleware over Depends?
FastAPI compiles each route's dependant tree when ``include_router`` is called.
Dependencies appended to ``route.dependencies`` AFTER include_router are silently
ignored by the resolver, making central post-hoc wiring impossible.  Middleware
runs before any route dispatch and is registered at app-startup time, so it
gates ALL routes uniformly without per-router wiring.

This module is intentionally thin.  It is kept so that the subpackage boundary
is explicit — future per-route Depends can be added here if the architecture
evolves to need them.
"""
