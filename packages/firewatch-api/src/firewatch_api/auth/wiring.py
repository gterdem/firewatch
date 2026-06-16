"""Central auth wiring for the FastAPI app (ADR-0026 Decisions 2-3 + Amendment 1).

``wire_auth(app)`` is called once in ``create_app`` after all routers are
registered.  It does two things:

1. Walks every ``APIRoute`` and stamps the endpoint function with its
   ``RouteClass`` (A/B/C) so the coverage test ``test_all_routes_have_route_class``
   can verify 100% classification.

2. Adds ``AuthMiddleware`` to the application so all incoming requests are
   gated when an api_key is configured (enforce-when-set, ADR-0026 Amendment 1).

Why middleware instead of per-route Depends?
FastAPI compiles each route's ``dependant`` tree at ``include_router`` time.
Dependencies appended to ``route.dependencies`` *after* include_router are not
picked up by the resolver.  Middleware runs before any route dispatch and is
registered at startup, so it reliably gates ALL routes without requiring
per-router wiring.

Classification rules (ADR-0026 Decision 3)
-------------------------------------------
Class A -- config-mutating: PUT, PATCH
Class B -- action-triggering / side-effecting: POST
Class C -- read / analyze: GET, HEAD, OPTIONS, ...

The ``@route_class`` decorator (classes.py) takes precedence over the heuristic.
If a future route annotates its handler with ``@route_class(RouteClass.X)`` AND
adds a path-override to ``_PATH_OVERRIDES``, the decorator-set attribute is used
verbatim.  The heuristic is the fallback for the common case.

Standards: ADR-0026 Decision 3, OWASP API1/API2/API5.
"""
from __future__ import annotations

from fastapi import FastAPI
from fastapi.routing import APIRoute

from firewatch_api.auth.classes import ROUTE_CLASS_STATE_KEY, RouteClass
from firewatch_api.auth.middleware import AuthMiddleware

# Methods that map to each RouteClass by default.
_METHOD_CLASS: dict[str, RouteClass] = {
    # Class A -- config-mutating (RFC 9110 sec 9.3.6 PUT, sec 9.3.7 PATCH)
    "PUT": RouteClass.A,
    "PATCH": RouteClass.A,
    # Class B -- action-triggering / side-effecting (RFC 9110 sec 9.3.3 POST)
    "POST": RouteClass.B,
}

# Per-path+method overrides for routes whose HTTP method alone does not determine
# the correct class.  Key: (frozenset_of_methods, path_pattern).
# Currently empty -- the method-level rule covers all mounted routes.
_PATH_OVERRIDES: dict[tuple[frozenset[str], str], RouteClass] = {}


def _classify_route(route: APIRoute) -> RouteClass:
    """Return the RouteClass for *route* using decorator > path-override > method.

    Priority:
    1. If the endpoint already carries ``_fw_route_class`` (set by the
       ``@route_class`` decorator), honour it — the decorator is authoritative.
    2. If a ``_PATH_OVERRIDES`` entry matches (method-set, path), use that.
    3. Fall back to the method-level heuristic (PUT/PATCH → A, POST → B, else C).
    """
    # Priority 1: explicit decorator annotation is authoritative.
    existing = getattr(route.endpoint, ROUTE_CLASS_STATE_KEY, None)
    if existing is not None:
        return existing  # type: ignore[return-value]

    # Priority 2: path + method override table.
    methods: frozenset[str] = frozenset(route.methods or [])
    override_key = (methods, route.path)
    if override_key in _PATH_OVERRIDES:
        return _PATH_OVERRIDES[override_key]

    # Priority 3: method heuristic — fallback for the common case.
    for method in ("PUT", "PATCH", "POST"):
        if method in methods:
            return _METHOD_CLASS[method]

    # Default: read-only / safe (GET, HEAD, OPTIONS, ...)
    return RouteClass.C


def wire_auth(app: FastAPI) -> None:
    """Stamp RouteClass attributes and add AuthMiddleware to the app.

    Called once after all routers are included in create_app.

    Effects:
    1. For each APIRoute: sets route.endpoint._fw_route_class = RouteClass.X
       so the coverage test can verify all routes are classified.
       Respects existing decorator-set attributes (decorator > override > heuristic).
    2. Adds AuthMiddleware to the app -- the middleware gates ALL requests
       when api_key is configured (read from app.state.config_store).
    """
    # --- 1. Stamp route class attributes on all endpoint functions -----------
    for route in app.routes:
        if not isinstance(route, APIRoute):
            continue  # skip Mount / WebSocketRoute / etc.
        rc = _classify_route(route)
        setattr(route.endpoint, ROUTE_CLASS_STATE_KEY, rc)

    # --- 2. Add the auth middleware -----------------------------------------
    # Must be called after route stamping so the coverage test sees attributes.
    # Middleware is registered here (not per-router) so it applies uniformly.
    app.add_middleware(AuthMiddleware)
