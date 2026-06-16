"""Starlette auth middleware (ADR-0026 Decisions 2-3 + Amendment 1).

``AuthMiddleware`` is a Starlette ``BaseHTTPMiddleware`` that enforces the
enforce-when-set policy on every incoming request:

    api_key set (non-None, non-empty, non-whitespace)
        => all routes gated; bearer required; 401 on absent/wrong token
    api_key not set
        => no-op; request proceeds (loopback trust boundary -- ADR-0026 D1)

The middleware delegates policy to ``AuthPosture.should_gate`` (posture.py)
and token extraction/verification to ``credential.py`` so the security logic
stays in one place and is independently testable.

Why middleware rather than Depends?
FastAPI compiles each route's ``dependant`` tree when ``include_router`` is
called.  Dependencies appended to ``route.dependencies`` AFTER include_router
are NOT picked up by the resolver.  Starlette middleware runs before any
route dispatch and is registered once at app-startup time, so it reliably
gates ALL routes without requiring per-router wiring.

Standards: RFC 6750 sec 3 (WWW-Authenticate), OWASP API1/API2, NIST SP 800-63B.
"""
from __future__ import annotations

import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from starlette.types import ASGIApp

from firewatch_api.auth.classes import RouteClass
from firewatch_api.auth.credential import extract_bearer_token, verify_bearer_token
from firewatch_api.auth.posture import AuthPosture

logger = logging.getLogger("firewatch.api.auth")

# RFC 6750 sec 3 -- the 401 response MUST include WWW-Authenticate.
_WWW_AUTHENTICATE = "Bearer"

# Minimal detail body -- generic, no key value.
_BODY_401 = b'{"detail":"Authentication required."}'
_CONTENT_TYPE = "application/json"


class AuthMiddleware(BaseHTTPMiddleware):
    """Enforce bearer auth on all routes when api_key is configured.

    Reads api_key from request.app.state.config_store at request time so
    that the runtime config (including the key) can be updated without a
    server restart.

    The middleware applies a single gate to ALL routes uniformly
    (ADR-0026 Decision 3 -- class A+B+C gated equally when key is set).
    Per-route classification (A/B/C) is stamped on endpoints by wire_auth
    for the coverage test and future per-class policy changes.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next) -> Response:  # type: ignore[override]
        """Gate the request if api_key is configured."""
        api_key = None
        config_store = getattr(request.app.state, "config_store", None)
        if config_store is not None:
            try:
                runtime = config_store.get_runtime()
                api_key = runtime.api_key
            except Exception:
                # Config read failure treated as no key -- fail-open on config
                # error so a broken config doesn't brick the loopback default.
                logger.warning(
                    "auth: failed to read RuntimeConfig from config_store; "
                    "treating api_key as unset",
                    exc_info=True,
                )

        if not AuthPosture.should_gate(api_key=api_key, route_class=RouteClass.C):
            # No key configured -- loopback trust boundary applies (ADR-0026 D1).
            return await call_next(request)

        # Key is configured -- enforce bearer on ALL routes.
        authorization = request.headers.get("Authorization")
        token = extract_bearer_token(authorization)

        if not verify_bearer_token(token, api_key):
            # Raise 401 with RFC 6750 sec 3 WWW-Authenticate header.
            # Never include the key value or submitted token in the response.
            return Response(
                content=_BODY_401,
                status_code=401,
                headers={"WWW-Authenticate": _WWW_AUTHENTICATE},
                media_type=_CONTENT_TYPE,
            )

        return await call_next(request)
