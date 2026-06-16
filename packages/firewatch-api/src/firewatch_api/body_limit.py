"""Request-body-size guard middleware (HTTP 413) for the ingest write door.

Rejects oversized request bodies on ``POST /logs`` and ``POST /logs/batch``
with **HTTP 413 Content Too Large** (RFC 9110 §15.5.14).  The guard operates in
two complementary stages:

1. **Content-Length fast-path:** If the request carries a ``Content-Length``
   header that exceeds the cap, it is rejected immediately before any body
   bytes are consumed.  This is the common case for well-behaved clients.

2. **Streaming hard cap:** Even when ``Content-Length`` is absent or
   understated (spoofed), the middleware reads the body chunk-by-chunk and
   rejects once the cumulative byte count exceeds the cap — so a forged header
   cannot bypass the limit.

The guard is scoped to the ingest write door only: ``POST /logs`` and
``POST /logs/batch``.  All other routes (GET read surface, PUT config, …) pass
through untouched.

Why a **pure-ASGI** middleware (not ``BaseHTTPMiddleware``)?
    A ``BaseHTTPMiddleware`` that consumes ``request.stream()`` and reassigns
    ``request._receive`` does NOT reliably hand the buffered body to the
    downstream route — the route reads a different (already-exhausted) receive
    channel and binds an empty body (HTTP 422 on otherwise-valid requests).  A
    pure-ASGI middleware wraps the ``receive`` callable directly, so buffering
    the body and re-injecting it via a replacement ``receive`` works correctly.

Configuration
-------------
``FIREWATCH_MAX_BODY_BYTES`` env var (ADR-0006 precedence):
    Maximum allowed request-body size in bytes.  Default: 1 048 576 (1 MiB).
    Invalid / non-positive values fall back to the default with a WARNING log
    (zero/negative means "use default", never "block everything").

Standards
---------
- OWASP API Security Top 10 (2023) **API4 — Unrestricted Resource Consumption**
- RFC 9110 §15.5.14 — 413 Content Too Large
- ADR-0026 — API auth posture / write-door hard floor before non-loopback exposure
- ADR-0029 D7.3 — body-size guard milestone gate

Dependency rule (CLAUDE.md non-negotiable #2):
    This module imports only the standard library and Starlette's ASGI types.
    It does NOT import firewatch-core, firewatch-sdk, or any plugin.
"""
from __future__ import annotations

import logging
import os

from starlette.types import ASGIApp, Message, Receive, Scope, Send

logger = logging.getLogger("firewatch.api.body_limit")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_ENV_MAX_BODY: str = "FIREWATCH_MAX_BODY_BYTES"

# 1 MiB — safe ceiling for a single log event or a 100-event batch of typical
# security events.  Matches the posture in ADR-0029 D7.3.
_DEFAULT_MAX_BODY_BYTES: int = 1024 * 1024  # 1 MiB

# Ingest write-door paths subject to the guard.  Only POST on these exact paths
# is guarded; other methods / paths pass through.
_GUARDED_PATHS: frozenset[str] = frozenset({"/logs", "/logs/batch"})

# Generic 413 body — MUST NOT echo attacker-controlled content (OWASP API4).
_BODY_413: bytes = b'{"detail":"Request body too large."}'
_CONTENT_TYPE: bytes = b"application/json"


def _resolve_cap() -> int:
    """Return the effective byte cap from env or default (ADR-0006).

    Read at request time so a test (or operator) can set the env var before
    ``create_app()`` and have it picked up.  Invalid / non-positive values fall
    back to the default.
    """
    raw = os.environ.get(_ENV_MAX_BODY, "")
    if raw:
        try:
            val = int(raw)
            if val > 0:
                return val
        except ValueError:
            pass
        logger.warning(
            "body_limit: invalid %s=%r — using default %d bytes",
            _ENV_MAX_BODY,
            raw,
            _DEFAULT_MAX_BODY_BYTES,
        )
    return _DEFAULT_MAX_BODY_BYTES


def _is_guarded(method: str, path: str) -> bool:
    """Return True if this request targets the ingest write door."""
    return method.upper() == "POST" and path in _GUARDED_PATHS


def _content_length(scope: Scope) -> int | None:
    """Parse the ``Content-Length`` header from the ASGI scope, or None."""
    for name, value in scope.get("headers", []):
        if name == b"content-length":
            try:
                return int(value)
            except ValueError:
                return None
    return None


async def _send_413(send: Send) -> None:
    """Send a generic 413 response that does not echo request content."""
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", _CONTENT_TYPE),
                (b"content-length", str(len(_BODY_413)).encode("latin-1")),
            ],
        }
    )
    await send({"type": "http.response.body", "body": _BODY_413})


class BodyLimitMiddleware:
    """Pure-ASGI middleware enforcing a raw-body byte cap on the ingest door.

    Registered in ``create_app`` via ``app.add_middleware(BodyLimitMiddleware)``.
    The cap is read from the environment at each request so configuration
    changes take effect without a restart.

    Security properties:
    - Rejects oversized bodies before normalization / persistence.
    - Streaming cap defeats absent / forged ``Content-Length`` headers.
    - Never echoes attacker-controlled body content in the 413 response.
    - Scoped to the write door only; the read surface is unaffected.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not _is_guarded(
            scope.get("method", ""), scope.get("path", "")
        ):
            await self.app(scope, receive, send)
            return

        cap = _resolve_cap()
        path = scope.get("path", "")

        # Stage 1: Content-Length fast-path — reject before consuming any body.
        declared = _content_length(scope)
        if declared is not None and declared > cap:
            logger.warning(
                "body_limit: rejected POST %s — Content-Length=%d > cap=%d",
                path,
                declared,
                cap,
            )
            await _send_413(send)
            return

        # Stage 2: stream + buffer with a hard cap (handles absent/spoofed CL).
        chunks: list[bytes] = []
        total = 0
        while True:
            message = await receive()
            mtype = message["type"]
            if mtype == "http.disconnect":
                # Client gone before the body finished — nothing to forward.
                return
            if mtype != "http.request":
                break
            body = message.get("body", b"")
            total += len(body)
            if total > cap:
                logger.warning(
                    "body_limit: rejected POST %s — streaming body exceeded cap=%d bytes",
                    path,
                    cap,
                )
                await _send_413(send)
                return
            chunks.append(body)
            if not message.get("more_body", False):
                break

        buffered = b"".join(chunks)
        replayed = False

        async def replay_receive() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": buffered, "more_body": False}
            # After the buffered body, defer to the original channel (e.g. for a
            # subsequent http.disconnect).
            return await receive()

        await self.app(scope, replay_receive, send)
