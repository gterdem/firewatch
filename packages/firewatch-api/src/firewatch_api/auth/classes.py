"""Route class enum and per-route declaration decorator (ADR-0026 Decision 3).

Every API route must carry an explicit ``RouteClass`` so a side-effecting GET
cannot be accidentally served as an open read.  ``ROUTE_CLASS_STATE_KEY`` is the
attribute name stamped onto each endpoint function by ``wire_auth`` (wiring.py).

RouteClass members
------------------
A — config-mutating (hard floor: always gated when a key is set)
B — action-triggering / side-effecting / outbound (hard floor)
C — read / analyze (gated by default when a key is set)

Coverage invariant
------------------
The test ``test_all_routes_have_route_class`` in test_auth_548.py walks every
``APIRoute`` mounted on the app and asserts that its endpoint function carries
``ROUTE_CLASS_STATE_KEY``.  Any unclassified route is a test failure.

Classification flow
-------------------
``wire_auth(app)`` in wiring.py stamps ``_fw_route_class`` on every route using a
method-based heuristic (PUT/PATCH → A, POST → B, GET/etc → C) plus an optional
path-override table.  The ``@route_class`` decorator is NOT used on any current
route because all routes are classified by the heuristic — removing unused
machinery avoids misleading code.  The decorator and this attribute name constant
are kept as extension points: if a future route requires an explicit override
that the heuristic cannot express, the decorator is the sanctioned way to do it
(annotate the handler and add a path-override entry in wiring.py).

No FastAPI imports here — this module is imported by both routers and posture.py.
"""
from __future__ import annotations

import enum
from collections.abc import Callable
from typing import Any, TypeVar

F = TypeVar("F", bound=Callable[..., Any])

# Attribute name stamped onto each endpoint function.
ROUTE_CLASS_STATE_KEY: str = "_fw_route_class"


class RouteClass(enum.Enum):
    """Risk classification for each API route (ADR-0026 §Route risk classes)."""

    A = "A"  # config-mutating — hard floor, never relaxable
    B = "B"  # action-triggering / side-effecting — hard floor, never relaxable
    C = "C"  # read / analyze — gated when a key is set (default posture)


def route_class(cls: RouteClass) -> Callable[[F], F]:
    """Decorator for future explicit route-class overrides.

    NOT used by any current route — all routes are classified centrally by the
    method-heuristic in wire_auth (wiring.py).  Kept as an extension point for
    routes that cannot be classified by HTTP method alone.

    When used, apply AFTER the FastAPI router decorator so that the original
    function object (which FastAPI stores as ``route.endpoint``) is decorated::

        @router.get("/sources/types")
        @route_class(RouteClass.C)
        async def list_source_types(...):
            ...

    wire_auth will see the pre-stamped attribute and skip the heuristic for that
    route when a path-override entry is also added to _PATH_OVERRIDES in wiring.py.
    """
    def decorator(fn: F) -> F:
        setattr(fn, ROUTE_CLASS_STATE_KEY, cls)
        return fn
    return decorator
