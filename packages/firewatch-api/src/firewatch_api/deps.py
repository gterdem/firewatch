"""FastAPI dependency providers for the FireWatch API (MB move, ADR-0029 D5).

Replaces the ``app.state.*`` closures from the MA app.py with typed ``Depends()``
providers.  Route functions declare these as parameters — FastAPI resolves them
at request time with zero global state.

Injection pattern:
    The ``Request`` object carries ``request.app.state.*`` set by ``create_app``.
    Each provider reads one attribute so the rest of the module never touches state.

Dependency rule:
    Imports firewatch-core and firewatch-sdk only.  Never imports a plugin or legacy/.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import HTTPException, Query, Request

from firewatch_sdk.models import FilterSpec


def parse_iso_or_422(name: str, value: str | None) -> str | None:
    """Validate an optional ISO-8601 datetime/date string query parameter.

    Returns the raw string unchanged when valid (the store accepts the string
    directly). Raises ``HTTPException(422)`` when the value is present but
    cannot be parsed by ``datetime.fromisoformat`` — satisfying ADR-0029 D3
    which requires query-validation failures to return 422, not 500.

    Args:
        name:  The parameter name, used in the error detail message.
        value: The raw query-string value, or None (no param supplied).
    """
    if value is None:
        return None
    try:
        datetime.fromisoformat(value)
    except ValueError:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid ISO datetime for '{name}': {value!r}",
        )
    return value


def logs_filterspec(
    source_type: str | None = Query(default=None, description="Exact match on source plugin type_key"),
    source_id: str | None = Query(default=None, description="Exact match on source instance id"),
    category: str | None = Query(
        default=None,
        description=(
            "Canonical stored category value (exact match) or legacy shorthand alias "
            "(sqli/xss/lfi/cmdi/proto/anomaly/bot/ratelimit/geo); 'all' = no filter (issue #325)."
        ),
    ),
    category_name: str | None = Query(
        default=None,
        description="DEPRECATED — synonym for category= exact match; use category= instead.",
    ),
    severity: str | None = Query(default=None, description="critical/high/medium/low"),
    ip: str | None = Query(default=None, description="Substring match on source_ip"),
    action: str | None = Query(
        default=None,
        description=(
            "Exact action value (ALLOW/BLOCK/DROP/ALERT) or the shorthand "
            "'blocked' (case-insensitive) which matches action ∈ {BLOCK, DROP} (issue #252)."
        ),
    ),
    rule: str | None = Query(default=None, description="Substring match on rule_id"),
    q: str | None = Query(default=None, description="Free-text search"),
    destination_ip: str | None = Query(
        default=None,
        description="Substring match on destination_ip (ML-3, issue #431).",
    ),
    protocol: str | None = Query(
        default=None,
        description="Exact match on protocol (e.g. TCP/UDP/ICMP) (ML-3, issue #431).",
    ),
    tls_ja4: str | None = Query(
        default=None,
        description="Exact match on JA4 TLS fingerprint (ML-13, issue #441); consume-only.",
    ),
) -> FilterSpec:
    """Build a ``FilterSpec`` from the standard ``/logs`` facet query params.

    Shared dependency (issue #662) so the aggregation endpoints — top-talkers,
    protocol-mix, top-pairs, graph — scope by the SAME facets ``/logs/paginated``
    accepts. Pagination-only params (``cursor``, ``limit``) are intentionally
    excluded; an all-``None`` call yields an empty ``FilterSpec()`` (no filtering),
    preserving each endpoint's pre-change behaviour.
    """
    return FilterSpec(
        source_type=source_type,
        source_id=source_id,
        category=category,
        category_name=category_name,
        severity=severity,
        ip=ip,
        action=action,
        rule=rule,
        q=q,
        destination_ip=destination_ip,
        protocol=protocol,
        tls_ja4=tls_ja4,
    )


def get_registry(request: Request) -> dict[str, Any]:
    """Provide the plugin registry injected at app-creation time."""
    return request.app.state.registry  # type: ignore[no-any-return]


def get_config_store(request: Request) -> Any:
    """Provide the ConfigStore injected at app-creation time.

    Returns None when no config store was injected (e.g. tests that only
    exercise read/sync routes).  The POST /sources/{type_key}/test route
    raises 503 when this is None, matching the guard pattern used for
    get_event_store and get_pipeline.
    """
    return getattr(request.app.state, "config_store", None)


def get_event_store(request: Request) -> Any:
    """Provide the EventStore (SQLiteEventStore) injected at app-creation time.

    Returns None when no store was injected (e.g. tests that only exercise
    config/discovery routes); callers must handle None or use the guard helper.
    """
    return getattr(request.app.state, "event_store", None)


def get_pipeline(request: Request) -> Any:
    """Provide the Pipeline injected at app-creation time.

    Returns None when no pipeline was injected; read routes that need the pipeline
    return 503 if it is absent.
    """
    return getattr(request.app.state, "pipeline", None)


def get_decision_store(request: Request) -> Any:
    """Provide the DecisionStore (SqliteDecisionStore) injected at app-creation time.

    Returns None when no store was injected (e.g. tests that only exercise
    other read routes); ``/decisions`` routes return 503, and the
    ``triage_decision`` annotation / ``queue_size`` exclusion degrade to
    "no decisions" (every actor renders as undecided) when this is None —
    ADR-0072 D2/D8.
    """
    return getattr(request.app.state, "decision_store", None)


def get_supervisor(request: Request) -> Any:
    """Provide the Supervisor injected at app-creation time (MB.4, issue #56).

    Returns None when no supervisor was injected (e.g. test environments that
    only exercise read routes).  Control routes (POST /sync/*, POST /sources/*/test)
    and the GET /sources instance list return 503 when supervisor is absent.

    The supervisor is route class B (action-triggering) and class C (read) per
    ADR-0026.  Auth gating is deferred to MB.7 (loopback-only for MB); this
    provider only resolves the dependency — it does not gate access.
    """
    return getattr(request.app.state, "supervisor", None)
