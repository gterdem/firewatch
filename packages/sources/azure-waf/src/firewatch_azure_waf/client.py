"""Azure Log Analytics client for the Azure WAF plugin.

Wraps ``azure-monitor-query``'s ``LogsQueryClient`` + ``DefaultAzureCredential``
(azure-waf-log-standard.md §1d / ADR-0024 kept technique).

Responsibilities:
  - Build KQL queries per product and table regime (explicit config; no speculative
    try/except — §3 critique #6).
  - Apply the 5-minute-overlap watermark window.
  - Raise TYPED errors on credential or connectivity failures — never swallow them
    as "no data" (§3 critique #6, corrects legacy sync.py:43 anti-pattern).
  - Yield ``RawEvent``s wrapping the full Log Analytics row (no lossy projection).

Table regimes (azure-waf-log-standard.md §1d):
  resource_specific:
    App Gateway → ``AGWFirewallLogs``
    Front Door  → ``AzureFrontDoorWebApplicationFirewallLog``
  azure_diagnostics:
    Both products → ``AzureDiagnostics``
    Column names carry _s / _d suffixes (e.g. ``clientIp_s``, ``ruleId_s``).

The module binds ``azure-monitor-query`` and ``azure-identity`` symbols at
module scope (try/except ImportError → None) so that ``import firewatch_azure_waf``
does not blow up when the Azure SDKs are absent, AND so that
``patch("firewatch_azure_waf.client.LogsQueryClient")`` works in tests.

Pattern mirrors Suricata's asyncssh handling (collector.py lines 43-46):
    try: import asyncssh as asyncssh
    except ImportError: asyncssh = None
Functions access these via ``globals()`` so patch targets are respected.
"""
from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from typing import Any

from firewatch_sdk import RawEvent

from firewatch_azure_waf._columns import canonicalize_row
from firewatch_azure_waf._kql import build_kql

logger = logging.getLogger("firewatch.azure_waf.client")

# ---------------------------------------------------------------------------
# Module-level Azure SDK references — bound once at import time.
# Tests patch these names at module scope:
#   patch("firewatch_azure_waf.client.LogsQueryClient")
#   patch("firewatch_azure_waf.client.LogsQueryStatus")
# The try/except keeps ``import firewatch_azure_waf`` safe when the Azure SDKs
# are absent (same guarantee the lazy-import pattern gave, but patchable).
# ---------------------------------------------------------------------------

try:
    from azure.monitor.query import LogsQueryClient as LogsQueryClient  # noqa: PLC0414
    from azure.monitor.query import LogsQueryStatus as LogsQueryStatus  # noqa: PLC0414
except ImportError:  # pragma: no cover
    LogsQueryClient = None  # type: ignore[assignment,misc]
    LogsQueryStatus = None  # type: ignore[assignment]

try:
    from azure.identity import (  # noqa: PLC0414
        ClientSecretCredential as ClientSecretCredential,
        DefaultAzureCredential as DefaultAzureCredential,
    )
except ImportError:  # pragma: no cover
    ClientSecretCredential = None  # type: ignore[assignment,misc]
    DefaultAzureCredential = None  # type: ignore[assignment,misc]

# ---------------------------------------------------------------------------
# Typed error hierarchy
# ---------------------------------------------------------------------------


class AzureWAFError(Exception):
    """Base class for Azure WAF client errors."""


class AzureWAFAuthError(AzureWAFError):
    """Raised when credential acquisition or authentication fails.

    Never silently swallowed — surfaces to the supervisor so the failing
    instance is isolated without masking the error as "no data"
    (§3 critique #6 / PLUGIN_CONTRACT.md hard rule).
    """


class AzureWAFConnectError(AzureWAFError):
    """Raised on network / connectivity failures reaching Log Analytics."""


class AzureWAFQueryError(AzureWAFError):
    """Raised when the KQL query fails (bad workspace ID, unknown table, etc.)."""


# ---------------------------------------------------------------------------
# Row → RawEvent conversion
# ---------------------------------------------------------------------------

def _row_to_dict(row: Any, columns: list[str] | None = None) -> dict[str, Any]:
    """Convert a ``LogsTableRow`` (or plain dict) to a column-name → value dict.

    Extraction strategy (in order of preference):

    1. ``isinstance(row, dict)`` fast-path — kept for test seams and any caller
       that already has a dict.
    2. ``dict(zip(columns, row))`` when ``columns`` is provided by the caller
       (the table-level approach).  ``LogsTableRow.__iter__`` is a documented
       public API (azure-monitor-query 2.0.0 — iterates over the row's values
       in column order); ``table.columns`` is the matching public list of names.
       This is the correct, robust path for all real SDK objects.
    3. If neither applies, log a WARNING (with the row index if available) so
       the failure is visible in logs rather than producing a silent empty dict.
       Returns ``{}`` in that case so a single bad row never stops the iterator;
       the caller logs the warning before yielding an empty-data event.

    Args:
        row:     A ``LogsTableRow`` instance, or a plain ``dict`` (test seam).
        columns: Column name list from ``LogsTable.columns`` — REQUIRED for the
                 real SDK path.  Must be provided when ``row`` is a
                 ``LogsTableRow``; passing ``None`` here for a real row will
                 trigger the warning path.
    """
    if isinstance(row, dict):
        return row

    if columns is not None:
        # Public API: LogsTableRow.__iter__ yields values in column order;
        # LogsTable.columns is the matching ordered list of names.
        return dict(zip(columns, row))

    # No columns provided for a non-dict row — this should never happen when
    # collect() passes table.columns correctly.  Log a warning so the bug is
    # visible rather than masked.
    row_index = getattr(row, "index", "unknown")
    logger.warning(
        "_row_to_dict: no column list provided for row index=%s (type=%s); "
        "yielding empty-data event — check that collect() passes table.columns",
        row_index,
        type(row).__name__,
    )
    return {}


def _row_to_raw_event(
    row: Any, received_at: datetime, columns: list[str] | None = None
) -> RawEvent:
    """Wrap a Log Analytics row in a ``RawEvent``.

    The full row dict becomes ``RawEvent.data``.  The normalizer reads whatever
    fields it recognizes and leaves the rest in ``raw_log`` for drill-down.
    """
    data = _row_to_dict(row, columns)
    # TimeGenerated may be a datetime object from the SDK — normalize to ISO string
    # so the normalizer's timestamp parser always gets a string.
    tg = data.get("TimeGenerated")
    if isinstance(tg, datetime):
        data["time"] = tg.isoformat()
    elif tg is not None:
        data["time"] = str(tg)

    # Canonicalize all three column regimes (resource_specific PascalCase,
    # azure_diagnostics _s/_d suffixed) into the uniform camelCase properties
    # shape that normalize.py reads.  canonicalize_row is a no-op for rows
    # that already carry a "properties" key (pre-formed JSON envelopes).
    data = canonicalize_row(data)

    return RawEvent(
        source_type="azure_waf",
        received_at=received_at,
        data=data,
    )


# ---------------------------------------------------------------------------
# Watermark window
# ---------------------------------------------------------------------------

def _compute_window(
    since: str | None,
    overlap_minutes: int,
) -> tuple[datetime, datetime]:
    """Return (since_dt, until_dt) for the KQL query window.

    - ``until_dt`` is always ``now(UTC)``.
    - ``since_dt``:
        - If ``since`` is None (first run): 24 hours ago.
        - Else: parse ``since`` minus ``overlap_minutes`` to catch late records.

    The 5-minute (or configured) overlap is the v1 technique kept per ADR-0024.
    """
    until_dt = datetime.now(timezone.utc)

    if since is None:
        since_dt = until_dt - timedelta(hours=24)
    else:
        try:
            since_dt = datetime.fromisoformat(since)
            if since_dt.tzinfo is None:
                since_dt = since_dt.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            logger.warning("AzureWAFClient: invalid since value %r; using 24h window", since)
            since_dt = until_dt - timedelta(hours=24)
        since_dt = since_dt - timedelta(minutes=overlap_minutes)

    return since_dt, until_dt


# ---------------------------------------------------------------------------
# Credential builder
# ---------------------------------------------------------------------------

def _build_credential(cfg: Any) -> Any:
    """Build an Azure credential from config.

    Uses ``ClientSecretCredential`` when tenant/client/secret are all set;
    falls back to ``DefaultAzureCredential`` otherwise.

    Raises ``AzureWAFAuthError`` (never a broad Exception) if the Azure SDK
    is not installed or if credential construction fails.

    Accesses the module-level ``ClientSecretCredential`` / ``DefaultAzureCredential``
    via ``globals()`` so that ``patch("firewatch_azure_waf.client.DefaultAzureCredential")``
    works in tests (same pattern as Suricata's ``globals().get("asyncssh")``).
    """
    _csc = globals().get("ClientSecretCredential")
    _dac = globals().get("DefaultAzureCredential")
    if _csc is None or _dac is None:  # pragma: no cover
        raise AzureWAFAuthError(
            "azure-identity is not installed.  "
            "Install with: pip install azure-identity"
        )

    if (
        cfg.tenant_id is not None
        and cfg.client_id is not None
        and cfg.client_secret is not None
    ):
        try:
            return _csc(
                tenant_id=cfg.tenant_id.get_secret_value(),
                client_id=cfg.client_id.get_secret_value(),
                client_secret=cfg.client_secret.get_secret_value(),
            )
        except Exception as exc:
            logger.debug(
                "_build_credential: ClientSecretCredential construction detail: %s", exc
            )
            raise AzureWAFAuthError(
                "Failed to build ClientSecretCredential — "
                "check tenant_id, client_id, and client_secret configuration"
            ) from exc

    try:
        cred = _dac()
        logger.info(
            "AzureWAFClient: using DefaultAzureCredential — "
            "ensure the identity holds Log Analytics Reader role on the workspace "
            "(least-privilege requirement)"
        )
        return cred
    except Exception as exc:
        logger.debug(
            "_build_credential: DefaultAzureCredential construction detail: %s", exc
        )
        raise AzureWAFAuthError(
            "Failed to build DefaultAzureCredential — "
            "check managed identity, az login, or AZURE_* environment variables"
        ) from exc


# ---------------------------------------------------------------------------
# Public collect coroutine (async generator)
# ---------------------------------------------------------------------------

async def collect(cfg: Any, since: str | None) -> AsyncIterator[RawEvent]:
    """Yield ``RawEvent``s from Azure Log Analytics for WAF events newer than ``since``.

    Args:
        cfg:   An ``AzureWAFConfig`` instance (typed as Any to avoid import cycle).
        since: ISO-8601 watermark string, or None for the initial 24-hour window.

    Raises:
        ``AzureWAFAuthError``    — credential acquisition or token failure.
        ``AzureWAFConnectError`` — network / endpoint unreachable.
        ``AzureWAFQueryError``   — bad workspace ID, unknown table, KQL syntax error.

    The caller (``plugin.collect``) catches ``asyncio.CancelledError`` and lets it
    propagate (PLUGIN_CONTRACT.md hard rule).  Other errors from this function
    are typed and intentionally surface to the supervisor rather than being
    silently swallowed (§3 critique #6).

    Accesses module-level ``LogsQueryClient`` / ``LogsQueryStatus`` via ``globals()``
    so that ``patch("firewatch_azure_waf.client.LogsQueryClient")`` works in tests
    (same pattern as Suricata's ``globals().get("asyncssh")`` in collector.py).
    """
    # Read module-level names through globals() so that unittest.mock.patch()
    # on ``firewatch_azure_waf.client.LogsQueryClient`` is respected at runtime.
    _lqc: Any = globals().get("LogsQueryClient")
    _lqs: Any = globals().get("LogsQueryStatus")
    if _lqc is None or _lqs is None:  # pragma: no cover
        raise AzureWAFAuthError(
            "azure-monitor-query is not installed.  "
            "Install with: pip install azure-monitor-query"
        )

    credential = _build_credential(cfg)

    since_dt, until_dt = _compute_window(since, cfg.overlap_minutes)

    kql_queries = build_kql(
        product=cfg.product,
        table_regime=cfg.table_regime,
        since_dt=since_dt,
        until_dt=until_dt,
    )

    received_at = datetime.now(timezone.utc)
    total_yielded = 0
    cap = cfg.max_events_per_collect

    try:
        client = _lqc(credential)
    except Exception as exc:
        raise AzureWAFConnectError(
            f"Failed to create LogsQueryClient: {exc}"
        ) from exc

    for kql in kql_queries:
        if total_yielded >= cap:
            logger.warning(
                "AzureWAFClient: max_events_per_collect=%d reached; stopping early", cap
            )
            break

        try:
            result = client.query_workspace(
                workspace_id=cfg.workspace_id,
                query=kql,
                timespan=None,  # time range is embedded in KQL WHERE clause
            )
        except Exception as exc:
            _raise_typed_error(exc)
            return  # unreachable; _raise_typed_error always raises

        if result.status == _lqs.PARTIAL:
            logger.warning(
                "AzureWAFClient: partial query result (workspace=%s); "
                "some rows may be missing",
                cfg.workspace_id,
            )
            # LogsQueryPartialResult uses .partial_data, not .tables
            tables_to_iter = result.partial_data  # type: ignore[union-attr]
        elif result.status == _lqs.SUCCESS:
            # LogsQueryResult uses .tables
            tables_to_iter = result.tables  # type: ignore[union-attr]
        else:
            raise AzureWAFQueryError(
                f"Log Analytics query failed for workspace {cfg.workspace_id!r}. "
                "Check workspace ID, table name, and permissions."
            )

        for table in tables_to_iter:
            for row in table.rows:
                if total_yielded >= cap:
                    logger.warning(
                        "AzureWAFClient: cap=%d reached mid-table; stopping", cap
                    )
                    return
                yield _row_to_raw_event(row, received_at, list(table.columns))
                total_yielded += 1

    logger.info(
        "AzureWAFClient.collect: yielded %d events (workspace=%s, since=%s)",
        total_yielded,
        cfg.workspace_id,
        since,
    )


# ---------------------------------------------------------------------------
# health_check probe
# ---------------------------------------------------------------------------

async def health_check(cfg: Any) -> bool:
    """Return True if the workspace is reachable and credentials are valid.

    Issues a minimal KQL query (limit 1, any category) to verify connectivity.
    Returns False (never raises) on any failure — surfaces cleanly to the
    Settings-card "Test" button (PLUGIN_CONTRACT.md health_check contract).

    Accesses module-level ``LogsQueryClient`` / ``LogsQueryStatus`` via ``globals()``
    so that ``patch("firewatch_azure_waf.client.LogsQueryClient")`` works in tests.
    """
    # Read module-level names through globals() so unittest.mock.patch() is respected.
    _lqc: Any = globals().get("LogsQueryClient")
    _lqs: Any = globals().get("LogsQueryStatus")
    if _lqc is None or _lqs is None:
        logger.warning("AzureWAFClient.health_check: azure-monitor-query not installed")
        return False

    try:
        credential = _build_credential(cfg)
    except AzureWAFError as exc:
        logger.warning("AzureWAFClient.health_check: credential error: %s", exc)
        return False

    probe_kql = (
        "AGWFirewallLogs\n"
        "| take 1\n"
        "| project TimeGenerated"
    )

    try:
        client = _lqc(credential)
        result = client.query_workspace(
            workspace_id=cfg.workspace_id,
            query=probe_kql,
            timespan=None,
        )
        return result.status in (
            _lqs.SUCCESS,
            _lqs.PARTIAL,
        )
    except Exception as exc:
        logger.warning("AzureWAFClient.health_check failed: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Error classifier
# ---------------------------------------------------------------------------

def _raise_typed_error(exc: BaseException) -> None:
    """Re-raise ``exc`` as a typed ``AzureWAFError`` subclass.

    Inspects the exception type and message to categorize it.
    Never swallows — always raises (§3 critique #6 anti-pattern avoided).
    """
    exc_type = type(exc).__name__
    msg = str(exc)

    auth_keywords = (
        "authentication", "unauthorized", "401", "403",
        "credential", "token", "permission", "access denied",
        "ClientAuthenticationError",
    )
    for kw in auth_keywords:
        if kw.lower() in msg.lower() or kw.lower() in exc_type.lower():
            raise AzureWAFAuthError(
                f"Azure authentication/authorization failure: {exc}"
            ) from exc

    network_keywords = (
        "connection", "network", "timeout", "unreachable",
        "resolve", "dns", "ServiceRequestError",
    )
    for kw in network_keywords:
        if kw.lower() in msg.lower() or kw.lower() in exc_type.lower():
            raise AzureWAFConnectError(
                f"Azure connectivity failure: {exc}"
            ) from exc

    # Default: treat as query error
    raise AzureWAFQueryError(
        f"Azure Log Analytics query error: {exc}"
    ) from exc
