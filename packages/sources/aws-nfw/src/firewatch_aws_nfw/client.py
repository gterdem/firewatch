"""AWS CloudWatch Logs client for the AWS Network Firewall plugin.

Wraps boto3's CloudWatch Logs client to pull NFW alert records using a
watermark-windowed incremental pull — mirrors azure_waf's client.py approach
applied to a second cloud provider (docs/contract-stress-2026-06.md §Source 1).

Responsibilities:
  - Build the CloudWatch Logs filter_log_events request with the watermark window.
  - Handle pagination via nextToken.
  - Raise TYPED errors on credential or connectivity failures — never swallow them
    as "no data" (PLUGIN_CONTRACT.md hard rule / EARS-3).
  - Yield RawEvents wrapping the full AWS+EVE log event (no lossy projection).

Typed error hierarchy:
  AwsNfwError         — base
  AwsNfwAuthError     — credential/IAM failure (AccessDeniedException, etc.)
  AwsNfwConnectError  — network/endpoint unreachable
  AwsNfwQueryError    — bad log group name, throttling, other API errors

The module binds boto3 at module scope (try/except ImportError → None) so that
import firewatch_aws_nfw does NOT blow up when boto3 is absent, AND so that
patch("firewatch_aws_nfw.client.boto3") works in tests.

Pattern mirrors azure_waf's client.py LogsQueryClient lazy-bind approach.
"""
from __future__ import annotations

import json
import logging
from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone
from typing import Any

from firewatch_sdk import RawEvent

logger = logging.getLogger("firewatch.aws_nfw.client")

# ---------------------------------------------------------------------------
# Module-level boto3 reference — bound once at import time.
# Tests patch this name at module scope:
#   patch("firewatch_aws_nfw.client.boto3")
# The try/except keeps import firewatch_aws_nfw safe when boto3 is absent.
# ---------------------------------------------------------------------------

try:
    import boto3 as boto3  # noqa: PLC0414
except ImportError:  # pragma: no cover
    boto3 = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Typed error hierarchy (EARS-3)
# ---------------------------------------------------------------------------


class AwsNfwError(Exception):
    """Base class for AWS Network Firewall client errors."""


class AwsNfwAuthError(AwsNfwError):
    """Raised when credential acquisition or IAM authorization fails.

    Examples: AccessDeniedException, UnauthorizedException, ExpiredTokenException.
    Never silently swallowed — surfaces to the supervisor so the failing instance
    is isolated without masking the error as "no data" (PLUGIN_CONTRACT.md / EARS-3).
    """


class AwsNfwConnectError(AwsNfwError):
    """Raised on network / endpoint connectivity failures.

    Examples: EndpointConnectionError, socket timeouts, DNS resolution failures.
    """


class AwsNfwQueryError(AwsNfwError):
    """Raised when the CloudWatch Logs API call fails for non-auth reasons.

    Examples: ResourceNotFoundException (wrong log group), ThrottlingException,
    InvalidParameterException.
    """


# ---------------------------------------------------------------------------
# Auth error keywords for classification
# ---------------------------------------------------------------------------

_AUTH_ERROR_CODES = frozenset({
    "AccessDeniedException",
    "UnauthorizedException",
    "InvalidClientTokenId",
    "AuthFailure",
    "ExpiredTokenException",
    "InvalidSignatureException",
    "SignatureDoesNotMatch",
})

_CONNECT_ERROR_TYPES = frozenset({
    "EndpointConnectionError",
    "ConnectTimeoutError",
    "ReadTimeoutError",
    "ConnectionError",
})

# ---------------------------------------------------------------------------
# Watermark window
# ---------------------------------------------------------------------------


def _compute_window(since: str | None, overlap_minutes: int) -> tuple[int, int]:
    """Return (start_ms, end_ms) epoch-millisecond window for filter_log_events.

    CloudWatch Logs filter_log_events uses epoch milliseconds for startTime/endTime.

    - end_ms: always now(UTC) in ms.
    - start_ms:
        - If since is None (first run): 24 hours ago.
        - Else: parse since minus overlap_minutes to catch late-arriving records.

    The overlap mirrors azure_waf's technique (ADR-0024 kept technique).
    """
    now_utc = datetime.now(timezone.utc)
    end_ms = int(now_utc.timestamp() * 1000)

    if since is None:
        start_dt = now_utc - timedelta(hours=24)
    else:
        try:
            start_dt = datetime.fromisoformat(since)
            if start_dt.tzinfo is None:
                start_dt = start_dt.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            logger.warning("AwsNfwClient: invalid since value %r; using 24h window", since)
            start_dt = now_utc - timedelta(hours=24)
        start_dt = start_dt - timedelta(minutes=overlap_minutes)

    start_ms = int(start_dt.timestamp() * 1000)
    return start_ms, end_ms


# ---------------------------------------------------------------------------
# Credential + client builder
# ---------------------------------------------------------------------------


def _build_boto3_client(cfg: Any) -> Any:
    """Build a boto3 CloudWatch Logs client from config.

    Uses explicit credentials when access_key_id + secret_access_key are set;
    falls back to the SDK default credential chain (instance profile, env vars,
    AWS SSO) otherwise.

    Reads module-level boto3 via globals() so that
    patch("firewatch_aws_nfw.client.boto3") is respected in tests.
    """
    _boto3: Any = globals().get("boto3")
    if _boto3 is None:  # pragma: no cover
        raise AwsNfwAuthError(
            "boto3 is not installed. Install with: pip install boto3"
        )

    kwargs: dict[str, Any] = {"region_name": cfg.region}

    if cfg.access_key_id is not None and cfg.secret_access_key is not None:
        kwargs["aws_access_key_id"] = cfg.access_key_id
        kwargs["aws_secret_access_key"] = cfg.secret_access_key.get_secret_value()

    try:
        return _boto3.client("logs", **kwargs)
    except Exception as exc:
        # Redact boto3 detail from the raised message — it can surface AWS account
        # IDs / ARNs into shared logs (PR #634 review NB-4). Full detail stays on
        # the chained __cause__ and the DEBUG log.
        logger.debug("boto3 CloudWatch Logs client build failure: %s", exc)
        raise AwsNfwAuthError(
            "Failed to build boto3 CloudWatch Logs client "
            "(check region and credentials; see DEBUG logs for detail)."
        ) from exc


def _raise_typed_error(exc: BaseException) -> None:
    """Re-raise exc as a typed AwsNfwError subclass.

    Inspects botocore ClientError code and exception type to categorize.
    Never swallows — always raises (PLUGIN_CONTRACT.md hard rule / EARS-3).
    """
    # Check for botocore ClientError with an error code
    error_code: str = ""
    try:
        # botocore.exceptions.ClientError carries .response["Error"]["Code"]
        error_code = exc.response["Error"]["Code"]  # type: ignore[attr-defined]
    except (AttributeError, KeyError, TypeError):
        pass

    if error_code in _AUTH_ERROR_CODES:
        # Keep the AWS error code (a category, not sensitive); redact the full
        # message which can carry account IDs / ARNs (NB-4). Detail at DEBUG.
        logger.debug("AWS auth failure detail (%s): %s", error_code, exc)
        raise AwsNfwAuthError(
            f"AWS authentication/authorization failure ({error_code}); "
            "see DEBUG logs for detail."
        ) from exc

    exc_type_name = type(exc).__name__
    if exc_type_name in _CONNECT_ERROR_TYPES:
        raise AwsNfwConnectError(
            f"AWS connectivity failure ({exc_type_name}): {exc}"
        ) from exc

    # Check message/type for connection-like patterns (EndpointConnectionError etc.)
    msg = str(exc).lower()
    exc_type_lower = exc_type_name.lower()
    network_keywords = ("connection", "network", "timeout", "unreachable", "endpoint")
    for kw in network_keywords:
        if kw in msg or kw in exc_type_lower:
            raise AwsNfwConnectError(
                f"AWS connectivity failure: {exc}"
            ) from exc

    # Default: treat as query/API error (throttling, bad log group name, etc.)
    raise AwsNfwQueryError(
        f"AWS CloudWatch Logs API error: {exc}"
    ) from exc


# ---------------------------------------------------------------------------
# Log event → RawEvent conversion
# ---------------------------------------------------------------------------


def _parse_log_event(log_event: dict[str, Any], received_at: datetime) -> RawEvent | None:
    """Parse a single CloudWatch Logs event dict into a RawEvent.

    The CloudWatch Logs event message is a JSON string containing the AWS NFW
    log record (an AWS envelope wrapping Suricata EVE JSON).

    Returns None if the message cannot be parsed (caller logs and skips).

    Reference: AWS Network Firewall Developer Guide — CloudWatch Logs format:
      {"firewall_name":…, "availability_zone":…, "event_timestamp":…,
       "event": { <Suricata EVE JSON> }}
    """
    message = log_event.get("message", "")
    try:
        record: dict[str, Any] = json.loads(message)
    except (json.JSONDecodeError, ValueError):
        return None

    return RawEvent(
        source_type="aws_network_firewall",
        received_at=received_at,
        data=record,
    )


# ---------------------------------------------------------------------------
# Public collect coroutine (async generator)
# ---------------------------------------------------------------------------


async def collect(cfg: Any, since: str | None) -> AsyncIterator[RawEvent]:
    """Yield RawEvents from CloudWatch Logs for NFW events newer than since.

    Args:
        cfg:   An AwsNetworkFirewallConfig instance (typed as Any to avoid import cycle).
        since: ISO-8601 watermark string, or None for the initial 24-hour window.

    Raises:
        AwsNfwAuthError    — credential/IAM failure.
        AwsNfwConnectError — network/endpoint unreachable.
        AwsNfwQueryError   — bad log group name, throttling, other API errors.

    The caller (plugin.collect) catches asyncio.CancelledError and lets it propagate
    (PLUGIN_CONTRACT.md hard rule). Other errors from this function are typed and
    intentionally surface to the supervisor rather than being silently swallowed (EARS-3).

    Reads module-level boto3 via globals() so that
    patch("firewatch_aws_nfw.client.boto3") works in tests.
    """
    client = _build_boto3_client(cfg)

    start_ms, end_ms = _compute_window(since, cfg.overlap_minutes)
    received_at = datetime.now(timezone.utc)
    total_yielded = 0
    cap = cfg.max_events_per_collect

    request_kwargs: dict[str, Any] = {
        "logGroupName": cfg.log_group_name,
        "startTime": start_ms,
        "endTime": end_ms,
        "limit": min(10_000, cap),  # CloudWatch Logs max per page is 10,000
    }

    while True:
        if total_yielded >= cap:
            logger.warning(
                "AwsNfwClient: max_events_per_collect=%d reached; stopping early", cap
            )
            break

        try:
            response = client.filter_log_events(**request_kwargs)
        except Exception as exc:
            _raise_typed_error(exc)
            return  # unreachable; _raise_typed_error always raises

        events_page: list[dict[str, Any]] = response.get("events") or []
        for log_event in events_page:
            if total_yielded >= cap:
                logger.warning(
                    "AwsNfwClient: cap=%d reached mid-page; stopping", cap
                )
                return

            raw = _parse_log_event(log_event, received_at)
            if raw is None:
                logger.debug(
                    "AwsNfwClient: skipping unparseable log event message"
                )
                continue
            yield raw
            total_yielded += 1

        # Pagination: follow nextToken if present
        next_token = response.get("nextToken")
        if not next_token:
            break
        request_kwargs["nextToken"] = next_token

    logger.info(
        "AwsNfwClient.collect: yielded %d events (log_group=%s, since=%s)",
        total_yielded,
        cfg.log_group_name,
        since,
    )


# ---------------------------------------------------------------------------
# health_check probe
# ---------------------------------------------------------------------------


async def health_check(cfg: Any) -> bool:
    """Return True if CloudWatch Logs is reachable and credentials are valid.

    Issues a minimal describe_log_groups call to verify connectivity.
    Returns False (never raises) on any failure — surfaces cleanly to the
    Settings-card "Test" button (PLUGIN_CONTRACT.md health_check contract).

    Reads module-level boto3 via globals() so that
    patch("firewatch_aws_nfw.client.boto3") works in tests.
    """
    try:
        client = _build_boto3_client(cfg)
        client.describe_log_groups(
            logGroupNamePrefix=cfg.log_group_name,
            limit=1,
        )
        return True
    except Exception as exc:
        logger.warning("AwsNfwClient.health_check failed: %s", exc)
        return False
