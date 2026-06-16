"""SyslogCefConfig — configuration for the Generic Syslog/CEF receiver.

Extends the same listener fields as SyslogConfig (bind/port/protocol/limits)
and adds CEF/format-selection fields.

Resolution order (ADR-0006): env vars > firewatch_config.json > defaults.

Security notes (same hardening as firewatch_syslog.config):
  - Default bind is 127.0.0.1 (loopback). Set to 0.0.0.0 to accept remote senders.
  - bind is validated as an IP literal (prevents DNS-resolution-at-bind attacks).
  - max_connections caps concurrent TCP connections (slow-loris guard).
  - idle_timeout closes silent TCP connections.
  - max_line_length bounds readline buffer and stored line content.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

logger = logging.getLogger("firewatch.syslog_cef.config")


class SyslogCefConfig(BaseModel):
    """Generic Syslog/CEF receiver configuration.

    Listens for syslog messages (RFC 5424, RFC 3164) and ArcSight CEF events
    on UDP, TCP, or both. CEF messages are parsed using the standard
    DeviceVendor/DeviceProduct->action registry; unknown vendors use the
    generic CEF dictionary mapping.

    Default bind is 127.0.0.1 (loopback). Set to 0.0.0.0 to accept
    from remote syslog/CEF sources. Default port 5515 (unprivileged).
    """

    model_config = ConfigDict(extra="ignore")

    bind: str = Field(
        default="127.0.0.1",
        title="Bind address",
        description=(
            "IP address (literal) to bind the listener to. Must be a valid IP "
            "literal — hostnames are rejected. "
            "Default '127.0.0.1' (loopback). Set to '0.0.0.0' to accept "
            "from all IPv4 syslog/CEF sources. "
            "SECURITY: '0.0.0.0' and '::' accept connections from any host."
        ),
    )

    @field_validator("bind")
    @classmethod
    def _validate_bind_is_ip_literal(cls, v: str) -> str:
        """Reject hostnames; only accept valid IP literals."""
        try:
            ipaddress.ip_address(v)
        except ValueError as exc:
            raise ValueError(
                f"bind must be a valid IP literal (e.g. '127.0.0.1', '0.0.0.0', '::'), "
                f"not a hostname. Got: {v!r}"
            ) from exc
        return v

    port: int = Field(
        default=5515,
        ge=1,
        le=65535,
        title="Listening port",
        description=(
            "UDP/TCP port for the syslog/CEF listener. Default 5515 (unprivileged). "
            "Standard syslog port 514 requires root privileges."
        ),
    )

    protocol: Literal["udp", "tcp", "both"] = Field(
        default="udp",
        title="Transport protocol",
        description="'udp' (default), 'tcp', or 'both' — which transports to listen on.",
    )

    batch_size: int = Field(
        default=50,
        ge=1,
        le=1000,
        title="Batch size",
        description=(
            "Maximum number of events to coalesce into one emit() call. "
            "Bounds memory usage. Default 50."
        ),
    )

    max_connections: int = Field(
        default=256,
        ge=1,
        le=4096,
        title="Max TCP connections",
        description=(
            "Maximum number of concurrent TCP connections. New connections above "
            "this cap are immediately closed. Default 256."
        ),
    )

    idle_timeout: float = Field(
        default=30.0,
        gt=0.0,
        title="TCP idle timeout (seconds)",
        description=(
            "A TCP connection that sends no data for this many seconds is closed. "
            "Default 30 seconds."
        ),
    )

    max_line_length: int = Field(
        default=8192,
        ge=128,
        le=1_048_576,
        title="Max line length (bytes)",
        description=(
            "Maximum syslog/CEF message length in bytes. Messages longer than this "
            "are truncated before processing. Default 8192 bytes."
        ),
    )

    @classmethod
    def model_json_schema(cls, *args: Any, **kwargs: Any) -> dict[str, Any]:
        """Inject `bind` and `port` into the JSON-schema `required` array.

        This is a UI-presentation hint for partitionFields (issue #686, ADR-0028):
        `required` fields are shown as Essential; everything else is Advanced/Optional.
        `bind` and `port` are the only fields the operator must examine on first run.

        `required` here is NOT enforced server-side — the Pydantic model retains its
        field defaults so configure-with-defaults (ADR-0006) is completely unchanged;
        `model_validate({})` still succeeds.
        """
        schema = super().model_json_schema(*args, **kwargs)
        req: list[str] = schema.setdefault("required", [])
        for name in ("bind", "port"):
            if name not in req:
                req.append(name)
        return schema


# ---------------------------------------------------------------------------
# build_config -- env > file > default resolution (ADR-0006)
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG_FILE = Path("firewatch_config.json")

_ENV_MAP: dict[str, str] = {
    "bind":             "FIREWATCH_SYSLOG_CEF_BIND",
    "port":             "FIREWATCH_SYSLOG_CEF_PORT",
    "protocol":         "FIREWATCH_SYSLOG_CEF_PROTOCOL",
    "batch_size":       "FIREWATCH_SYSLOG_CEF_BATCH_SIZE",
    "max_connections":  "FIREWATCH_SYSLOG_CEF_MAX_CONNECTIONS",
    "idle_timeout":     "FIREWATCH_SYSLOG_CEF_IDLE_TIMEOUT",
    "max_line_length":  "FIREWATCH_SYSLOG_CEF_MAX_LINE_LENGTH",
}

_INT_FIELDS = {"port", "batch_size", "max_connections", "max_line_length"}
_FLOAT_FIELDS = {"idle_timeout"}


def build_config(config_file: Path | str | None = _DEFAULT_CONFIG_FILE) -> SyslogCefConfig:
    """Construct a SyslogCefConfig with env > file > default precedence (ADR-0006)."""
    merged: dict[str, Any] = {}

    if config_file is not None:
        file_path = Path(config_file)
        if file_path.exists():
            try:
                raw = json.loads(file_path.read_text(encoding="utf-8"))
                section: dict[str, Any] = raw.get("syslog_cef") or {}
                for key in _ENV_MAP:
                    if key in section:
                        merged[key] = section[key]
            except Exception as exc:
                logger.warning("SyslogCefConfig: cannot read %s: %s", file_path, exc)

    for field, env_var in _ENV_MAP.items():
        raw_val = os.environ.get(env_var)
        if raw_val is not None:
            if field in _INT_FIELDS:
                try:
                    merged[field] = int(raw_val)
                except ValueError:
                    logger.warning("Invalid %s value %r; ignoring", env_var, raw_val)
            elif field in _FLOAT_FIELDS:
                try:
                    merged[field] = float(raw_val)
                except ValueError:
                    logger.warning("Invalid %s value %r; ignoring", env_var, raw_val)
            else:
                merged[field] = raw_val

    return SyslogCefConfig.model_validate(merged)
