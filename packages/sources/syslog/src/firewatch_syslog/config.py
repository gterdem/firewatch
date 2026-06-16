"""Syslog plugin configuration.

Resolution order (ADR-0006): env vars > firewatch_config.json > hardcoded defaults.

``SyslogConfig`` is the Pydantic model returned by ``config_schema()``. It drives the
rjsf UI source card.

``build_config`` constructs a resolved instance following the precedence chain. The UI
calls it with ``config_file`` pointing at the persisted ``firewatch_config.json``; tests
pass a ``tmp_path`` file or ``None`` to isolate env-var reads.

Security notes:
  - Default bind is 127.0.0.1 (loopback), not 0.0.0.0.  Operators who need to accept
    syslog from remote hosts must explicitly set FIREWATCH_SYSLOG_BIND or the
    ``firewatch_config.json`` ``bind`` field. Default port 5514 is above 1024 — no root
    privileges required.
  - The ``bind`` field is validated as an IP literal (ipaddress.ip_address) to prevent
    DNS-resolution-at-bind attacks (BLOCKING-2). Hostnames are rejected.
  - ``max_connections`` caps concurrent TCP connections (BLOCKING-1, slow-loris guard).
  - ``idle_timeout`` closes TCP connections that send no data for N seconds (BLOCKING-1).
  - ``max_line_length`` bounds the readline buffer passed to asyncio.start_server
    (BLOCKING-1) and truncates stored line content (NB-5).
"""
import ipaddress
import json
import logging
import os
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

logger = logging.getLogger("firewatch.syslog.config")


# ---------------------------------------------------------------------------
# Pydantic model — drives the rjsf UI card (PLUGIN_CONTRACT.md config_schema)
# ---------------------------------------------------------------------------


class SyslogConfig(BaseModel):
    """Syslog listener configuration.

    Controls the syslog listener: which address/port to bind, which transports
    to accept (UDP, TCP, or both), and safety limits for concurrent TCP
    connections, idle timeouts, and maximum line length.

    Default bind is 127.0.0.1 (loopback). Set to 0.0.0.0 or :: to accept
    from remote syslog sources. Default port 5514 is unprivileged (> 1024).
    """

    model_config = ConfigDict(extra="ignore")

    bind: str = Field(
        default="127.0.0.1",
        title="Bind address",
        description=(
            "IP address (literal) to bind the syslog listener to. Must be a valid IP "
            "literal — hostnames and FQDNs are rejected (DNS-resolution-at-bind vector). "
            "Default '127.0.0.1' (loopback — safe default). Set to '0.0.0.0' to accept "
            "from all IPv4 hosts. '::' is the IPv6 any-address — same exposure caveat as "
            "'0.0.0.0': accepts connections from ANY host on the network. "
            "SECURITY: '0.0.0.0' and '::' accept connections from ANY host on the network."
        ),
    )

    @field_validator("bind")
    @classmethod
    def _validate_bind_is_ip_literal(cls, v: str) -> str:
        """Reject hostnames; only accept valid IP literals (BLOCKING-2).

        Uses ipaddress.ip_address() which raises ValueError for non-literals.
        This also closes the DNS-resolution-at-bind vector: a hostname could resolve
        to an unintended address at bind time.
        """
        try:
            ipaddress.ip_address(v)
        except ValueError as exc:
            raise ValueError(
                f"bind must be a valid IP literal (e.g. '127.0.0.1', '0.0.0.0', '::1', '::'), "
                f"not a hostname or invalid string. Got: {v!r}"
            ) from exc
        return v

    port: int = Field(
        default=5514,
        ge=1,
        le=65535,
        title="Listening port",
        description=(
            "UDP/TCP port for the syslog listener. Default 5514 (unprivileged; above 1024 "
            "so no root needed). Standard syslog port 514 requires root."
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
            "Maximum number of RawEvents to coalesce into one emit() call. "
            "Bounds memory usage (DoS guard). Default 50."
        ),
    )

    max_connections: int = Field(
        default=256,
        ge=1,
        le=4096,
        title="Max TCP connections",
        description=(
            "Maximum number of concurrent TCP connections accepted by the listener. "
            "When the cap is reached, new connections are immediately closed. "
            "Increase if you have many syslog sources; lower it to limit resource usage. "
            "Default 256. Hard upper bound 4096."
        ),
    )

    idle_timeout: float = Field(
        default=30.0,
        gt=0.0,
        title="TCP idle timeout (seconds)",
        description=(
            "A TCP connection that sends no data for this many seconds is closed "
            "automatically. This frees connection slots for active syslog sources. "
            "Lower values evict silent connections faster; higher values tolerate "
            "infrequent senders. Default 30 seconds."
        ),
    )

    max_line_length: int = Field(
        default=8192,
        ge=128,
        le=1_048_576,
        title="Max line length (bytes)",
        description=(
            "Maximum syslog message length in bytes. Lines longer than this are truncated "
            "before processing. Increase for sources that emit structured (JSON) syslog "
            "lines; lower it to bound per-connection memory use. Default 8192 bytes."
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
# build_config — env > file > default resolution (ADR-0006)
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG_FILE = Path("firewatch_config.json")

# Mapping: config-field-name → env var name.
_ENV_MAP: dict[str, str] = {
    "bind":             "FIREWATCH_SYSLOG_BIND",
    "port":             "FIREWATCH_SYSLOG_PORT",
    "protocol":         "FIREWATCH_SYSLOG_PROTOCOL",
    "batch_size":       "FIREWATCH_SYSLOG_BATCH_SIZE",
    "max_connections":  "FIREWATCH_SYSLOG_MAX_CONNECTIONS",
    "idle_timeout":     "FIREWATCH_SYSLOG_IDLE_TIMEOUT",
    "max_line_length":  "FIREWATCH_SYSLOG_MAX_LINE_LENGTH",
}

# Fields that need integer coercion from env
_INT_FIELDS = {"port", "batch_size", "max_connections", "max_line_length"}
# Fields that need float coercion from env
_FLOAT_FIELDS = {"idle_timeout"}


def build_config(
    config_file: Path | str | None = _DEFAULT_CONFIG_FILE,
) -> SyslogConfig:
    """Construct a ``SyslogConfig`` with env > file > default precedence (ADR-0006).

    1. Start from Pydantic defaults.
    2. Apply any values found in the ``"syslog"`` section of *config_file*.
    3. Apply env vars — these always win; they can't be overridden.

    ``config_file=None`` skips the file layer (useful in tests).
    """
    merged: dict[str, Any] = {}

    # Layer 2: config file (lower priority than env)
    if config_file is not None:
        file_path = Path(config_file)
        if file_path.exists():
            try:
                raw = json.loads(file_path.read_text(encoding="utf-8"))
                section: dict[str, Any] = raw.get("syslog") or {}
                for key in _ENV_MAP:
                    if key in section:
                        merged[key] = section[key]
            except Exception as exc:
                logger.warning("SyslogConfig: cannot read %s: %s", file_path, exc)

    # Layer 3: env vars (highest priority — override file values)
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

    return SyslogConfig.model_validate(merged)
