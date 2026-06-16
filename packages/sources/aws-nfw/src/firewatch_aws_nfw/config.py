"""AWS Network Firewall plugin configuration.

Resolution order (ADR-0006): env vars > firewatch_config.json > hardcoded defaults.

AwsNetworkFirewallConfig is the Pydantic model returned by config_schema(). It drives
the rjsf UI source card (zero frontend code needed — the Settings card renders from
this schema alone per PLUGIN_CONTRACT.md).

AWS auth priority (mirroring AWS SDK behaviour):
  1. Explicit access_key_id + secret_access_key (config/env)
  2. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
  3. IAM instance profile / ECS task role / AWS SSO (SDK default chain)

SecretStr fields MUST default to None (PLUGIN_CONTRACT.md):
  The /sources/types discovery endpoint emits config_schema().model_json_schema()
  verbatim. A non-None secret default would leak into the API response.

Delivery mode:
  CloudWatch Logs is the only supported mode in this version.
  S3 export mode is out of scope per issue #603.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, SecretStr

logger = logging.getLogger("firewatch.aws_nfw.config")


class AwsNetworkFirewallConfig(BaseModel):
    """AWS Network Firewall CloudWatch Logs collector configuration.

    Connects to AWS CloudWatch Logs to collect Network Firewall alert logs.
    Credentials default to the AWS SDK credential chain (IAM instance profile,
    environment variables, or AWS SSO); explicit key fields are optional.
    """

    model_config = ConfigDict(extra="ignore")

    # ── AWS region ────────────────────────────────────────────────────────────
    region: str = Field(
        default="us-east-1",
        pattern=r"^[a-z0-9-]{1,30}$",
        title="AWS Region",
        description=(
            "AWS region where the Network Firewall and CloudWatch Logs group reside. "
            "For example: us-east-1, eu-west-1, ap-southeast-2."
        ),
    )

    # ── CloudWatch Logs ───────────────────────────────────────────────────────
    log_group_name: str = Field(
        default="",
        min_length=1,
        title="CloudWatch Log Group Name",
        description=(
            "Name of the CloudWatch Logs log group receiving Network Firewall alert logs. "
            "Typically /aws/network-firewall/<firewall-name>/alert. "
            "Found in the Logging section of the Network Firewall console."
        ),
    )

    # ── AWS credentials ───────────────────────────────────────────────────────
    # All secret fields MUST default to None (PLUGIN_CONTRACT.md):
    # the /sources/types discovery endpoint serializes config_schema().model_json_schema()
    # and Pydantic emits defaults verbatim — a non-None secret default leaks into the API.
    access_key_id: str | None = Field(
        default=None,
        title="AWS Access Key ID",
        description=(
            "AWS access key ID. Leave blank to use the default credential chain "
            "(IAM instance profile, environment variables, or AWS SSO)."
        ),
    )
    secret_access_key: SecretStr | None = Field(
        default=None,
        title="AWS Secret Access Key",
        description=(
            "AWS secret access key paired with the access key ID. "
            "Leave blank to use the default credential chain. "
            "This value is stored securely and never logged or returned in API responses."
        ),
    )
    # NOTE: STS cross-account role assumption (role_arn) is intentionally NOT
    # offered yet — a config field that the boto3 client silently ignores is a
    # dead-wired, trust-eroding control (PR #634 security review NB-1). Track
    # assume-role as a future enhancement before re-adding the field.

    # ── Query tuning ─────────────────────────────────────────────────────────
    overlap_minutes: int = Field(
        default=5,
        ge=0,
        le=60,
        title="Watermark Overlap (minutes)",
        description=(
            "How many minutes before the last-seen timestamp to re-query on each "
            "collection cycle. A small overlap catches log records that arrive at "
            "CloudWatch Logs slightly late. Default 5 minutes."
        ),
    )
    max_events_per_collect: int = Field(
        default=50_000,
        ge=1,
        le=1_000_000,
        title="Max Events Per Collect",
        description=(
            "Maximum number of events returned in a single collection cycle. "
            "Caps memory use when the log group contains a large backlog of logs."
        ),
    )


# ---------------------------------------------------------------------------
# build_config — env > file > default resolution (ADR-0006)
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG_FILE = Path("firewatch_config.json")

_ENV_MAP: dict[str, str] = {
    "region":                "FIREWATCH_AWS_NFW_REGION",
    "log_group_name":        "FIREWATCH_AWS_NFW_LOG_GROUP",
    "access_key_id":         "FIREWATCH_AWS_NFW_ACCESS_KEY_ID",
    "secret_access_key":     "FIREWATCH_AWS_NFW_SECRET_ACCESS_KEY",
    "overlap_minutes":       "FIREWATCH_AWS_NFW_OVERLAP_MINUTES",
    "max_events_per_collect": "FIREWATCH_AWS_NFW_MAX_EVENTS",
}

_INT_FIELDS = {"overlap_minutes", "max_events_per_collect"}
_SECRET_FIELDS = {"secret_access_key"}
_NULLABLE_FIELDS = {"access_key_id", "secret_access_key"}


def build_config(
    config_file: Path | str | None = _DEFAULT_CONFIG_FILE,
) -> AwsNetworkFirewallConfig:
    """Construct an AwsNetworkFirewallConfig with env > file > default precedence (ADR-0006).

    1. Start from Pydantic defaults.
    2. Apply values from the "aws_network_firewall" section of config_file (if present).
    3. Apply env vars (always win; cannot be overridden by file).

    config_file=None skips the file layer (useful in tests).
    """
    merged: dict[str, Any] = {}

    if config_file is not None:
        file_path = Path(config_file)
        if file_path.exists():
            try:
                raw = json.loads(file_path.read_text(encoding="utf-8"))
                section: dict[str, Any] = raw.get("aws_network_firewall") or {}
                for key in _ENV_MAP:
                    if key in section:
                        merged[key] = section[key]
            except Exception as exc:
                logger.warning("AwsNfwConfig: cannot read %s: %s", file_path, exc)

    for field, env_var in _ENV_MAP.items():
        raw_val = os.environ.get(env_var)
        if raw_val is not None:
            if field in _INT_FIELDS:
                try:
                    merged[field] = int(raw_val)
                except ValueError:
                    logger.warning("Invalid %s value %r; ignoring", env_var, raw_val)
            elif field in _NULLABLE_FIELDS and raw_val == "":
                merged[field] = None
            else:
                merged[field] = raw_val

    return AwsNetworkFirewallConfig.model_validate(merged)
