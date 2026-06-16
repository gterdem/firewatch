"""Azure WAF plugin configuration.

Resolution order (ADR-0006): env vars > firewatch_config.json > hardcoded defaults.

``AzureWAFConfig`` is the Pydantic model returned by ``config_schema()``.  It drives
the rjsf UI source card (zero frontend code needed — the Settings card renders from
this schema alone per PLUGIN_CONTRACT.md).

Table regime (azure-waf-log-standard.md §1d):
  - ``resource_specific`` (default): query resource-specific tables
    ``AGWFirewallLogs`` / ``AzureFrontDoorWebApplicationFirewallLog``.
  - ``azure_diagnostics``: query the legacy ``AzureDiagnostics`` shared table.
  Selection is EXPLICIT config — NOT a speculative try/except (§3 critique #6).

Product selection:
  - ``app_gateway``: Application Gateway WAF (``ApplicationGatewayFirewallLog``).
  - ``front_door``: Front Door WAF (``FrontDoorWebApplicationFirewallLog``).
  - ``both``: query both (default).

Credentials:
  - ``DefaultAzureCredential`` is used unless explicit overrides are set.
  - Tenant/client/secret fields use ``SecretStr`` and default to ``None``
    (PLUGIN_CONTRACT.md: SecretStr fields MUST default to None so the schema
    discovery endpoint never leaks secrets in the emitted default).
"""
from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

logger = logging.getLogger("firewatch.azure_waf.config")

ProductLiteral = Literal["app_gateway", "front_door", "both"]
TableRegimeLiteral = Literal["resource_specific", "azure_diagnostics"]


# GUID pattern per RFC 4122 §3 (case-insensitive 8-4-4-4-12 hex groups).
# Used by the workspace_id validator — defined at module level to avoid
# recompiling the pattern on every validation call.
_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
    r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


class AzureWAFConfig(BaseModel):
    """Azure WAF Log Analytics collector configuration.

    Connects to a Log Analytics workspace to collect Azure WAF firewall logs
    from Application Gateway WAF or Azure Front Door WAF (or both). Credentials
    default to DefaultAzureCredential (managed identity, az login, or
    environment variables); explicit service-principal fields are optional.
    """
    # Developer notes:
    # - Credential fields use SecretStr so secrets are never logged or emitted
    #   in API responses (PLUGIN_CONTRACT.md: SecretStr fields MUST default to None
    #   so the /sources/types discovery endpoint never leaks secrets).

    model_config = ConfigDict(extra="ignore")

    # ── Log Analytics workspace ───────────────────────────────────────────────
    workspace_id: str = Field(
        default="",
        title="Log Analytics Workspace ID",
        description=(
            "The GUID of the Log Analytics workspace that receives Azure WAF "
            "diagnostic logs.  Found under the workspace's 'Overview' blade in "
            "the Azure portal."
        ),
    )

    @field_validator("workspace_id")
    @classmethod
    def workspace_id_must_be_guid(cls, v: str) -> str:
        """Enforce GUID format for workspace_id.

        Fails at validate_config/Settings-save time with a clear error rather
        than an opaque query error when the Log Analytics workspace ID is
        malformed.  GUID pattern per RFC 4122 §3 (case-insensitive hex groups).
        """
        if v and not _GUID_RE.match(v):
            raise ValueError(
                f"workspace_id must be a valid GUID "
                f"(e.g. 12345678-1234-1234-1234-123456789abc); got {v!r}"
            )
        return v

    # ── Table regime ──────────────────────────────────────────────────────────
    table_regime: TableRegimeLiteral = Field(
        default="resource_specific",
        title="Table Regime",
        description=(
            "Which Log Analytics table layout to query.  "
            "'resource_specific' (recommended) queries typed resource tables "
            "(AGWFirewallLogs, AzureFrontDoorWebApplicationFirewallLog).  "
            "'azure_diagnostics' queries the legacy AzureDiagnostics shared table "
            "with _s/_d column suffixes.  Select explicitly — not auto-detected."
        ),
    )

    # ── Product filter ────────────────────────────────────────────────────────
    product: ProductLiteral = Field(
        default="both",
        title="WAF Product",
        description=(
            "Which Azure WAF product to collect from.  "
            "'app_gateway' = Application Gateway WAF; "
            "'front_door' = Azure Front Door WAF; "
            "'both' = query both products."
        ),
    )

    # ── Credentials ───────────────────────────────────────────────────────────
    # All secret fields MUST default to None (PLUGIN_CONTRACT.md):
    # the /sources/types discovery endpoint serializes config_schema().model_json_schema()
    # and Pydantic emits defaults verbatim — a non-None secret would appear in the API.
    tenant_id: SecretStr | None = Field(
        default=None,
        title="Azure Tenant ID",
        description=(
            "Azure AD tenant ID.  Leave blank to use DefaultAzureCredential "
            "auto-discovery (managed identity / az login / env vars)."
        ),
    )
    client_id: SecretStr | None = Field(
        default=None,
        title="Service Principal Client ID",
        description=(
            "Client (application) ID of the service principal.  "
            "Required only when using explicit service-principal credentials; "
            "leave blank for managed identity or az login."
        ),
    )
    client_secret: SecretStr | None = Field(
        default=None,
        title="Service Principal Client Secret",
        description=(
            "Client secret for the service principal.  "
            "Required only when using explicit service-principal credentials; "
            "leave blank for managed identity or az login.  "
            "This value is stored securely and never logged or returned in API responses."
        ),
    )

    # ── Query tuning ─────────────────────────────────────────────────────────
    overlap_minutes: int = Field(
        default=5,
        ge=0,
        le=60,
        title="Watermark Overlap (minutes)",
        description=(
            "How many minutes before the last-seen timestamp to re-query on each "
            "collection cycle. A small overlap catches log records that arrive at "
            "Log Analytics slightly late. Default 5 minutes."
        ),
    )
    max_events_per_collect: int = Field(
        default=50_000,
        ge=1,
        le=1_000_000,
        title="Max Events Per Collect",
        description="Maximum number of events returned in a single collection cycle. Caps memory use when the workspace contains a large backlog of logs.",
    )


# ---------------------------------------------------------------------------
# build_config — env > file > default resolution (ADR-0006)
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG_FILE = Path("firewatch_config.json")

_ENV_MAP: dict[str, str] = {
    "workspace_id":           "FIREWATCH_AZURE_WAF_WORKSPACE_ID",
    "table_regime":           "FIREWATCH_AZURE_WAF_TABLE_REGIME",
    "product":                "FIREWATCH_AZURE_WAF_PRODUCT",
    "tenant_id":              "FIREWATCH_AZURE_WAF_TENANT_ID",
    "client_id":              "FIREWATCH_AZURE_WAF_CLIENT_ID",
    "client_secret":          "FIREWATCH_AZURE_WAF_CLIENT_SECRET",
    "overlap_minutes":        "FIREWATCH_AZURE_WAF_OVERLAP_MINUTES",
    "max_events_per_collect": "FIREWATCH_AZURE_WAF_MAX_EVENTS",
}


def build_config(config_file: Path | str | None = _DEFAULT_CONFIG_FILE) -> AzureWAFConfig:
    """Construct an ``AzureWAFConfig`` with env > file > default precedence (ADR-0006).

    1. Start from Pydantic defaults.
    2. Apply values from the ``"azure_waf"`` section of *config_file* (if present).
    3. Apply env vars (always win; cannot be overridden by file).

    ``config_file=None`` skips the file layer (useful in tests).
    """
    merged: dict[str, Any] = {}

    if config_file is not None:
        file_path = Path(config_file)
        if file_path.exists():
            try:
                raw = json.loads(file_path.read_text(encoding="utf-8"))
                section: dict[str, Any] = raw.get("azure_waf") or {}
                for key in _ENV_MAP:
                    if key in section:
                        merged[key] = section[key]
            except Exception as exc:
                logger.warning("AzureWAFConfig: cannot read %s: %s", file_path, exc)

    for field, env_var in _ENV_MAP.items():
        raw_val = os.environ.get(env_var)
        if raw_val is not None:
            if field in ("overlap_minutes", "max_events_per_collect"):
                try:
                    merged[field] = int(raw_val)
                except ValueError:
                    logger.warning("Invalid %s value %r; ignoring", env_var, raw_val)
            elif field in ("tenant_id", "client_id", "client_secret") and raw_val == "":
                merged[field] = None
            else:
                merged[field] = raw_val

    return AzureWAFConfig.model_validate(merged)
