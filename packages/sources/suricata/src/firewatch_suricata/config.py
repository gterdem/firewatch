"""Suricata plugin configuration.

Resolution order (ADR-0006): env vars > firewatch_config.json > hardcoded defaults.

``SuricataConfig`` is the Pydantic model returned by ``config_schema()``. It drives the
rjsf UI source card and carries the JSON Schema ``if/then/else`` conditional that shows
only the relevant fields for the selected mode (ADR-0019).

``build_config`` constructs a resolved instance following the precedence chain. The UI
calls it with ``config_file`` pointing at the persisted ``firewatch_config.json``; tests
pass a ``tmp_path`` file or ``None`` to isolate env-var reads.
"""
import json
import logging
import os
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr

logger = logging.getLogger("firewatch.suricata.config")


# ---------------------------------------------------------------------------
# JSON Schema if/then/else helper (must be defined before SuricataConfig uses it)
# ---------------------------------------------------------------------------


def _build_if_then_else(schema: dict[str, Any]) -> None:
    """Inject JSON Schema ``if/then/else`` for the local/remote mode toggle.

    rjsf uses this to show only the mode-relevant fields in the source card
    (ADR-0019 / ADR-0028 D5). Called by Pydantic v2 as the ``json_schema_extra``
    callable with signature ``(schema: dict) -> None``. The mutation happens
    in-place on the schema dict Pydantic has assembled.

    ADR-0028 D5 — reveal-not-require:
        Branch ``properties`` entries *reveal* fields to rjsf / AJV when the
        condition matches. The corresponding conditional fields must be ABSENT
        from top-level ``properties`` — otherwise rjsf renders them in both
        modes regardless of the branch (branch properties are additive, not
        filtering). This function ``pop``s each conditional field out of
        top-level ``schema["properties"]`` before placing its real sub-schema
        (the popped value) into the appropriate branch. Only ``mode`` (and any
        future always-shown field) stays at top level.

        ``@rjsf/validator-ajv8`` (AJV 2020-12) evaluates ``if/then/else``
        including nested ``properties`` at form-render time.

    Fix for issue #49 (regression from #45):
        The previous implementation left all fields in top-level ``properties``
        (Pydantic's default) and put empty ``{}`` placeholders in the branches.
        That produced "require, not reveal" — all fields were always visible.
        This version pops each conditional field from top-level and carries the
        real Pydantic-generated sub-schema into the matching branch.
    """
    props: dict[str, Any] = schema.setdefault("properties", {})

    # Remote-only fields: pop from top-level, carry real sub-schemas into then.
    remote_only_fields = (
        "remote_host", "remote_port", "remote_user",
        "remote_key", "remote_path", "verify_host_key",
    )
    then_props: dict[str, Any] = {}
    for field in remote_only_fields:
        if field in props:
            then_props[field] = props.pop(field)

    # Local-only field: pop from top-level, carry real sub-schema into else.
    else_props: dict[str, Any] = {}
    if "local_path" in props:
        else_props["local_path"] = props.pop("local_path")

    schema["if"] = {
        "properties": {"mode": {"const": "remote"}},
        "required": ["mode"],
    }
    # Remote-mode branch: reveal SSH fields (moved from top-level); require remote_host.
    schema["then"] = {
        "properties": then_props,
        "required": ["remote_host"],
    }
    # Local-mode branch: reveal local_path (moved from top-level); require local_path.
    schema["else"] = {
        "properties": else_props,
        "required": ["local_path"],
    }


# ---------------------------------------------------------------------------
# Pydantic model — drives the rjsf UI card (PLUGIN_CONTRACT.md config_schema)
# ---------------------------------------------------------------------------


class SuricataConfig(BaseModel):
    """Suricata collector configuration.

    Choose between reading the Suricata EVE JSON log file from the local
    filesystem ("local" mode) or pulling it from a remote host over SSH
    ("remote" mode). Only the fields relevant to the selected mode are shown
    in the Settings card.
    """
    # Developer notes:
    # - The emitted JSON Schema uses if/then/else so rjsf only renders
    #   mode-relevant fields (ADR-0019, _build_if_then_else).
    # - SSH key field (remote_key) uses SecretStr — never plain str
    #   (PLUGIN_CONTRACT.md hard rule).

    model_config = ConfigDict(
        # Carry extra undeclared fields from the config file without error;
        # unknown vendor fields stay opaque (PLUGIN_CONTRACT.md).
        extra="ignore",
        # Use JSON schema with if/then/else for the rjsf mode toggle.
        json_schema_extra=_build_if_then_else,
    )

    mode: Literal["local", "remote"] = Field(
        default="local",
        title="Collection Mode",
        description="'local' reads eve.json from the filesystem; 'remote' pulls via SSH.",
    )

    # ── Local mode ────────────────────────────────────────────────────────────

    local_path: str = Field(
        default="/var/log/suricata/eve.json",
        title="EVE JSON path",
        description="Path to the Suricata eve.json file (local mode only).",
    )
    # SECURITY NOTE: production hardening could restrict local_path to expected
    # prefixes (e.g. /var/log) via a Pydantic validator to prevent path traversal.
    # Current threat model is trusted-operator; no behavior change is required here.

    # ── Rule descriptions ─────────────────────────────────────────────────────

    rules_path: str = Field(
        default="/etc/suricata/rules",
        title="Suricata rules path",
        description=(
            "Path to a Suricata .rules file or directory of .rules files. "
            "Local mode: SID to description names load automatically each sync. "
            "Remote mode: names load ONLY when you click Fetch Ruleset "
            "(no automatic download over SSH). "
            "Leave blank to skip rule-name display (scoring still works on rule IDs)."
        ),
    )

    # ── Remote mode ───────────────────────────────────────────────────────────

    remote_host: str = Field(
        default="",
        title="Remote host",
        description="Hostname or IP of the Suricata host (remote mode only).",
    )
    remote_port: int = Field(
        default=22,
        ge=1,
        le=65535,
        title="SSH port",
        description="SSH port (remote mode only).",
    )
    remote_user: str | None = Field(
        default=None,
        title="SSH user",
        description="SSH username; defaults to the current OS user if not set.",
    )
    remote_key: SecretStr | None = Field(
        default=None,
        title="SSH private key path",
        description=(
            "Path to the SSH private key file (e.g. ~/.ssh/id_rsa). "
            "Leave blank to use SSH agent or default keys."
        ),
    )
    remote_path: str = Field(
        default="/var/log/suricata/eve.json",
        title="Remote EVE JSON path",
        description="Path to eve.json on the remote host.",
    )
    verify_host_key: bool = Field(
        default=True,
        title="Verify SSH host key",
        description=(
            "Leave ON. asyncssh validates the host key against ~/.ssh/known_hosts — "
            "run 'ssh <user>@<host>' once first to accept the key. "
            "Turn OFF only for sensors whose host key legitimately rotates "
            "(e.g. re-imaged VMs); doing so removes MITM protection and "
            "logs a warning on every connection."
        ),
    )


# ---------------------------------------------------------------------------
# build_config — env > file > default resolution (ADR-0006)
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG_FILE = Path("firewatch_config.json")

# Mapping: config-field-name → env var name.
# Env vars always win; a present env var locks its field against file overrides.
_ENV_MAP: dict[str, str] = {
    "mode":             "FIREWATCH_SURICATA_MODE",
    "local_path":       "FIREWATCH_SURICATA_EVE_PATH",
    "rules_path":       "FIREWATCH_SURICATA_RULES_PATH",
    "remote_host":      "FIREWATCH_SURICATA_REMOTE_HOST",
    "remote_port":      "FIREWATCH_SURICATA_REMOTE_PORT",
    "remote_user":      "FIREWATCH_SURICATA_REMOTE_USER",
    "remote_key":       "FIREWATCH_SURICATA_REMOTE_KEY",
    "remote_path":      "FIREWATCH_SURICATA_REMOTE_PATH",
    "verify_host_key":  "FIREWATCH_SURICATA_VERIFY_HOST_KEY",
}


def build_config(
    config_file: Path | str | None = _DEFAULT_CONFIG_FILE,
) -> SuricataConfig:
    """Construct a ``SuricataConfig`` with env > file > default precedence (ADR-0006).

    1. Start from Pydantic defaults.
    2. Apply any values found in the ``"suricata"`` section of *config_file*.
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
                section: dict[str, Any] = raw.get("suricata") or {}
                for key in _ENV_MAP:
                    if key in section:
                        merged[key] = section[key]
            except Exception as exc:
                logger.warning("SuricataConfig: cannot read %s: %s", file_path, exc)

    # Layer 3: env vars (highest priority — lock out file values)
    for field, env_var in _ENV_MAP.items():
        raw_val = os.environ.get(env_var)
        if raw_val is not None:
            # Cast to the right type before handing to Pydantic.
            if field == "remote_port":
                try:
                    merged[field] = int(raw_val)
                except ValueError:
                    logger.warning("Invalid %s value %r; ignoring", env_var, raw_val)
            elif field == "verify_host_key":
                merged[field] = raw_val.lower() not in ("false", "0", "no")
            elif field in ("remote_user", "remote_key") and raw_val == "":
                merged[field] = None
            else:
                merged[field] = raw_val

    return SuricataConfig.model_validate(merged)
