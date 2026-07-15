"""ClamAV plugin configuration.

Resolution order (ADR-0006): env vars > firewatch_config.json > hardcoded defaults.

``ClamAVConfig`` is the Pydantic model returned by ``config_schema()``. It drives the rjsf
UI source card and carries the JSON Schema ``if/then/else`` conditional (ADR-0019, same
pattern as ``firewatch_suricata.config``) that reveals only the fields relevant to the
selected collection mode.

Two collection modes (ADR-0065 §3, local-first / journald-first):
  - ``"journald"`` (default) — reads ClamAV's detections from the systemd journal via the
    SDK's ``JournaldReader``. Works out of the box on any mainstream systemd distro
    (Arch, Ubuntu, Fedora, Debian) with zero path configuration, provided ClamAV is
    configured to log to syslog (``clamd.conf``'s ``LogSyslog true``) or the on-access
    daemon (``clamonacc``) does the same.
  - ``"file"`` — tails a plain ClamAV log file directly via the SDK's ``FileTailReader``.
    The non-systemd fallback (issue #2 acceptance criteria).

``build_config`` constructs a resolved instance following the precedence chain. The UI
calls it with ``config_file`` pointing at the persisted ``firewatch_config.json``; tests
pass a ``tmp_path`` file or ``None`` to isolate env-var reads.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger("firewatch.clamav.config")


# ---------------------------------------------------------------------------
# JSON Schema if/then/else helper (must be defined before ClamAVConfig uses it)
# ---------------------------------------------------------------------------


def _build_if_then_else(schema: dict[str, Any]) -> None:
    """Inject JSON Schema ``if/then/else`` for the journald/file mode toggle.

    rjsf uses this to show only the mode-relevant fields in the source card (ADR-0019),
    mirroring ``firewatch_suricata.config._build_if_then_else`` (reveal-not-require,
    ADR-0028 D5): conditional fields are popped out of top-level ``properties`` and
    carried into the matching branch's ``then``/``else``, so rjsf never renders both
    branches at once.
    """
    props: dict[str, Any] = schema.setdefault("properties", {})

    # File-mode-only fields: pop from top-level, carry real sub-schemas into "then".
    file_only_fields = ("log_path", "follow_symlinks")
    then_props: dict[str, Any] = {}
    for field in file_only_fields:
        if field in props:
            then_props[field] = props.pop(field)

    # Journald-mode-only field: pop from top-level, carry real sub-schema into "else".
    else_props: dict[str, Any] = {}
    if "identifiers" in props:
        else_props["identifiers"] = props.pop("identifiers")

    schema["if"] = {
        "properties": {"mode": {"const": "file"}},
        "required": ["mode"],
    }
    schema["then"] = {"properties": then_props, "required": ["log_path"]}
    schema["else"] = {"properties": else_props, "required": []}


# ---------------------------------------------------------------------------
# Pydantic model — drives the rjsf UI card (PLUGIN_CONTRACT.md config_schema)
# ---------------------------------------------------------------------------


class ClamAVConfig(BaseModel):
    """ClamAV collector configuration.

    Choose between reading ClamAV detections from the systemd journal
    ("journald" mode, default — ADR-0065 journald-first principle) or tailing
    ClamAV's plain-text log file directly ("file" mode — the non-systemd
    fallback). Only the fields relevant to the selected mode are shown in the
    Settings card.

    ``journalctl_bin`` is deliberately NOT exposed here: ``JournaldReader``'s own
    docstring warns that a bare, PATH-resolved binary name accepted from
    operator-facing config is a PATH-hijack surface once surfaced through a
    schema-driven Settings card — exactly what this config schema is. Omitting
    the field closes that surface rather than requiring an absolute-path
    validator no one asked for.
    """

    model_config = ConfigDict(
        # Carry extra undeclared fields from the config file without error;
        # unknown vendor fields stay opaque (PLUGIN_CONTRACT.md).
        extra="ignore",
        # Use JSON schema with if/then/else for the rjsf mode toggle.
        json_schema_extra=_build_if_then_else,
    )

    mode: Literal["journald", "file"] = Field(
        default="journald",
        title="Collection mode",
        description=(
            "'journald' (default) reads ClamAV detections from the systemd journal — "
            "works out of the box on any mainstream systemd distro with zero path "
            "configuration, provided ClamAV logs to syslog (clamd.conf's "
            "'LogSyslog true', or the clamonacc on-access scanner). 'file' tails a "
            "plain ClamAV log file directly — the fallback for non-systemd hosts."
        ),
    )

    # ── journald mode ────────────────────────────────────────────────────────

    identifiers: list[str] = Field(
        default_factory=lambda: ["clamd", "clamonacc"],
        title="journald identifiers",
        description=(
            "SYSLOG_IDENTIFIER values to match in journald mode. 'clamd' is the "
            "resident daemon; 'clamonacc' is the on-access scanner. Add 'clamscan' or "
            "'clamdscan' if you invoke those directly with syslog logging configured. "
            "Ignored in file mode."
        ),
    )

    # ── file mode ─────────────────────────────────────────────────────────────

    log_path: str = Field(
        default="/var/log/clamav/clamav.log",
        title="ClamAV log file path",
        description=(
            "Path to ClamAV's plain-text log file, tailed in file mode (the "
            "non-systemd fallback). Point clamd.conf's LogFile (or clamscan/"
            "clamdscan's --log) at this path. Ignored in journald mode."
        ),
    )

    follow_symlinks: bool = Field(
        default=False,
        title="Follow a symlinked log path",
        description=(
            "File mode only. By default a symlink at log_path is refused — a "
            "compromised process with write access to the log directory could "
            "otherwise redirect the reader to an arbitrary file (see "
            "FileTailReader's security note). Enable only if your distro's ClamAV "
            "package legitimately symlinks its log file to a canonical name."
        ),
    )


# ---------------------------------------------------------------------------
# build_config — env > file > default resolution (ADR-0006)
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG_FILE = Path("firewatch_config.json")

# Mapping: config-field-name → env var name.
_ENV_MAP: dict[str, str] = {
    "mode":             "FIREWATCH_CLAMAV_MODE",
    "identifiers":      "FIREWATCH_CLAMAV_IDENTIFIERS",
    "log_path":         "FIREWATCH_CLAMAV_LOG_PATH",
    "follow_symlinks":  "FIREWATCH_CLAMAV_FOLLOW_SYMLINKS",
}


def build_config(
    config_file: Path | str | None = _DEFAULT_CONFIG_FILE,
) -> ClamAVConfig:
    """Construct a ``ClamAVConfig`` with env > file > default precedence (ADR-0006).

    1. Start from Pydantic defaults.
    2. Apply any values found in the ``"clamav"`` section of *config_file*.
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
                section: dict[str, Any] = raw.get("clamav") or {}
                for key in _ENV_MAP:
                    if key in section:
                        merged[key] = section[key]
            except Exception as exc:
                logger.warning("ClamAVConfig: cannot read %s: %s", file_path, exc)

    # Layer 3: env vars (highest priority — override file values)
    for field, env_var in _ENV_MAP.items():
        raw_val = os.environ.get(env_var)
        if raw_val is None:
            continue
        if field == "identifiers":
            merged[field] = [v.strip() for v in raw_val.split(",") if v.strip()]
        elif field == "follow_symlinks":
            merged[field] = raw_val.lower() not in ("false", "0", "no")
        else:
            merged[field] = raw_val

    return ClamAVConfig.model_validate(merged)
