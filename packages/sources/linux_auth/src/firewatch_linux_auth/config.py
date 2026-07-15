"""Linux auth plugin configuration.

Resolution order (ADR-0006): env vars > firewatch_config.json > hardcoded defaults.

``LinuxAuthConfig`` is the Pydantic model returned by ``config_schema()``. It drives
the rjsf UI source card.

``build_config`` constructs a resolved instance following the precedence chain. The
UI calls it with ``config_file`` pointing at the persisted ``firewatch_config.json``;
tests pass a ``tmp_path`` file or ``None`` to isolate env-var reads.

Collection mode (ADR-0065 / firewatch-plugin-author skill "local-first, journald-
first"): ``"auto"`` (default) tries the systemd journal first and transparently
falls back to plain file-tail if journald is unavailable on this host (Arch-family
installs have no classic auth.log; some minimal/container images have no systemd).
``"journald"`` / ``"file"`` pin one reader explicitly — useful for an operator who
wants a loud failure instead of a silent fallback.
"""
import json
import logging
import os
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger("firewatch.linux_auth.config")


# ---------------------------------------------------------------------------
# Pydantic model — drives the rjsf UI card (PLUGIN_CONTRACT.md config_schema)
# ---------------------------------------------------------------------------


class LinuxAuthConfig(BaseModel):
    """Linux auth & intrusion-signal collector configuration.

    Local mode only (M1, issue #3): reads this machine's own authentication
    logs — sshd, sudo, useradd/usermod/groupadd/userdel, and generic PAM
    (``pam_unix``) authentication failures — with zero network configuration
    (ADR-0065 §1, Solo self-sufficiency).
    """

    model_config = ConfigDict(extra="ignore")

    mode: Literal["auto", "journald", "file"] = Field(
        default="auto",
        title="Collection mode",
        description=(
            "'auto' (default) tries the systemd journal first and falls back to "
            "file-tail if journald is unavailable on this host. 'journald' or "
            "'file' pin one reader explicitly (a pinned reader that is "
            "unavailable logs an error and yields no events, rather than "
            "silently falling back)."
        ),
    )

    auth_log_path: str = Field(
        default="/var/log/auth.log",
        title="Auth log path (file-tail fallback)",
        description=(
            "Path to the plain-text auth log file, used in 'file' mode or as "
            "the 'auto' fallback. Debian/Ubuntu convention is "
            "'/var/log/auth.log'; RHEL/CentOS-family distros use "
            "'/var/log/secure' instead — set this field accordingly on those "
            "hosts. Ignored in 'journald' mode."
        ),
    )

    journalctl_bin: str = Field(
        default="journalctl",
        title="journalctl binary",
        description=(
            "Name or path of the journalctl binary (PATH-resolved by default). "
            "Only change this if journalctl is not on PATH. Ignored in 'file' mode."
        ),
    )


# ---------------------------------------------------------------------------
# build_config — env > file > default resolution (ADR-0006)
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG_FILE = Path("firewatch_config.json")

# Mapping: config-field-name → env var name.
_ENV_MAP: dict[str, str] = {
    "mode":             "FIREWATCH_LINUX_AUTH_MODE",
    "auth_log_path":    "FIREWATCH_LINUX_AUTH_LOG_PATH",
    "journalctl_bin":   "FIREWATCH_LINUX_AUTH_JOURNALCTL_BIN",
}


def build_config(
    config_file: Path | str | None = _DEFAULT_CONFIG_FILE,
) -> LinuxAuthConfig:
    """Construct a ``LinuxAuthConfig`` with env > file > default precedence (ADR-0006).

    1. Start from Pydantic defaults.
    2. Apply any values found in the ``"linux_auth"`` section of *config_file*.
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
                section: dict[str, Any] = raw.get("linux_auth") or {}
                for key in _ENV_MAP:
                    if key in section:
                        merged[key] = section[key]
            except Exception as exc:
                logger.warning("LinuxAuthConfig: cannot read %s: %s", file_path, exc)

    # Layer 3: env vars (highest priority — override file values)
    for field, env_var in _ENV_MAP.items():
        raw_val = os.environ.get(env_var)
        if raw_val is not None:
            merged[field] = raw_val

    return LinuxAuthConfig.model_validate(merged)
