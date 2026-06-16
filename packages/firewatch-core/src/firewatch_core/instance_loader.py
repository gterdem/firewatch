"""Instance loader — reads the ``_instances`` list from ``firewatch_config.json``.

Each entry in ``_instances`` declares a named source instance to run:

  ``source_type`` — the plugin's ``type_key`` (entry-point group key)
  ``source_id``   — the user-assigned instance name (ADR-0016; e.g. "pi-home")
  ``flavor``      — "pull" or "push"
  ``extra_cfg``   — optional per-instance config overrides (merged over the
                    type-level config from ``ConfigStore.get_source``)

This module bridges the MA.2 config service (``firewatch_config.json``) to the
supervisor's registration API (``Supervisor.add_pull`` / ``add_push``) and the
single-shot ``run_pull_cycle`` path in ``sync --once``.

Why a separate ``_instances`` key?
-----------------------------------
``ConfigStore.get_source(type, schema)`` resolves one config object per
*source type*, not per *named instance*. Multi-instance-per-type (ADR-0016)
requires knowing *which instances to run* independently of the per-type config.
Storing the instance list under ``_instances`` in the same JSON file keeps
configuration in the single MA.2 config service without changing the
``ConfigStore`` port contract.

The ``_instances`` key uses the leading underscore convention (like ``_runtime``)
to signal that it is owned by the core / CLI layer, not a per-source section.

Config sourcing rule (EARS-4 / issue #35):
The CLI MUST NOT hardcode source paths or instance names. It reads them
exclusively from this loader, which in turn reads ``firewatch_config.json``.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger("firewatch.instance_loader")

# Key under which the instance list lives in firewatch_config.json.
_INSTANCES_KEY: str = "_instances"

# Keys whose values are redacted in log output to prevent secret leaks.
# Compared case-insensitively as a substring match against each key name.
_SECRET_KEY_PATTERNS: tuple[str, ...] = (
    "key", "secret", "token", "password", "passwd", "credential",
)


def _redact_entry(entry: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of *entry* with secret-ish values masked.

    Any key whose lowercase name contains one of _SECRET_KEY_PATTERNS has
    its value replaced with "***".  Non-sensitive keys (source_type,
    source_id, ...) are preserved verbatim so the log remains actionable.
    """
    redacted: dict[str, Any] = {}
    for k, v in entry.items():
        lower_k = k.lower()
        if any(pat in lower_k for pat in _SECRET_KEY_PATTERNS):
            redacted[k] = "***"
        else:
            redacted[k] = v
    return redacted


class InstanceConfig(BaseModel):
    """Declares one named source instance to run.

    Fields
    ------
    source_type : str
        The plugin's ``type_key`` — must match a registered entry point in
        the ``firewatch.sources`` group.  Core looks up the plugin via
        ``load_source_plugins()`` and uses this key.
    source_id : str
        The user-assigned instance name (ADR-0016).  Used as the watermark
        key, the ``PluginContext.source_id``, and for logging.  Must be
        unique within a ``source_type`` to avoid watermark collisions.
    flavor : str
        "pull" (watermark-driven) or "push" (listener).  Must match the
        plugin's declared ``metadata().flavor``.  The CLI uses this to
        decide whether to call ``supervisor.add_pull`` or ``add_push``.
    extra_cfg : dict
        Optional per-instance config overrides.  Merged over the type-level
        config returned by ``ConfigStore.get_source(source_type, schema)``.
        Useful for running two instances of the same type with different
        settings (e.g. two Suricata hosts).
    interval : float
        Pull interval in seconds (pull flavor only).  Default 60 s.
    transport : str
        Transport type for push instances ("udp" | "tcp" | "file").
        Determines the backpressure policy in the supervisor (ADR-0023).
    """

    source_type: str
    source_id: str
    flavor: str  # "pull" | "push"
    extra_cfg: dict[str, Any] = Field(default_factory=dict)
    interval: float = 60.0
    transport: str = "tcp"


def load_instances(config_file: Path | str | None = None) -> list[InstanceConfig]:
    """Load the ``_instances`` list from ``firewatch_config.json``.

    Parameters
    ----------
    config_file:
        Path to the config JSON file.  Defaults to ``firewatch_config.json``
        in the current working directory (matching ``JsonFileConfigStore``
        default).  Pass an absolute path or ``tmp_path`` in tests.

    Returns
    -------
    list[InstanceConfig]
        Validated instance declarations.  Returns an empty list when:
        - the file does not exist (first run / no config yet);
        - the ``_instances`` key is absent;
        - a particular entry fails validation (that entry is skipped with
          a warning; other valid entries are returned).

    Notes
    -----
    This function reads the file layer *only* — the same raw JSON that
    ``JsonFileConfigStore._file_data`` holds.  It does NOT re-apply env-var
    overrides (env vars apply to typed config fields, not the instance list).
    This is intentional: the instance list is structural (what to run), not
    a config value (how to run it).  Env overrides on the per-type config
    are applied later when ``ConfigStore.get_source`` is called at instance
    startup.
    """
    path = Path(config_file) if config_file else Path("firewatch_config.json")

    if not path.exists():
        logger.debug("instance_loader: config file %s not found; no instances", path)
        return []

    try:
        raw = path.read_text(encoding="utf-8")
        data: dict[str, Any] = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning(
            "instance_loader: could not read config file %s: %s; no instances",
            path, exc,
        )
        return []

    raw_instances = data.get(_INSTANCES_KEY)
    if not isinstance(raw_instances, list):
        logger.debug(
            "instance_loader: no '%s' key in %s; no instances to load",
            _INSTANCES_KEY, path,
        )
        return []

    instances: list[InstanceConfig] = []
    for i, entry in enumerate(raw_instances):
        if not isinstance(entry, dict):
            logger.warning(
                "instance_loader: _instances[%d] is not a dict; skipping", i
            )
            continue
        try:
            instances.append(InstanceConfig.model_validate(entry))
        except Exception as exc:
            logger.warning(
                "instance_loader: _instances[%d] failed validation (%s); "
                "skipping entry: %s",
                i, exc, _redact_entry(entry),
            )

    logger.info(
        "instance_loader: loaded %d instance(s) from %s", len(instances), path
    )
    return instances
