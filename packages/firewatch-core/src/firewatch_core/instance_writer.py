"""Instance writer — atomic upsert/remove of ``_instances`` entries in ``firewatch_config.json``.

Implements ADR-0031 §A (auto-sync state IS the ``_instances`` entry) for issue #137.

This module is the *write* counterpart to ``instance_loader.py`` (which reads).
The split keeps reading and writing as separate, focused concerns.

**Invariants enforced:**
- Only the ``_instances`` key is touched — the per-source config section
  (``firewatch_config.json[<source_type>]``) is never read or written here.
- Writes are atomic: write-to-temp + rename (same pattern as ``JsonFileConfigStore``).
- A missing ``_instances`` key is treated as an empty list (idempotent).

**Thread-safety:** not thread-safe; callers are on the asyncio single-process loop
(ADR-0023 §B) and must not ``await`` between the read and write phases. That is
already satisfied for the current API write path (synchronous config mutations on
the event-loop thread).
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger("firewatch.instance_writer")

# Key under which the instance list lives in firewatch_config.json.
# Matches instance_loader._INSTANCES_KEY — kept local to avoid cross-import
# coupling between loader and writer (both are thin modules with one concern).
_INSTANCES_KEY: str = "_instances"


def upsert_instance(
    *,
    config_file: Path | str,
    source_type: str,
    source_id: str,
    flavor: str,
    interval: float,
    transport: str,
) -> None:
    """Atomically write or update one ``_instances`` entry in the config file.

    If an entry for ``(source_type, source_id)`` already exists it is replaced
    in-place; otherwise a new entry is appended.  All other keys in the file
    (the per-source config sections, ``_runtime``, etc.) are left untouched.

    Args:
        config_file:  Path to ``firewatch_config.json``.
        source_type:  Plugin ``type_key`` (e.g. ``"suricata"``).
        source_id:    Instance name (e.g. ``"suricata"`` for the default single-
                      instance-per-type era, ADR-0031 §B).
        flavor:       ``"pull"`` or ``"push"``.
        interval:     Pull interval in seconds (pull flavor only; stored for
                      ``InstanceConfig.interval`` on the next boot).
        transport:    Transport type (``"udp"`` | ``"tcp"`` | ``"file"``).
    """
    path = Path(config_file)
    data = _read_or_empty(path)

    instances: list[dict[str, Any]] = list(data.get(_INSTANCES_KEY) or [])

    new_entry: dict[str, Any] = {
        "source_type": source_type,
        "source_id": source_id,
        "flavor": flavor,
        "interval": interval,
        "transport": transport,
    }

    # Replace existing entry or append new one.
    replaced = False
    for i, entry in enumerate(instances):
        if (
            isinstance(entry, dict)
            and entry.get("source_type") == source_type
            and entry.get("source_id") == source_id
        ):
            instances[i] = new_entry
            replaced = True
            break
    if not replaced:
        instances.append(new_entry)

    data[_INSTANCES_KEY] = instances
    _atomic_write(path, data)
    logger.info(
        "instance_writer.upsert %s/%s flavor=%s interval=%.1fs (%s)",
        source_type, source_id, flavor, interval, "updated" if replaced else "added",
    )


def remove_instance(
    *,
    config_file: Path | str,
    source_type: str,
    source_id: str,
) -> None:
    """Atomically remove one ``_instances`` entry from the config file.

    Idempotent: if no matching entry exists, the file is written back unchanged
    (or left unchanged if it was already consistent).

    The per-source config section (``firewatch_config.json[<source_type>]``) is
    never touched — the source stays configured and manually-syncable after
    removal (ADR-0031 §A "auto-sync OFF = remove _instances entry").

    Args:
        config_file:  Path to ``firewatch_config.json``.
        source_type:  Plugin ``type_key``.
        source_id:    Instance name.
    """
    path = Path(config_file)
    data = _read_or_empty(path)

    instances: list[dict[str, Any]] = list(data.get(_INSTANCES_KEY) or [])
    filtered = [
        e for e in instances
        if not (
            isinstance(e, dict)
            and e.get("source_type") == source_type
            and e.get("source_id") == source_id
        )
    ]

    removed = len(instances) - len(filtered)
    data[_INSTANCES_KEY] = filtered
    _atomic_write(path, data)
    if removed:
        logger.info(
            "instance_writer.remove %s/%s — removed from _instances",
            source_type, source_id,
        )
    else:
        logger.debug(
            "instance_writer.remove %s/%s — no entry found (idempotent)",
            source_type, source_id,
        )


# --------------------------------------------------------------------------- #
# Internal helpers                                                              #
# --------------------------------------------------------------------------- #


def _read_or_empty(path: Path) -> dict[str, Any]:
    """Read and parse the config file; return {} on missing or corrupt file."""
    if not path.exists():
        return {}
    try:
        raw = path.read_text(encoding="utf-8")
        data = json.loads(raw)
        if not isinstance(data, dict):
            logger.warning(
                "instance_writer: config file %s root is not a dict; treating as empty",
                path,
            )
            return {}
        return data
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning(
            "instance_writer: could not read config file %s: %s; treating as empty",
            path, exc,
        )
        return {}


def _atomic_write(path: Path, data: dict[str, Any]) -> None:
    """Write *data* atomically via write-to-temp + rename (POSIX atomic).

    Same pattern as ``JsonFileConfigStore._persist`` — prevents half-written files
    on crash mid-write.
    """
    content = json.dumps(data, indent=2, ensure_ascii=False)
    try:
        dir_ = path.parent
        dir_.mkdir(parents=True, exist_ok=True)
        fd, tmp_path_str = tempfile.mkstemp(
            dir=dir_, prefix=".fw_instances_", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(content)
            os.replace(tmp_path_str, path)
        except Exception:
            try:
                os.unlink(tmp_path_str)
            except OSError:
                pass
            raise
    except OSError as exc:
        logger.warning("instance_writer: failed to persist to %s: %s", path, exc)
        raise
