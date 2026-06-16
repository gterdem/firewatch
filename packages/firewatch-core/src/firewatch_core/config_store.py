"""JsonFileConfigStore — the persisting ConfigStore adapter.

Implements the ``ConfigStore`` port (firewatch-sdk) with:
- env vars > ``firewatch_config.json`` > Pydantic defaults (ADR-0006)
- atomic persistence (write-to-temp + rename — no half-written files)
- corrupt-file fallback to last-known-good + defaults with a warning (ADR-0023 seam)
- env-lock enforcement: a write to an env-locked field is rejected without mutating state
- ``SecretStr`` fields are never logged or serialised in plain text

Design notes
------------
Env-var name convention:
  - Runtime fields:      ``FIREWATCH_<UPPER_FIELD_NAME>``
                         e.g. ``FIREWATCH_ALERT_THRESHOLD``
  - Per-source fields:   ``FIREWATCH_SRC_<UPPER_SOURCE_TYPE>_<UPPER_FIELD_NAME>``
                         e.g. ``FIREWATCH_SRC_SURICATA_MODE``

The distinct ``FIREWATCH_SRC_`` prefix for source fields prevents collisions with
runtime fields (F3 fix).  For example, ``alert_threshold`` is a runtime field whose
env var is ``FIREWATCH_ALERT_THRESHOLD``; a hypothetical source named ``alert`` with
a field ``threshold`` would previously map to the same name.  The ``SRC_`` prefix
makes source vars unambiguous.

The adapter does NOT hard-code knowledge of any source's fields.  It discovers env-var
coverage at resolution time by iterating the schema's model fields and checking the
``FIREWATCH_SRC_<SOURCE_TYPE>_<FIELD>`` pattern.  The schema is supplied by the caller
(core, which got it from the plugin via ``config_schema()``).  This keeps the adapter
source-agnostic (PLUGIN_CONTRACT.md / CLAUSE.md non-negotiable #1).

Write semantics
---------------
``set_runtime`` and ``set_source`` persist only the explicitly-written fields (the
``updates`` dict merged with the existing file section).  Env-resolved values are NOT
written to the file — the env layer is always live and should not be collapsed into the
file layer (ADR-0006: env wins permanently, not just on first write).

Thread-safety: this class is not thread-safe.  In the asyncio single-process model
(ADR-0023) concurrent access from coroutines is safe as long as callers do not
``await`` between the read and write phases of ``set_*`` calls (they don't — both
methods are synchronous).

SecretStr serialization: when writing a config to the JSON file, any ``SecretStr``
field is serialized by calling ``.get_secret_value()`` so the value reaches the file
(the file is the write-side; the constraint is that it must never appear in *logs*
or *repr*).  On load the raw string is passed to Pydantic, which reconstructs
the ``SecretStr`` wrapper.
"""
from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

from pydantic import BaseModel, SecretStr

from firewatch_sdk.config import ConfigStore, RuntimeConfig

logger = logging.getLogger("firewatch.config_store")

# Environment-variable prefix for runtime fields.
_RUNTIME_PREFIX = "FIREWATCH_"

# Prefix for per-source env vars (distinct from runtime prefix to prevent collisions — F3).
_SOURCE_PREFIX = "FIREWATCH_SRC_"

# Key under which runtime config lives in the JSON file.
_RUNTIME_KEY = "_runtime"

# Key under which auto-sync instance records live in the JSON file (ADR-0031 §A).
_INSTANCES_KEY = "_instances"

# Source-type values that collide with internal JSON keys and are therefore reserved (F1).
# Defense-in-depth: TYPE_KEY_PATTERN upstream already blocks underscore-prefixed keys,
# but _RESERVED_KEYS provides an explicit second layer for callers with direct store
# access (issue #166 NB-C).
_RESERVED_KEYS: frozenset[str] = frozenset({_RUNTIME_KEY, _INSTANCES_KEY})


# ---------------------------------------------------------------------------
# Env-var naming helpers
# ---------------------------------------------------------------------------


def _runtime_env_var(field: str) -> str:
    """Map a RuntimeConfig field name to its env var name.

    e.g.  ``alert_threshold``  →  ``FIREWATCH_ALERT_THRESHOLD``
    """
    return f"{_RUNTIME_PREFIX}{field.upper()}"


def _source_env_var(source_type: str, field: str) -> str:
    """Map a source field name to its env var name.

    e.g.  ``("suricata", "mode")``  →  ``FIREWATCH_SRC_SURICATA_MODE``

    The ``SRC_`` infix distinguishes source env vars from runtime vars and prevents
    collisions (F3).  The ``FIREWATCH_ALERT_THRESHOLD`` runtime var can no longer
    be shadowed by a source named ``alert`` with a field ``threshold``.
    """
    return f"{_SOURCE_PREFIX}{source_type.upper()}_{field.upper()}"


# ---------------------------------------------------------------------------
# Type coercion helper for env strings
# ---------------------------------------------------------------------------


def _coerce_env_value(raw: str, annotation: Any) -> Any:
    """Best-effort coerce a raw env string to the field's Python type.

    Handles bool, int, float; everything else stays as str (Pydantic handles
    SecretStr, Literal, Optional, etc. from a plain string).
    """
    import types
    import typing

    # Unwrap Optional[X] / X | None → get the inner type
    origin = typing.get_origin(annotation)
    args = typing.get_args(annotation)

    if origin is types.UnionType or origin is typing.Union:
        # Filter out NoneType; take the first non-None arg
        non_none = [a for a in args if a is not type(None)]
        if non_none:
            return _coerce_env_value(raw, non_none[0])
        return raw

    if annotation is bool:
        return raw.lower() not in ("false", "0", "no", "off")
    if annotation is int:
        try:
            return int(raw)
        except ValueError:
            return raw
    if annotation is float:
        try:
            return float(raw)
        except ValueError:
            return raw
    # str, SecretStr, Literal, unknown — let Pydantic handle it
    return raw


# ---------------------------------------------------------------------------
# Shared resolution helpers
# ---------------------------------------------------------------------------


def _env_locked_fields(
    schema: type[BaseModel],
    env_var_fn: Any,
    *fn_args: Any,
) -> set[str]:
    """Return field names whose env var is currently set (env-locked fields)."""
    locked: set[str] = set()
    for field_name in schema.model_fields:
        env_name = env_var_fn(*fn_args, field_name)
        if os.environ.get(env_name) is not None:
            locked.add(field_name)
    return locked


def _apply_env_layer(
    merged: dict[str, Any],
    schema: type[BaseModel],
    env_var_fn: Any,
    *fn_args: Any,
) -> None:
    """Mutate *merged* in-place: apply env vars for any field that has one set."""
    for field_name, field_info in schema.model_fields.items():
        env_name = env_var_fn(*fn_args, field_name)
        raw = os.environ.get(env_name)
        if raw is None:
            continue
        annotation = field_info.annotation
        merged[field_name] = _coerce_env_value(raw, annotation)


# ---------------------------------------------------------------------------
# Main adapter class
# ---------------------------------------------------------------------------


class JsonFileConfigStore:
    """Persisting ConfigStore backed by ``firewatch_config.json``.

    Parameters
    ----------
    config_file:
        Path to the JSON config file.  Defaults to ``firewatch_config.json``
        (cwd-relative).  Pass an absolute path or a ``tmp_path`` in tests.
    """

    def __init__(self, config_file: Path | str | None = None) -> None:
        self._path = Path(config_file) if config_file else Path("firewatch_config.json")
        # In-memory cache of the *file layer only* (env values are always re-read live).
        self._file_data: dict[str, Any] = {}
        # Last-known-good snapshot for the corrupt-file fallback seam (ADR-0023).
        self._last_known_good: dict[str, Any] = {}
        self._load()

    # ------------------------------------------------------------------
    # Public path accessor (ADR-0031 option A)
    # ------------------------------------------------------------------

    @property
    def config_path(self) -> Path:
        """Return the path to the backing config file.

        Used by the auto-sync write routes to pass the same path to
        ``instance_writer.upsert_instance`` / ``remove_instance`` (ADR-0031
        option A: single source of truth for the path — the route reads it
        from the injected store rather than threading it separately).
        """
        return self._path

    # ------------------------------------------------------------------
    # Public existence probe (issue #155 NB-2)
    # ------------------------------------------------------------------

    def has_source(self, type_key: str) -> bool:
        """Return True when a config section for *type_key* exists in the file.

        A section "exists" when the key is present in the file layer AND the
        key does not start with ``_`` (the leading-underscore convention for
        internal keys such as ``_runtime`` and ``_instances`` — ADR-0006 §note,
        ADR-0031 §A).

        This is the public seam for the boot-path idle-registration pass
        (``_register_idle_configured_pulls`` in ``firewatch-cli``).  It replaces
        the previous ``getattr(store, "_file_data", {})`` private-attribute probe
        which silently returns ``{}`` for any non-file store (issue #155 NB-2).

        Only inspects the file layer (``_file_data``), not env vars — a source
        that has only env vars and no file section is considered *not configured*
        from a persistence standpoint (the boot path needs a file section to
        know the source was deliberately configured, not just env-injected).
        """
        if type_key.startswith("_"):
            return False
        return type_key in self._file_data

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load(self) -> None:
        """Load the config file into ``_file_data``.

        First run (file absent) → silently start empty.
        Corrupt file → fall back to last-known-good (or {}) and warn.
        """
        if not self._path.exists():
            self._file_data = {}
            return
        try:
            raw = self._path.read_text(encoding="utf-8")
            data: dict[str, Any] = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError("config file root must be a JSON object")
            self._file_data = data
            # Snapshot for the last-known-good seam.
            self._last_known_good = {k: v for k, v in data.items()}
        except (json.JSONDecodeError, ValueError) as exc:
            logger.warning(
                "firewatch_config.json is corrupt (%s); "
                "falling back to last-known-good + defaults",
                exc,
            )
            # Restore from last-known-good (empty on first run).
            self._file_data = {k: v for k, v in self._last_known_good.items()}

    def _persist(self, new_data: dict[str, Any]) -> None:
        """Atomically write *new_data* to the config file.

        Uses write-to-temp-then-rename so a crash mid-write never leaves a
        half-written file (atomic on POSIX; best-effort on Windows).

        **Out-of-band key preservation (ADR-0031 §A / issue #742):**
        ``ConfigStore`` does not own the ``_instances`` key — ``instance_writer``
        writes it directly to disk without going through this class.  Because
        ``_file_data`` is loaded once at startup, the in-memory cache becomes
        stale whenever ``instance_writer`` writes between startup and this call.
        To prevent clobbering, we re-read the current on-disk value of every
        ``_``-prefixed key that ConfigStore does not manage (i.e. every internal
        key except ``_runtime`` which ConfigStore *does* own) and merge them into
        ``new_data`` before writing.  The re-read happens here — inside the same
        critical section as the write — so no new race is introduced.
        """
        # Re-read on-disk values for internal keys this class does not own, so
        # an out-of-band ``instance_writer`` write is never reverted.  We own
        # ``_runtime`` but NOT ``_instances`` (and any other future ``_``-keyed
        # internal sections written by external modules).
        try:
            if self._path.exists():
                on_disk_raw = self._path.read_text(encoding="utf-8")
                on_disk: dict[str, Any] = json.loads(on_disk_raw)
                if isinstance(on_disk, dict):
                    for key, value in on_disk.items():
                        if key.startswith("_") and key != _RUNTIME_KEY:
                            # Preserve the on-disk value for keys ConfigStore
                            # does not manage (e.g. _instances).
                            new_data[key] = value
        except (OSError, json.JSONDecodeError):
            # If we can't read the current file for the merge, proceed with
            # what we have — a partial clobber is better than failing the write.
            pass

        # Serialise: convert SecretStr → plain string for JSON.
        json_ready = _deep_jsonify(new_data)
        content = json.dumps(json_ready, indent=2, ensure_ascii=False)

        try:
            dir_ = self._path.parent
            dir_.mkdir(parents=True, exist_ok=True)
            fd, tmp_path = tempfile.mkstemp(
                dir=dir_, prefix=".fw_cfg_", suffix=".tmp"
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    fh.write(content)
                os.replace(tmp_path, self._path)
            except Exception:
                # Clean up the temp file if rename failed.
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
        except OSError as exc:
            logger.warning("failed to persist config to %s: %s", self._path, exc)
            raise

        # Update in-memory cache and last-known-good snapshot after successful write.
        self._file_data = new_data
        self._last_known_good = {k: v for k, v in new_data.items()}

    # ------------------------------------------------------------------
    # ConfigStore port — runtime config
    # ------------------------------------------------------------------

    def get_runtime(self) -> RuntimeConfig:
        """Resolve and return the current ``RuntimeConfig`` (env > file > default)."""
        merged: dict[str, Any] = {}

        # Layer 1: file values
        runtime_section = self._file_data.get(_RUNTIME_KEY) or {}
        for field_name in RuntimeConfig.model_fields:
            if field_name in runtime_section:
                merged[field_name] = runtime_section[field_name]

        # Layer 2: env vars (highest priority — override file)
        _apply_env_layer(merged, RuntimeConfig, _runtime_env_var)

        return RuntimeConfig.model_validate(merged)

    def set_runtime(self, updates: dict[str, Any]) -> None:
        """Validate and persist runtime config updates.

        Only *updates* (and the existing file section) are written to disk.
        Env-resolved values are NOT written — the env layer is always live
        and must not be collapsed into the file (ADR-0006).

        Raises ``ValueError`` for env-locked fields.
        Raises ``pydantic.ValidationError`` for invalid values.
        Does NOT mutate state on failure.
        """
        # Check env-lock before any state mutation.
        locked = _env_locked_fields(RuntimeConfig, _runtime_env_var)
        blocked = set(updates) & locked
        if blocked:
            raise ValueError(
                f"Cannot write config fields currently locked by env vars: "
                f"{sorted(blocked)}.  Unset the env var(s) first."
            )

        # Merge with existing file section (not the resolved/env values).
        current_file_section: dict[str, Any] = dict(
            self._file_data.get(_RUNTIME_KEY) or {}
        )
        proposed_file = {**current_file_section, **updates}

        # Validate the proposed file values combined with env layer.
        merged_for_validation: dict[str, Any] = dict(proposed_file)
        _apply_env_layer(merged_for_validation, RuntimeConfig, _runtime_env_var)
        RuntimeConfig.model_validate(merged_for_validation)

        # Build new file data — only store what belongs in the file layer.
        new_file_section = _dict_to_file_values(proposed_file)
        new_data = {**self._file_data, _RUNTIME_KEY: new_file_section}
        self._persist(new_data)

    # ------------------------------------------------------------------
    # ConfigStore port — per-source config
    # ------------------------------------------------------------------

    def get_source(self, source_type: str, schema: type[BaseModel]) -> BaseModel:
        """Resolve per-source config (env > file > default) for *source_type*.

        *schema* is the plugin's ``config_schema()`` Pydantic model.  Core passes
        it generically; the adapter never hard-codes per-source field knowledge.

        Raises ``ValueError`` if *source_type* is a reserved internal key (F1).
        """
        if source_type in _RESERVED_KEYS:
            raise ValueError(
                f"source_type={source_type!r} is a reserved internal key and cannot "
                "be used as a source identifier."
            )

        merged: dict[str, Any] = {}

        # Layer 1: file section keyed by source_type.
        source_section = self._file_data.get(source_type) or {}
        for field_name in schema.model_fields:
            if field_name in source_section:
                merged[field_name] = source_section[field_name]

        # Layer 2: env vars (highest priority).
        _apply_env_layer(merged, schema, _source_env_var, source_type)

        return schema.model_validate(merged)

    def set_source(
        self, source_type: str, schema: type[BaseModel], updates: dict[str, Any]
    ) -> None:
        """Validate and persist per-source config updates.

        Only the file layer (existing section merged with *updates*) is written.
        Env-resolved values are NOT written to disk.

        Raises ``ValueError`` if *source_type* is a reserved internal key (F1).
        Raises ``ValueError`` for env-locked fields.
        Raises ``pydantic.ValidationError`` for invalid values.
        Does NOT mutate state on failure.
        """
        if source_type in _RESERVED_KEYS:
            raise ValueError(
                f"source_type={source_type!r} is a reserved internal key and cannot "
                "be used as a source identifier."
            )

        # Check env-lock.
        locked = _env_locked_fields(schema, _source_env_var, source_type)
        blocked = set(updates) & locked
        if blocked:
            raise ValueError(
                f"Cannot write config fields for source '{source_type}' currently "
                f"locked by env vars: {sorted(blocked)}.  Unset the env var(s) first."
            )

        # Merge with existing file section and validate.
        current_file_section: dict[str, Any] = dict(
            self._file_data.get(source_type) or {}
        )
        proposed_file = {**current_file_section, **updates}

        # Validate proposed file values combined with env layer.
        merged_for_validation: dict[str, Any] = dict(proposed_file)
        _apply_env_layer(merged_for_validation, schema, _source_env_var, source_type)
        schema.model_validate(merged_for_validation)

        # Build new file data.
        new_section = _dict_to_file_values(proposed_file)
        new_data = {**self._file_data, source_type: new_section}
        self._persist(new_data)


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------


def _dict_to_file_values(data: dict[str, Any]) -> dict[str, Any]:
    """Convert a dict of config values to JSON-serialisable form.

    SecretStr values are extracted with ``.get_secret_value()``.  This is the
    file-layer serialisation; the constraint is "never in logs/repr", not "never on
    disk".
    """
    result: dict[str, Any] = {}
    for key, value in data.items():
        if isinstance(value, SecretStr):
            result[key] = value.get_secret_value()
        else:
            result[key] = value
    return result


def _deep_jsonify(obj: Any) -> Any:
    """Recursively convert SecretStr values in a nested structure to plain str."""
    if isinstance(obj, SecretStr):
        return obj.get_secret_value()
    if isinstance(obj, dict):
        return {k: _deep_jsonify(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_deep_jsonify(item) for item in obj]
    return obj


# ---------------------------------------------------------------------------
# Structural conformance assertion (verified by test_config_store.py)
# ---------------------------------------------------------------------------
_: ConfigStore = JsonFileConfigStore.__new__(JsonFileConfigStore)  # type: ignore[assignment]
