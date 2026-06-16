"""``firewatch sync --once`` — single pull cycle for each configured instance.

Implements EARS-2 (issue #35):
  When ``firewatch sync --once`` runs, it shall execute a single pull cycle
  for each configured pull instance and then exit with a status code
  reflecting success/failure.

Design notes
------------
- Sources are configured **only** through the MA.2 config service (EARS-4):
  ``load_instances(config_file)`` reads ``_instances`` from
  ``firewatch_config.json``.  No hardcoded paths or instance names.
- Each pull instance gets its own ``PluginContext`` minted here via the
  same two-line pattern the supervisor uses (ADR-0027 §3: "a single-shot /
  CLI caller mints its own ``ctx`` the SAME two-line way the supervisor
  does").  The factory function is ``scoped_kv(store, type_key)``.
- Push-flavor instances are skipped (a push listener has no single-shot
  pull semantic).
- Instance types not present in the registry are skipped with a warning.
- Exit code: 0 if ALL cycles succeeded (or were skipped); 1 if ANY cycle
  raised an exception.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from firewatch_sdk import PluginContext, SourcePlugin

from firewatch_core.instance_loader import load_instances
from firewatch_core.scoped_kv import scoped_kv

from firewatch_cli.commands._pipeline_factory import _build_pipeline

logger = logging.getLogger("firewatch.cli.sync_once")


async def cmd_sync_once(
    registry: dict[str, SourcePlugin],
    config_file: Path | str | None = None,
) -> int:
    """Run one pull cycle for every configured pull instance, then return.

    Parameters
    ----------
    registry:
        Plugin registry — ``{type_key: plugin_instance}``.  Obtained from
        ``load_source_plugins()`` in production; injected as a fake in tests.
    config_file:
        Path to ``firewatch_config.json``.  Defaults to the current working
        directory.  The instance list is read from ``_instances`` in this file.

    Returns
    -------
    int
        Exit code: 0 on full success, 1 if any cycle raised an exception.
    """
    config_path = Path(config_file) if config_file else Path("firewatch_config.json")
    instances = load_instances(config_path)

    pull_instances = [inst for inst in instances if inst.flavor == "pull"]
    if not pull_instances:
        logger.info("sync_once: no pull instances configured; nothing to do")
        return 0

    pipeline = _build_pipeline(config_path)

    # init the store if it has an async init (SQLiteEventStore does)
    store = pipeline.store  # type: ignore[attr-defined]
    if hasattr(store, "init"):
        await store.init()

    any_failed = False
    for inst in pull_instances:
        plugin = registry.get(inst.source_type)
        if plugin is None:
            logger.warning(
                "sync_once: source_type=%r (source_id=%r) not found in registry; "
                "skipping — is the plugin installed?",
                inst.source_type, inst.source_id,
            )
            continue

        # Resolve per-type config (MA.2) merged with per-instance overrides.
        cfg = _resolve_config(plugin, inst.extra_cfg, config_path)

        # Mint ctx per ADR-0027 §3: source_type from plugin constant only.
        source_type = plugin.metadata().type_key
        kv = scoped_kv(store, source_type)
        ctx = PluginContext(kv=kv, source_id=inst.source_id)

        logger.info(
            "sync_once: running pull cycle for %s/%s",
            source_type, inst.source_id,
        )
        try:
            inserted = await pipeline.run_pull_cycle(  # type: ignore[attr-defined]
                plugin, cfg, inst.source_id, ctx
            )
            logger.info(
                "sync_once: %s/%s — %d event(s) inserted",
                source_type, inst.source_id, inserted,
            )
        except Exception:
            logger.exception(
                "sync_once: pull cycle failed for %s/%s",
                source_type, inst.source_id,
            )
            any_failed = True

    if hasattr(store, "close"):
        try:
            await store.close()
        except Exception:
            logger.warning("sync_once: store.close() raised; ignoring", exc_info=True)

    return 1 if any_failed else 0


def _resolve_config(
    plugin: SourcePlugin,
    extra_cfg: dict[str, Any],
    config_path: Path,
) -> BaseModel:
    """Resolve per-instance config: type-level defaults + extra_cfg overrides.

    Tries ``JsonFileConfigStore.get_source`` first; if the config file does not
    exist yet, falls back to the plugin's schema defaults.  Then merges
    ``extra_cfg`` on top (per-instance overrides have highest priority after
    env vars, which the store already handles).
    """
    schema = plugin.config_schema()
    source_type = plugin.metadata().type_key

    try:
        from firewatch_core.config_store import JsonFileConfigStore
        store_cfg = JsonFileConfigStore(config_file=config_path)
        base_cfg = store_cfg.get_source(source_type, schema)
        # Merge extra_cfg on top of the resolved base config.
        if extra_cfg:
            merged = {**base_cfg.model_dump(), **extra_cfg}
            return schema.model_validate(merged)
        return base_cfg
    except Exception:
        logger.error(
            "sync_once._resolve_config: could not load config for %r; "
            "using schema defaults + extra_cfg",
            source_type, exc_info=True,
        )
        return schema.model_validate(extra_cfg)
