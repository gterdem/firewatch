"""Source-plugin loader — entry-point discovery.

Adding a source requires zero core edits (CLAUDE.md non-negotiable #1): plugins register
under the ``firewatch.sources`` entry-point group and are discovered here at startup. A
plugin that fails to import or construct is logged and skipped — one bad plugin never
aborts startup (PLUGIN_CONTRACT.md hard rules).
"""
import logging
from importlib.metadata import entry_points

from firewatch_sdk import SourcePlugin

ENTRY_POINT_GROUP = "firewatch.sources"

logger = logging.getLogger("firewatch.loader")


def load_source_plugins() -> dict[str, SourcePlugin]:
    """Discover and instantiate every registered source plugin.

    Returns a registry mapping ``source_type`` (the plugin's ``metadata().type_key``) to a
    plugin instance. Discovery is resilient: any plugin whose entry point fails to load,
    instantiate, or report metadata is logged and skipped.
    """
    registry: dict[str, SourcePlugin] = {}
    for ep in entry_points(group=ENTRY_POINT_GROUP):
        try:
            plugin_cls = ep.load()
            plugin: SourcePlugin = plugin_cls()
            type_key = plugin.metadata().type_key
        except Exception:
            logger.exception("failed to load source plugin %r; skipping", ep.name)
            continue

        if ep.name != type_key:
            logger.warning(
                "entry-point name %r != metadata().type_key %r; registering under %r",
                ep.name, type_key, type_key,
            )
        if type_key in registry:
            logger.warning(
                "duplicate source_type %r; %r overrides the earlier plugin",
                type_key, ep.name,
            )
        registry[type_key] = plugin

    logger.info("loaded %d source plugin(s): %s", len(registry), sorted(registry))
    return registry
