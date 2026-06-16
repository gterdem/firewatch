"""firewatch-suricata — Suricata EVE JSON source plugin for FireWatch.

The canonical reference PullSource implementation (PLUGIN_CONTRACT.md).
Registered as ``suricata`` under the ``firewatch.sources`` entry-point group.
"""
from firewatch_suricata.plugin import SuricataSource

__all__ = ["SuricataSource"]
