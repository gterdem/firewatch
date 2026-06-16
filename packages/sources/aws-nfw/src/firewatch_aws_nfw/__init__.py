"""FireWatch AWS Network Firewall source plugin.

Registered as ``aws_network_firewall`` under the ``firewatch.sources`` entry-point group.
Adding this package requires zero edits to firewatch-core (PLUGIN_CONTRACT.md modularity
guarantee).

Module layout (per architect's sketch in issue #603):
  plugin.py    — thin SourcePlugin/PullSource surface; delegates to sub-modules.
  config.py    — AwsNetworkFirewallConfig Pydantic model (Settings card driver).
  client.py    — CloudWatch Logs pull + watermark window + typed errors.
  normalize.py — EVE-in-AWS-envelope → SecurityEvent (reuse Suricata EVE mapping shape).
"""
