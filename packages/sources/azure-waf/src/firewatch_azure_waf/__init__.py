"""FireWatch Azure WAF source plugin.

Registered as ``azure_waf`` under the ``firewatch.sources`` entry-point group.
Implements ``SourcePlugin`` + ``PullSource`` against the firewatch-sdk contract.

Depends on ``firewatch-sdk`` ONLY. Never imports ``firewatch-core`` or ``legacy/``.
"""
