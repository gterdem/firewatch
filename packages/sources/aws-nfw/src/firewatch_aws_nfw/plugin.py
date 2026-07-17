"""AwsNetworkFirewallSource — FireWatch PullSource plugin for AWS Network Firewall.

Registered as ``aws_network_firewall`` under the ``firewatch.sources`` entry-point group.
Adding this package requires zero edits to firewatch-core (PLUGIN_CONTRACT.md
modularity guarantee / EARS-6).

Implements:
  - SourcePlugin  (metadata, config_schema, validate_config, normalize, health_check)
  - PullSource    (collect)

Depends on firewatch-sdk ONLY. Never imports firewatch-core or legacy/.

Module layout (per architect's sketch in issue #603):
  plugin.py    — thin surface; delegates to sub-modules.
  config.py    — AwsNetworkFirewallConfig Pydantic model (Settings card driver).
  client.py    — CloudWatch Logs pull + watermark window + typed errors.
  normalize.py — EVE-in-AWS-envelope → SecurityEvent (reuses Suricata EVE mapping shape).

Key design note:
  AWS NFW's stateful engine IS Suricata; its alert log records are EVE JSON wrapped
  in an AWS CloudWatch Logs envelope. normalize() strips the envelope and applies
  the same EVE mapping as the Suricata plugin. This is the second-cloud PULL proof
  in the contract-stress test (docs/contract-stress-2026-06.md §Source 1).

OCSF alignment (ADR-0020):
  ocsf_class=2004 (Detection Finding), ocsf_category=2 (Findings).
  Source: https://schema.ocsf.io/classes/detection_finding

Action mapping (ADR-0012):
  blocked→BLOCK (IPS mode, packet dropped), alert→ALERT (IDS mode, detected only).
"""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

from pydantic import BaseModel

from firewatch_sdk import PluginContext, RawEvent, SecurityEvent, SourceMetadata

from firewatch_aws_nfw import client as _client
from firewatch_aws_nfw import normalize as _normalize
from firewatch_aws_nfw.config import AwsNetworkFirewallConfig

# Plugin version — SemVer string (PLUGIN_CONTRACT.md SourceMetadata.version).
_VERSION = "0.1.0"

# The canonical type key for this source.
# Constrained to ^[a-z][a-z0-9_]*$ (PLUGIN_CONTRACT.md / ADR-0025 addendum).
_TYPE_KEY = "aws_network_firewall"


class AwsNetworkFirewallSource:
    """AWS Network Firewall CloudWatch Logs source plugin.

    Implements SourcePlugin + PullSource from firewatch-sdk.

    Pull path (EARS-1 / docs/contract-stress-2026-06.md §Source 1):
      Pulls alert log records from a CloudWatch Logs log group using boto3's
      filter_log_events API with a watermark-windowed time range. Handles
      pagination via nextToken. Credentials default to the AWS SDK chain
      (instance profile, env vars, SSO); explicit key/secret are optional.

    Normalization (ADR-0012, ADR-0014, ADR-0020, EARS-2, EARS-5):
      - source_type is the constant "aws_network_firewall" — never branches on source_id.
      - AWS envelope stripped; inner Suricata EVE record mapped identically to
        the firewatch_suricata normalizer (same stateful engine, same EVE format).
      - blocked→BLOCK, alert→ALERT (ADR-0012).
      - ocsf_class=2004 (Detection Finding), ocsf_category=2 (Findings) (ADR-0020).
      - MITRE ATT&CK from ET Open alert.metadata.mitre_* (ADR-0014).
      - ADR-0048 network-depth fields: flow/dns/tls/http sub-objects → nullable fields.
    """

    # ── SourcePlugin methods ─────────────────────────────────────────────────

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            type_key=_TYPE_KEY,
            display_name="AWS Network Firewall",
            version=_VERSION,
            flavor="pull",
            # ADR-0067 D6 + Amendment 1 (issue #75): declared enforcement-posture
            # default. AWS Network Firewall is an inline, enforcing control — stateful
            # rule groups can DROP/REJECT/ALERT. A qualified Tier-2 verdict with zero
            # BLOCK/DROP events from this actor gets the honest "not blocked — this
            # control was enforcing and did not block it" label (Amendment 1 A1.1)
            # rather than the generic "block status unknown".
            enforcement="enforce",
        )

    def config_schema(self) -> type[BaseModel]:
        """Return the Pydantic model that drives the rjsf UI Settings card.

        The schema is returned as a class (not an instance) so the discovery
        endpoint can call model_json_schema() on it. SecretStr fields default
        to None so secrets are never emitted in the JSON schema response
        (PLUGIN_CONTRACT.md / EARS-4).
        """
        return AwsNetworkFirewallConfig

    def validate_config(self, cfg: dict[str, Any]) -> None:
        """Validate a raw config dict against the AwsNetworkFirewallConfig schema.

        Raises pydantic.ValidationError if invalid.
        """
        AwsNetworkFirewallConfig.model_validate(cfg)

    def normalize(self, raw: RawEvent, source_id: str) -> SecurityEvent:
        """Map an AWS NFW RawEvent to a SecurityEvent.

        source_type is always "aws_network_firewall" (this plugin's constant).
        source_id is the caller's instance name — passed through, never branched on
        (Flag B, PLUGIN_CONTRACT.md / EARS-6).
        """
        return _normalize.normalize(raw, source_id)

    async def health_check(self, cfg: BaseModel) -> bool:
        """Return True if CloudWatch Logs is reachable and credentials are valid.

        Returns False (never raises) on any failure, so the Settings-card "Test"
        button surfaces failures cleanly (PLUGIN_CONTRACT.md health_check contract).
        """
        try:
            nfw_cfg = (
                cfg
                if isinstance(cfg, AwsNetworkFirewallConfig)
                else AwsNetworkFirewallConfig.model_validate(cfg.model_dump())
            )
        except Exception:
            return False

        return await _client.health_check(nfw_cfg)

    # ── PullSource method ────────────────────────────────────────────────────

    async def collect(
        self, cfg: BaseModel, since: str | None, ctx: PluginContext
    ) -> AsyncIterator[RawEvent]:
        """Yield RawEvents for NFW alert records newer than since.

        since is an ISO-8601 watermark string (or None for the initial 24h window).
        The 5-minute overlap is applied inside client.collect to catch late records.

        ctx carries ctx.kv (scoped KV, ADR-0025) and ctx.source_id (instance label,
        ADR-0027). Neither is used for detection (Flag B).

        Must be cancellable (CancelledError propagates — PLUGIN_CONTRACT.md hard rule).
        On credential/connectivity/API errors, raises typed errors so the supervisor
        can isolate this instance without masking failures as "no data" (EARS-3).
        """
        nfw_cfg = (
            cfg
            if isinstance(cfg, AwsNetworkFirewallConfig)
            else AwsNetworkFirewallConfig.model_validate(cfg.model_dump())
        )
        try:
            async for raw in _client.collect(nfw_cfg, since):
                yield raw
        except asyncio.CancelledError:
            raise  # always propagate (PLUGIN_CONTRACT.md hard rule)
        # AwsNfwError subclasses (Auth/Connect/Query) propagate to the supervisor;
        # they are NOT caught here — swallowing them as "no data" is the anti-pattern
        # we explicitly avoid (PLUGIN_CONTRACT.md / EARS-3).
