"""AzureWAFSource — FireWatch PullSource plugin for Azure WAF.

Registered as ``azure_waf`` under the ``firewatch.sources`` entry-point group.
Adding this package requires zero edits to firewatch-core (PLUGIN_CONTRACT.md
modularity guarantee).

Implements:
  - ``SourcePlugin``  (metadata, config_schema, validate_config, normalize, health_check)
  - ``PullSource``    (collect)

Depends on ``firewatch-sdk`` ONLY. Never imports ``firewatch-core`` or ``legacy/``.

Module layout (per architect's sketch in issue #86):
  plugin.py    — thin surface; delegates to sub-modules.
  config.py    — AzureWAFConfig Pydantic model (Settings card driver).
  client.py    — Log Analytics KQL pull + watermark window + typed errors.
  normalize.py — RawEvent → SecurityEvent; App-Gateway/Front-Door shapes; action map.
  crs.py       — static CRS rule-ID range table (no runtime CRS dependency, ADR-0014).
  severity.py  — severity_from_category() + anomaly-score refinement.
"""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

from pydantic import BaseModel

from firewatch_sdk import PluginContext, RawEvent, SecurityEvent, SourceMetadata

from firewatch_azure_waf import client as _client
from firewatch_azure_waf import normalize as _normalize
from firewatch_azure_waf.config import AzureWAFConfig

# Plugin version — SemVer string (PLUGIN_CONTRACT.md SourceMetadata.version).
_VERSION = "0.1.0"

# The canonical type key for this source.  Matches the entry-point name and the
# literal already referenced in firewatch-core pipeline.py:158,277 for security_mode.
# Constrained to ^[a-z][a-z0-9_]*$ (PLUGIN_CONTRACT.md / ADR-0025 addendum).
_TYPE_KEY = "azure_waf"


class AzureWAFSource:
    """Azure WAF Log Analytics source plugin.

    Implements ``SourcePlugin`` + ``PullSource`` from firewatch-sdk.

    Pull path (ADR-0005, azure-waf-log-standard.md §1d):
      Queries Azure Log Analytics via ``azure-monitor-query``'s ``LogsQueryClient``
      with ``DefaultAzureCredential`` (or explicit service-principal credentials).
      Prefers resource-specific tables (``AGWFirewallLogs``, Front Door equivalent)
      with an explicit AzureDiagnostics fallback when configured.

    Normalization (ADR-0012, ADR-0014, ADR-0016, ADR-0020):
      - ``source_type`` is the constant ``"azure_waf"`` — never branches on ``source_id``.
      - Action map: Block→BLOCK, Detected/Matched/AnomalyScoring→ALERT, Allow→ALLOW, Log→LOG.
      - ocsf_class=4002 (HTTP Activity), ocsf_category=4 (Network Activity).
      - Full CRS range coverage via static table (no ~68% Other, ADR-0014).
      - severity always set from CRS category + anomaly-score refinement.
    """

    # ── SourcePlugin methods ─────────────────────────────────────────────────

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            type_key=_TYPE_KEY,
            display_name="Azure WAF",
            version=_VERSION,
            flavor="pull",
            # ADR-0060: canonical SecurityEvent fields Azure WAF's normalize() populates.
            # Azure WAF is an L7 HTTP gateway.  It does NOT carry destination_ip,
            # destination_port, or protocol (azure-waf-log-standard.md §3 critique #5).
            # It also does not carry http_method or http_user_agent in diagnostic logs.
            # Flow (bytes/packets), DNS, and TLS fingerprint fields are absent (L7 only).
            # source_port is conditionally set (Front Door has clientPort; App Gateway
            # does not) — included in produces because it is populated when available.
            produces=frozenset({
                # Transport — source side only (destination fields not available in WAF logs)
                "source_ip", "source_port",
                # Event classification
                "action", "category", "severity",
                "ocsf_class", "ocsf_category",
                # Rule fields
                "rule_id", "rule_name",
                # Payload snippet (built from details.data / details.message / requestUri)
                "payload_snippet",
                # MITRE ATT&CK / CAPEC (from CRS lookup table)
                "attack_technique", "attack_tactic",
                "kill_chain_phase", "capec_id",
                # ADR-0048 Group D: HTTP fields (the two Azure WAF actually provides)
                # http_method and http_user_agent are NOT set (not in WAF diagnostic logs)
                "http_url", "http_host",
                # Source event correlation
                "source_event_id",
                # Raw log retained for drill-down
                "raw_log",
            }),
        )

    def config_schema(self) -> type[BaseModel]:
        """Return the Pydantic model that drives the rjsf UI Settings card.

        The schema is returned as a class (not an instance) so the discovery
        endpoint can call ``model_json_schema()`` on it.  SecretStr fields
        default to ``None`` so secrets are never emitted in the JSON schema
        response (PLUGIN_CONTRACT.md).
        """
        return AzureWAFConfig

    def validate_config(self, cfg: dict[str, Any]) -> None:
        """Validate a raw config dict against the AzureWAFConfig schema.

        Raises ``pydantic.ValidationError`` if invalid.
        """
        AzureWAFConfig.model_validate(cfg)

    def normalize(self, raw: RawEvent, source_id: str) -> SecurityEvent:
        """Map an Azure WAF ``RawEvent`` to a ``SecurityEvent``.

        ``source_type`` is always ``"azure_waf"`` (this plugin's constant).
        ``source_id`` is the caller's instance name — passed through, never branched on
        (Flag B, PLUGIN_CONTRACT.md).
        """
        return _normalize.normalize(raw, source_id)

    async def health_check(self, cfg: BaseModel) -> bool:
        """Return True if the Log Analytics workspace is reachable and credentials are valid.

        Returns False (never raises) on any failure, so the Settings-card "Test"
        button surfaces failures cleanly (PLUGIN_CONTRACT.md health_check contract).
        """
        try:
            waf_cfg = (
                cfg
                if isinstance(cfg, AzureWAFConfig)
                else AzureWAFConfig.model_validate(cfg.model_dump())
            )
        except Exception:
            return False

        return await _client.health_check(waf_cfg)

    # ── PullSource method ────────────────────────────────────────────────────

    async def collect(
        self, cfg: BaseModel, since: str | None, ctx: PluginContext
    ) -> AsyncIterator[RawEvent]:
        """Yield ``RawEvent``s for Azure WAF events newer than ``since``.

        ``since`` is an ISO-8601 watermark string (or None for the initial 24h window).
        The 5-minute overlap is applied inside ``client.collect`` to catch late records.

        ``ctx`` carries ``ctx.kv`` (scoped KV, ADR-0025) and ``ctx.source_id``
        (instance label, ADR-0027).  Neither is used for detection (Flag B).

        Must be cancellable (CancelledError propagates).
        On credential / connectivity / query errors, raises typed errors so the
        supervisor can isolate this instance without masking failures as "no data"
        (PLUGIN_CONTRACT.md hard rules + azure-waf-log-standard.md §3 critique #6).
        """
        waf_cfg = (
            cfg
            if isinstance(cfg, AzureWAFConfig)
            else AzureWAFConfig.model_validate(cfg.model_dump())
        )
        try:
            async for raw in _client.collect(waf_cfg, since):
                yield raw
        except asyncio.CancelledError:
            raise  # always propagate (PLUGIN_CONTRACT.md hard rule)
        # AzureWAFError subclasses (Auth/Connect/Query) propagate to the supervisor;
        # they are NOT caught here — swallowing them as "no data" is the legacy
        # anti-pattern we explicitly avoid (§3 critique #6).
