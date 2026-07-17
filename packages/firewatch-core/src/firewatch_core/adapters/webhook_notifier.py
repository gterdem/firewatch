"""WebhookNotifier — Discord/Slack/generic webhook implementation of the Notifier port.

Behavior ported from the v1 alerter (the legacy/ oracle) — Discord/Slack auto-detect
with a generic-JSON fallback — but re-wired to the FireWatch v2 contract:

- Config is read from the injected ``ConfigStore`` at call time (so an operator's
  config edit takes effect on the next alert, mirroring v1), never from a global.
- ``webhook_url`` is a ``SecretStr`` (its value may carry an auth token); it is
  extracted only at send time and never logged.
- The URL is anti-SSRF-validated at config-write time by ``RuntimeConfig`` (ADR-0026);
  this adapter does not re-validate.
- ``check_and_alert`` gates on the band axis only when ``notify_on_auto_escalate`` is
  False; when True (the default since ADR-0059 Amendment 1 / issue #74) it uses the
  shared ``is_alert_worthy`` predicate from ``escalation.worthiness`` (band OR
  tier <= 2, ADR-0059 D3).
- ``check_and_alert`` fires only on a notification-worthy STATE TRANSITION, never on
  repeated re-evaluation of an unchanged state (ADR-0059 Amendment 1 / issue #74).
  Cadence is delegated to ``escalation.transition.NotifyTransitionTracker`` — see that
  module for the exact transition rules. This closes the stock-vs-flow gap: without
  it, an actor that stays alert-worthy re-notifies on every ingest-triggered
  analysis (``pipeline.background_analyze_and_alert`` runs per event / per batch-IP).

MB.3 / issue #55. Implements ``firewatch_sdk.ports.Notifier``.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from firewatch_core.escalation.transition import NotifyTransitionTracker
from firewatch_core.escalation.worthiness import band_meets, is_alert_worthy
from firewatch_sdk.config import ConfigStore, RuntimeConfig
from firewatch_sdk.models import ThreatScore

logger = logging.getLogger("firewatch.webhook")

_TIMEOUT_S = 10.0

_THREAT_COLORS: dict[str, int] = {
    "CRITICAL": 0xEF4444,
    "HIGH": 0xF97316,
    "MEDIUM": 0x3B82F6,
    "LOW": 0x22C55E,
}


class WebhookNotifier:
    """Outbound webhook notifier (Discord/Slack auto-detect, generic fallback)."""

    def __init__(self, config_store: ConfigStore) -> None:
        self._config = config_store
        # Per-actor notification cadence (ADR-0059 Amendment 1 / issue #74). Lives
        # on the instance so cadence state survives across calls for as long as
        # this WebhookNotifier does — one process restart is the acceptable reset
        # boundary (issue #74's implementation note).
        self._transitions = NotifyTransitionTracker()

    # ---- config access (read fresh each call) --------------------------------

    def _runtime(self) -> RuntimeConfig:
        return self._config.get_runtime()

    @staticmethod
    def _url(runtime: RuntimeConfig) -> str | None:
        wh = runtime.webhook_url
        return wh.get_secret_value() if wh is not None else None

    @staticmethod
    def _meets_threshold(level: str, threshold: str) -> bool:
        """Delegate to the shared band-ordering helper (single source of truth).

        Thin wrapper kept for backward compatibility — external callers that
        already reference ``WebhookNotifier._meets_threshold`` continue to work.
        The ordering logic lives in ``escalation.worthiness.band_meets``.
        """
        return band_meets(level, threshold)

    # ---- URL flavor detection -------------------------------------------------

    @staticmethod
    def _is_discord(url: str) -> bool:
        return "discord.com/api/webhooks" in url or "discordapp.com/api/webhooks" in url

    @staticmethod
    def _is_slack(url: str) -> bool:
        return "hooks.slack.com" in url

    # ---- payload formatting (ported from the v1 oracle) -----------------------

    def _format_alert(self, url: str, ts: ThreatScore) -> dict[str, Any]:
        if self._is_discord(url):
            return self._format_discord(ts)
        if self._is_slack(url):
            return self._format_slack(ts)
        return self._format_generic(ts)

    def _format_discord(self, ts: ThreatScore) -> dict[str, Any]:
        color = _THREAT_COLORS.get(ts.threat_level, 0x64748B)
        attacks = ", ".join(ts.attack_types) if ts.attack_types else "None detected"
        insights = (
            "\n".join(f"• {i}" for i in ts.ai_insights[:5])
            if ts.ai_insights
            else "No AI insights"
        )
        return {
            "embeds": [
                {
                    "title": f"🔥 FireWatch Alert — {ts.threat_level}",
                    "description": (
                        f"**Threat detected from `{ts.source_ip}`**\n"
                        f"Score: **{ts.score}/100** | AI: {ts.ai_status}"
                    ),
                    "color": color,
                    "fields": [
                        {"name": "Events", "value": str(ts.total_events), "inline": True},
                        {"name": "Blocked", "value": str(ts.blocked_events), "inline": True},
                        {"name": "Attack Types", "value": attacks, "inline": False},
                        {"name": "AI Insights", "value": insights[:1024], "inline": False},
                    ],
                    "footer": {"text": "FireWatch"},
                }
            ],
        }

    def _format_slack(self, ts: ThreatScore) -> dict[str, Any]:
        attacks = ", ".join(ts.attack_types) if ts.attack_types else "None"
        insights = (
            "\n".join(f"• {i}" for i in ts.ai_insights[:5])
            if ts.ai_insights
            else "No AI insights"
        )
        return {
            "text": f"🔥 {ts.threat_level} threat from {ts.source_ip} (score: {ts.score})",
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": f"🔥 FireWatch Alert — {ts.threat_level}"},
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"*IP:* `{ts.source_ip}` | *Score:* {ts.score}/100 | *AI:* {ts.ai_status}\n"
                            f"*Events:* {ts.total_events} | *Blocked:* {ts.blocked_events}\n"
                            f"*Attacks:* {attacks}"
                        ),
                    },
                },
                {"type": "section", "text": {"type": "mrkdwn", "text": f"*Insights:*\n{insights}"}},
            ],
        }

    def _format_generic(self, ts: ThreatScore) -> dict[str, Any]:
        return {
            "alert_level": ts.threat_level,
            "source_ip": ts.source_ip,
            "score": ts.score,
            "total_events": ts.total_events,
            "blocked_events": ts.blocked_events,
            "attack_types": ts.attack_types,
            "ai_status": ts.ai_status,
            "ai_insights": ts.ai_insights,
            "message": (
                f"{ts.threat_level} threat detected from {ts.source_ip} (score: {ts.score})"
            ),
        }

    # ---- delivery -------------------------------------------------------------

    @staticmethod
    async def _post(url: str, payload: dict[str, Any]) -> bool:
        """POST *payload* to *url*; return True on success, False on any failure (never raises).

        The URL is intentionally excluded from all log output — it may carry an auth
        token (SecretStr policy, ADR-0026).  On HTTP error only the status code is
        logged; on connection/timeout errors no URL or traceback is emitted (the
        traceback can reference the request object which embeds the URL).

        ``follow_redirects=False`` is set explicitly (ADR-0026 Decision 6, OWASP API7):
        a 3xx redirect could bypass the config-write-time URL allowlist by redirecting
        to a blocked internal/metadata target after validation.  A 3xx response is
        treated as a delivery failure (status code logged, returns False).
        """
        try:
            async with httpx.AsyncClient(
                timeout=_TIMEOUT_S,
                follow_redirects=False,  # ADR-0026 D6 — no unbounded redirect following
            ) as client:
                response = await client.post(url, json=payload)
                response.raise_for_status()
            return True
        except httpx.HTTPStatusError as exc:
            # Log only the status code — never the URL (may carry a token).
            # 3xx responses reach here via raise_for_status() because follow_redirects=False.
            logger.error("Webhook delivery failed with HTTP %d", exc.response.status_code)
            return False
        except Exception:
            # Connection errors, timeouts, etc.  Use logger.error (not .exception)
            # to suppress the traceback, which can reference the request URL.
            logger.error("Webhook delivery failed (connection/timeout error)")
            return False

    # ---- Notifier port --------------------------------------------------------

    async def send_alert(self, threat: ThreatScore) -> bool:
        """Unconditionally send the alert. Returns True on success."""
        url = self._url(self._runtime())
        if url is None:
            logger.debug("No webhook URL configured — skipping alert for %s", threat.source_ip)
            return False
        ok = await self._post(url, self._format_alert(url, threat))
        if ok:
            logger.info("Alert sent for %s (score %d)", threat.source_ip, threat.score)
        return ok

    async def check_and_alert(self, threat: ThreatScore) -> bool:
        """Send only if the threat is alert-worthy AND its state just transitioned.

        Gate logic (ADR-0059 D3, default flipped by Amendment 1 / issue #74):
        - ``notify_on_auto_escalate`` **True** (default): full ``is_alert_worthy``
          predicate — band OR escalation tier <= 2. A low-score allowed-through /
          block-status-unknown detection also triggers a notification.
        - ``notify_on_auto_escalate`` **False**: band-only gate.
          ``band_meets(threat_level, alert_threshold)`` must be True or no
          notification is sent.

        Cadence (ADR-0059 Amendment 1 / issue #74): worthiness alone is not
        sufficient — the call also fires only when ``NotifyTransitionTracker``
        reports a fresh transition (entering the worthy state, or getting louder
        while already in it) for this actor. An actor that stays continuously
        worthy across repeated calls (this method is invoked per ingested event /
        per batch-IP, see ``pipeline.background_analyze_and_alert``) does NOT
        re-notify on every call — this is the fix for the pre-existing
        statelessness bug where a CRITICAL-band actor re-notified on every
        analysis. The transition tracker's inputs (band + tier) are recorded on
        every evaluation, including non-worthy ones, so a later crossing is
        detected correctly.

        A webhook URL must be configured or the call returns False without
        touching the transition tracker (no channel — nothing to track towards).
        """
        runtime = self._runtime()
        url = self._url(runtime)
        if url is None:
            return False

        band_met = band_meets(threat.threat_level, runtime.alert_threshold)
        tier = threat.escalation.tier if threat.escalation is not None else None

        if runtime.notify_on_auto_escalate:
            worthy = is_alert_worthy(threat, runtime.alert_threshold)
        else:
            worthy = band_met

        fresh = self._transitions.transitioned(
            threat.source_ip,
            band_met=band_met,
            tier=tier,
            tier_axis_enabled=runtime.notify_on_auto_escalate,
        )
        if not (worthy and fresh):
            return False

        ok = await self._post(url, self._format_alert(url, threat))
        if ok:
            logger.info("Threshold alert sent for %s (score %d)", threat.source_ip, threat.score)
        return ok

    async def send_sync_digest(
        self,
        total_new: int,
        blocked_new: int,
        ip_blocks: list[dict[str, Any]],
        categories: dict[str, int],
    ) -> bool:
        """Send a roll-up digest after a sync run (only if configured + meaningful)."""
        runtime = self._runtime()
        url = self._url(runtime)
        if url is None or not runtime.alert_on_sync or blocked_new == 0:
            return False

        top_ips = ", ".join(f"{d['ip']} ({d['blocked']})" for d in ip_blocks[:5])
        top_cats = ", ".join(
            f"{cat} ({cnt})" for cat, cnt in sorted(categories.items(), key=lambda x: -x[1])[:5]
        )

        if self._is_discord(url):
            payload: dict[str, Any] = {
                "embeds": [
                    {
                        "title": "🔄 FireWatch Sync Alert",
                        "description": (
                            f"Auto-synced **{total_new}** new logs (**{blocked_new}** blocked)"
                        ),
                        "color": 0xF59E0B,
                        "fields": [
                            {"name": "Top IPs", "value": top_ips or "None", "inline": False},
                            {"name": "Categories", "value": top_cats or "None", "inline": False},
                        ],
                        "footer": {"text": "FireWatch — Auto-sync"},
                    }
                ],
            }
        elif self._is_slack(url):
            payload = {
                "text": f"🔄 FireWatch: Auto-synced {total_new} logs ({blocked_new} blocked)",
                "blocks": [
                    {
                        "type": "header",
                        "text": {"type": "plain_text", "text": "🔄 FireWatch Sync Alert"},
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": (
                                f"*New logs:* {total_new} | *Blocked:* {blocked_new}\n"
                                f"*Top IPs:* {top_ips}\n*Categories:* {top_cats}"
                            ),
                        },
                    },
                ],
            }
        else:
            payload = {
                "type": "sync_digest",
                "total_new": total_new,
                "blocked_new": blocked_new,
                "top_ips": ip_blocks[:5],
                "categories": categories,
                "message": f"Auto-synced {total_new} logs ({blocked_new} blocked)",
            }

        ok = await self._post(url, payload)
        if ok:
            logger.info("Sync digest sent: %d new, %d blocked", total_new, blocked_new)
        return ok
