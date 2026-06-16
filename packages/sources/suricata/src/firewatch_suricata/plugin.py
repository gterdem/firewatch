"""SuricataSource — the canonical FireWatch PullSource reference plugin.

Registered as ``suricata`` under the ``firewatch.sources`` entry-point group.
Adding this package to the workspace requires zero edits to firewatch-core
(PLUGIN_CONTRACT.md modularity guarantee).

This module implements:
  - ``SourcePlugin`` (metadata, config_schema, validate_config, normalize, health_check)
  - ``PullSource`` (collect)
  - ``ActionCapable`` (run_action, action_status) — issue #168 / ADR-0034

It depends on ``firewatch-sdk`` ONLY. Never imports firewatch-core or legacy/.

Issue #150 — rule descriptions:
  ``collect()`` in local mode writes SID->description mappings from the configured
  ``rules_path`` into ``ctx.kv`` (namespace ``"rule_descriptions"``) before
  yielding events.  Remote mode uses ``fetch_ruleset`` action instead (ADR-0034 §D).

Issue #165 — per-namespace cap + change detection:
  ``_write_rule_descriptions`` now:
    (a) Reads the rules file fingerprint (mtime + byte size) from the private
        ``_suricata_state`` namespace in ``ctx.kv`` before parsing.  If the
        fingerprint matches the current file on disk, the write is skipped
        entirely (no re-parse, no re-write).  This prevents the 244k+
        cap errors per session observed with a 30-second collect cycle and a
        43 MB ruleset.
    (b) On a ``SourceKVCapExceededError`` from ``ctx.kv.put``, logs exactly
        ONE warning for the whole cycle and bails — no 40k swallowed
        exceptions (ADR-0003 / issue #165 EARS A2).

Issue #168 — fetch_ruleset maintenance action (ADR-0034 §D):
  ``metadata().actions`` declares ``fetch_ruleset`` (long_running=True).
  ``run_action`` and ``action_status`` are implemented; dispatch delegates to
  ``firewatch_suricata.actions``.  Per-cycle remote stat is recorded in
  ``collect()`` for remote mode.
"""
from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from firewatch_sdk import (
    ActionCapable,  # noqa: F401  — satisfying the protocol; checked by isinstance
    ActionResult,
    ActionStatus,
    PluginContext,
    RawEvent,
    SecurityEvent,
    SourceAction,
    SourceMetadata,
)

from firewatch_suricata import collector as _collector
from firewatch_suricata import normalize as _normalize
from firewatch_suricata.config import SuricataConfig
from firewatch_suricata.rules import parse_rules_dir, parse_rules_file

logger = logging.getLogger("firewatch.suricata.plugin")

# Plugin version — SemVer string (PLUGIN_CONTRACT.md SourceMetadata.version).
_VERSION = "0.1.0"

# The canonical type key for this source. Must match the entry-point name and
# the regex ^[a-z][a-z0-9_]*$ (PLUGIN_CONTRACT.md SourceMetadata type_key constraint;
# leading letter required — leading underscore is core-reserved, ADR-0025 addendum).
_TYPE_KEY = "suricata"

# Namespace key used in ctx.kv for rule SID->description catalog (ADR-0025).
# The pipeline reads this namespace after each collect cycle and promotes entries
# into the global rule_descriptions table (issue #150).
_RULE_DESC_NAMESPACE = "rule_descriptions"

# Private namespace used to persist per-file change-detection state (issue #165).
# Keyed by the resolved rules_path string so that a config change to a different
# file always triggers a fresh load.  The leading underscore is a usage convention
# indicating internal/plugin-private state; it does not conflict with the
# core-reserved "_global" source_type (that boundary is at source_type, not namespace).
_RULES_STATE_NAMESPACE = "_suricata_state"

# KV key prefix for rules-file fingerprints within _RULES_STATE_NAMESPACE.
# Full key: _FP_KEY_PREFIX + rules_path_str (e.g. "_rules_fp:/etc/suricata/rules").
_FP_KEY_PREFIX = "_rules_fp:"


def _file_fingerprint(path: Path) -> str:
    """Return a ``"{mtime}:{size}"`` fingerprint for the file or directory at *path*.

    For a regular file: uses ``st_mtime`` and ``st_size`` from a single ``stat()``
    call (no hashing — fast enough for a hot loop; collision-resistant in practice
    because mtime is float and size is bytes).

    For a directory: aggregates mtime and size across all ``.rules`` files inside
    it (sorted for determinism).  Any file whose stat raises is silently skipped —
    the worst outcome is a false-positive "changed" result that triggers an
    unnecessary re-parse, which is safe.

    Returns an empty string when the path does not exist, which causes the
    fingerprint comparison to always miss and triggers a re-parse.
    """
    try:
        if path.is_file():
            st = path.stat()
            return f"{st.st_mtime}:{st.st_size}"
        if path.is_dir():
            parts: list[str] = []
            for f in sorted(path.glob("*.rules")):
                try:
                    st = f.stat()
                    parts.append(f"{f.name}:{st.st_mtime}:{st.st_size}")
                except OSError:
                    pass
            return "|".join(parts) if parts else ""
    except OSError:
        pass
    return ""


class SuricataSource:
    """Suricata EVE JSON source plugin.

    Implements ``SourcePlugin`` + ``PullSource`` + ``ActionCapable`` from firewatch-sdk.

    Two collection modes (ADR-0005):
      - ``local``: reads ``eve.json`` from the local filesystem.
      - ``remote``: SSHs into a remote host and greps the EVE log file.

    Normalization (ADR-0012, ADR-0014, ADR-0016):
      - ``source_type`` is the constant ``"suricata"`` — never branches on ``source_id``.
      - ``action=ALERT`` for IDS detections; ``action=BLOCK`` for IPS blocks.
      - ``attack_technique`` / ``attack_tactic`` from ET Open ``mitre_*`` metadata.

    Maintenance actions (ADR-0034 §D, issue #168):
      - ``fetch_ruleset``: manual SSH/local ruleset download.
      - See ``firewatch_suricata.actions`` for dispatch.
    """

    # ── SourcePlugin methods ─────────────────────────────────────────────────

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            type_key=_TYPE_KEY,
            display_name="Suricata IDS/IPS",
            version=_VERSION,
            flavor="pull",
            actions=(
                SourceAction(
                    id="fetch_ruleset",
                    label="Fetch Ruleset",
                    description=(
                        "Download the Suricata rules file from the sensor and build "
                        "the SID→description catalog used for rule-name display."
                    ),
                    long_running=True,
                    confirm=(
                        "This will download the full Suricata ruleset (~40–60 MB) "
                        "from the sensor over SSH. Proceed?"
                    ),
                    provides=("rule_descriptions",),
                ),
                SourceAction(
                    id="run_connectivity_check",
                    label="Run diagnostics",
                    description=(
                        "Probe SSH reachability/auth, eve.json readability, "
                        "and recent alert activity."
                    ),
                    long_running=False,
                    confirm=None,
                    provides=(),
                ),
            ),
            # ADR-0060: canonical SecurityEvent fields Suricata's normalize() populates.
            # Suricata is a broad L3–L7 IDS/IPS sensor; it populates transport fields
            # (L3/L4), classification fields, MITRE ATT&CK, and ADR-0048 network-depth
            # sub-objects (flow, DNS, TLS, HTTP).  Fields it never sets (file_*, dns_answer,
            # kill_chain_phase, capec_id, geo_*, tls_ja3) are intentionally omitted.
            produces=frozenset({
                # Core identity and transport (L3/L4)
                "source_ip", "source_port",
                "destination_ip", "destination_port", "protocol",
                # Event classification
                "action", "category", "severity",
                "ocsf_class", "ocsf_category",
                # Rule fields
                "rule_id", "rule_name",
                # Payload
                "payload_snippet",
                # MITRE ATT&CK (from ET Open metadata)
                "attack_technique", "attack_tactic",
                # ADR-0048 Group A: flow volume & duration
                "bytes_in", "bytes_out",
                "packets_in", "packets_out",
                "flow_duration_ms",
                # ADR-0048 Group B: DNS
                "dns_query", "dns_rcode",
                # ADR-0048 Group C: TLS / JA4 (Suricata 7.x+; null on older builds)
                "tls_ja4", "tls_ja4s",
                "tls_sni", "tls_version",
                # ADR-0048 Group D: HTTP
                "http_method", "http_host", "http_url", "http_user_agent",
                # Source event correlation
                "source_event_id",
                # Raw log retained for drill-down
                "raw_log",
            }),
        )

    def config_schema(self) -> type[BaseModel]:
        """Return the Pydantic model that drives the rjsf UI source card.

        The returned class emits JSON Schema with ``if/then/else`` for the
        local/remote mode toggle (ADR-0019). SSH key fields use ``SecretStr``
        (PLUGIN_CONTRACT.md). Config resolution respects env > file > default
        (ADR-0006); use ``build_config()`` at runtime to construct the instance.
        """
        return SuricataConfig

    def validate_config(self, cfg: dict[str, Any]) -> None:
        """Validate a raw config dict against the Suricata config schema.

        Raises ``pydantic.ValidationError`` if the config is invalid.
        """
        SuricataConfig.model_validate(cfg)

    def normalize(self, raw: RawEvent, source_id: str) -> SecurityEvent:
        """Map a Suricata EVE alert RawEvent to a SecurityEvent.

        ``source_type`` is always ``"suricata"`` (this plugin's constant).
        ``source_id`` is the caller's instance name, passed through as-is.
        This method MUST NOT branch on ``source_id`` (Flag B, PLUGIN_CONTRACT.md).
        """
        return _normalize.normalize(raw, source_id)

    async def health_check(self, cfg: BaseModel) -> bool:
        """Return True if the configured source is reachable/readable.

        Local mode: checks whether the eve.json path exists, is a regular file,
        AND is readable by the current process (os.access R_OK).
        Remote mode: opens an SSH connection and verifies the remote file via
        ``test -r`` — directly, without going through ``_collector.collect``.

        Fix (#689): the previous remote implementation ran ``_collector.collect``
        and treated an empty result as success.  Because ``collect`` never raises
        out of its loop (PLUGIN_CONTRACT.md hard rule), SSH connect failures and
        unreadable eve.json both returned empty — so health_check falsely reported
        True even when the source was broken.  The new implementation calls the
        SSH helpers directly so failures surface as False.

        Returns False (never raises) on any failure.
        """
        try:
            suricata_cfg = (
                cfg
                if isinstance(cfg, SuricataConfig)
                else SuricataConfig.model_validate(cfg.model_dump())
            )
        except Exception:
            return False

        try:
            if suricata_cfg.mode == "local":
                import os as _os
                path = Path(suricata_cfg.local_path or "")
                return (
                    path.exists()
                    and path.is_file()
                    and _os.access(path, _os.R_OK)
                )
            else:
                # Remote: use the diagnostics SSH + test-r probes directly so
                # connect/auth/read failures return False (not silently empty).
                from firewatch_suricata.diagnostics import (
                    _probe_evejson_remote,
                    _probe_ssh,
                )
                ssh = await _probe_ssh(suricata_cfg)
                if ssh.status != "pass":
                    return False
                evejson = await _probe_evejson_remote(suricata_cfg)
                return evejson.status == "pass"
        except Exception:
            return False

    # ── PullSource method ────────────────────────────────────────────────────

    async def collect(
        self, cfg: BaseModel, since: str | None, ctx: PluginContext
    ) -> AsyncIterator[RawEvent]:
        """Yield ``RawEvent``s for Suricata EVE alerts newer than ``since``.

        ``since`` is an ISO-8601 watermark string, or ``None`` for the initial
        full sync. Must be cancellable; must not raise out of its loop
        (PLUGIN_CONTRACT.md hard rules).

        ``ctx`` is the per-instance capability carrier (ADR-0027). ``ctx.kv`` is
        used to persist rule SID->description mappings in local mode (issue #150).

        Rule descriptions:
          - Local mode: parsed per-cycle from ``rules_path`` with change detection.
          - Remote mode: populated ONLY by the ``fetch_ruleset`` action (ADR-0034 §D).
            collect() in remote mode records a cheap stat of the rules path into
            ``ruleset_meta`` to enable freshness detection by ``action_status``.
        """
        suricata_cfg = (
            cfg
            if isinstance(cfg, SuricataConfig)
            else SuricataConfig.model_validate(cfg.model_dump())
        )

        if suricata_cfg.mode == "local":
            # Issue #150/#165: populate rule descriptions in ctx.kv before yielding
            # events, with change-detection to skip unchanged rulesets.
            await _write_rule_descriptions(suricata_cfg, ctx)

        async for raw in _collector.collect(suricata_cfg, since, ctx=ctx):
            yield raw

    # ── ActionCapable methods ─────────────────────────────────────────────────

    async def run_action(
        self,
        action_id: str,
        cfg: Any,
        ctx: PluginContext,
    ) -> ActionResult:
        """Execute the named maintenance action.

        Delegates to ``firewatch_suricata.actions``.  MUST NOT raise — all
        failures return ``ActionResult(ok=False, …)`` (ADR-0034).
        """
        from firewatch_suricata import actions as _actions

        try:
            suricata_cfg = (
                cfg
                if isinstance(cfg, SuricataConfig)
                else SuricataConfig.model_validate(
                    cfg.model_dump() if hasattr(cfg, "model_dump") else cfg
                )
            )
            if action_id == "fetch_ruleset":
                return await _actions.fetch_ruleset_run(suricata_cfg, ctx)
            if action_id == "run_connectivity_check":
                from firewatch_suricata.diagnostics import run_connectivity_check
                return await run_connectivity_check(suricata_cfg, ctx)
            return ActionResult(
                ok=False,
                message=f"Unknown action: {action_id!r}",
            )
        except Exception as exc:
            logger.error(
                "suricata.plugin: run_action(%r) unexpected error: %s",
                action_id,
                type(exc).__name__,
            )
            return ActionResult(
                ok=False,
                message=(
                    "Action failed due to an unexpected error. "
                    "Check the FireWatch logs."
                ),
            )

    async def action_status(
        self,
        action_id: str,
        cfg: Any,
        ctx: PluginContext,
    ) -> ActionStatus:
        """Return the current status of the named action (KV-only, no SSH).

        Delegates to ``firewatch_suricata.actions``.
        """
        from firewatch_suricata import actions as _actions

        if action_id == "fetch_ruleset":
            suricata_cfg = (
                cfg
                if isinstance(cfg, SuricataConfig)
                else SuricataConfig.model_validate(
                    cfg.model_dump() if hasattr(cfg, "model_dump") else cfg
                )
            )
            return await _actions.fetch_ruleset_status(suricata_cfg, ctx)
        return ActionStatus()


async def _write_rule_descriptions(
    cfg: SuricataConfig, ctx: PluginContext
) -> None:
    """Parse the configured rules_path and write SID->msg into ctx.kv.

    Change detection (issue #165 EARS A3):
      Computes a ``"{mtime}:{size}"`` fingerprint for the rules file/directory
      and compares it against the value stored in
      ``ctx.kv._suricata_state._rules_fp:{rules_path}``.  If the fingerprints
      match, the function returns without re-parsing or re-writing.  The new
      fingerprint is stored only after a fully successful write cycle so that
      a partially-written cycle (e.g. cap hit mid-way) triggers a re-attempt
      on the next call.

    Cap-exceeded signal (issue #165 EARS A2):
      On the first ``SourceKVCapExceededError`` from ``ctx.kv.put``, logs
      exactly ONE warning and bails.  Remaining rules are not attempted.
      This replaces the previous per-key loop that swallowed 40k+ exceptions
      per session.

    Fail-safe (ADR-0003):
      Any parse error, filesystem error, or unexpected kv error is caught and
      logged; rule-description unavailability must never abort event collection.

    Parameters
    ----------
    cfg:
        The resolved SuricataConfig; ``rules_path`` is read from here.
    ctx:
        The per-instance PluginContext providing the scoped KV store.
    """
    rules_path_str = (cfg.rules_path or "").strip()
    if not rules_path_str:
        return

    rules_path = Path(rules_path_str)

    # ── Change detection ────────────────────────────────────────────────────
    # Fingerprint the file/directory on disk and compare against the last-seen
    # fingerprint stored in ctx.kv.  Skip re-writing if unchanged.
    fp_key = _FP_KEY_PREFIX + rules_path_str
    current_fp = _file_fingerprint(rules_path)

    try:
        stored_fp = await ctx.kv.get(_RULES_STATE_NAMESPACE, fp_key)
    except Exception:
        stored_fp = None  # Safe to re-parse if we can't read the cached state.

    if current_fp and stored_fp == current_fp:
        logger.debug(
            "suricata.plugin: rules_path %r fingerprint unchanged; skipping re-write",
            rules_path_str,
        )
        return

    # ── Parse ───────────────────────────────────────────────────────────────
    try:
        if rules_path.is_dir():
            descs = parse_rules_dir(rules_path)
        elif rules_path.is_file():
            descs = parse_rules_file(rules_path)
        else:
            logger.debug(
                "suricata.plugin: rules_path %r does not exist; skipping rule-desc load",
                rules_path_str,
            )
            return
    except Exception:
        logger.warning(
            "suricata.plugin: failed to parse rules from %r",
            rules_path_str,
            exc_info=True,
        )
        return

    if not descs:
        return

    # ── Write — bail on first cap error; log once (issue #165 A2) ──────────
    # The ScopedKV implementation raises ``SourceKVCapExceededError(RuntimeError)``
    # when the per-namespace row cap is hit.  Plugins must NOT import the core
    # package (the dependency rule), so we identify the exception by class name
    # rather than by a direct isinstance check.
    # RuntimeError is a safe catch-all base because ScopedKV only raises
    # RuntimeError subclasses for cap violations; infrastructure errors (aiosqlite
    # OperationalError, etc.) are OSError/sqlite3.Error, not RuntimeError.
    written = 0
    for sid, msg in descs.items():
        try:
            await ctx.kv.put(_RULE_DESC_NAMESPACE, sid, msg)
            written += 1
        except RuntimeError as exc:
            if type(exc).__name__ == "SourceKVCapExceededError":
                logger.warning(
                    "suricata.plugin: ctx.kv cap exceeded writing rule descriptions"
                    " from %r after %d entries — remaining entries skipped for this"
                    " cycle (issue #165)",
                    rules_path_str,
                    written,
                )
            else:
                logger.warning(
                    "suricata.plugin: unexpected RuntimeError writing rule desc"
                    " sid=%s to ctx.kv",
                    sid,
                    exc_info=True,
                )
            return  # Bail — do NOT store fingerprint; retry next cycle.
        except Exception:
            logger.warning(
                "suricata.plugin: unexpected error writing rule desc sid=%s to ctx.kv",
                sid,
                exc_info=True,
            )
            return  # Treat any unexpected error as a bail, same as cap.

    # ── Persist fingerprint — only on full success ──────────────────────────
    if current_fp:
        try:
            await ctx.kv.put(_RULES_STATE_NAMESPACE, fp_key, current_fp)
        except Exception:
            # Failure to store the fingerprint is non-fatal: the worst outcome
            # is a redundant re-parse on the next cycle.
            logger.debug(
                "suricata.plugin: could not store rules fingerprint in ctx.kv: %s",
                fp_key,
            )

    logger.info(
        "suricata.plugin: wrote %d rule description(s) to ctx.kv from %r",
        written,
        rules_path_str,
    )
