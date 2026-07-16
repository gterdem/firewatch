"""ClamAVSource — local malware-detection PullSource plugin.

Registered as ``clamav`` under the ``firewatch.sources`` entry-point group. Adding this
package to the workspace requires zero edits to firewatch-core (PLUGIN_CONTRACT.md
modularity guarantee).

This module implements:
  - ``SourcePlugin`` (metadata, config_schema, validate_config, normalize, health_check)
  - ``PullSource`` (collect)

It depends on ``firewatch-sdk`` ONLY. Never imports firewatch-core or legacy/.

Local-first (ADR-0065 §1): collects from the machine FireWatch runs on, with zero
network configuration, via the SDK's journald reader (default) or file-tail reader (the
non-systemd fallback) — see ``firewatch_clamav.collector``.

Normalization (ADR-0012, ADR-0014, ADR-0020, ADR-0067 D4, ADR-0069):
  - ``source_type`` is the constant ``"clamav"`` — never branches on ``source_id``.
  - ``action=ALERT`` for detect-only; ``action=BLOCK`` when a companion remove/quarantine
    outcome is observed in the log stream.
  - ``severity="high"`` always — malware on disk is a genuine, load-bearing assertion.
  - MITRE/CAPEC left unset — ClamAV signature names carry no such metadata to derive from.

**Reality check (issue #2 acceptance criteria):** ClamAV only detects *when it scans*.
Instant detection requires on-access scanning (``clamonacc``); a plain ``clamscan`` /
`LogFile`-only setup only reports what it's told to scan. This is a setup/wizard concern
(M2.6), not something this plugin's code can change — see the package README.
"""
from __future__ import annotations

import os
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from firewatch_sdk import PluginContext, RawEvent, SecurityEvent, SourceMetadata
from firewatch_sdk.localhost import JournaldReader, LocalReaderError

from firewatch_clamav import collector as _collector
from firewatch_clamav import normalize as _normalize
from firewatch_clamav.config import ClamAVConfig

_VERSION = "0.1.0"

# The canonical type key for this source. Must match the entry-point name and the regex
# ^[a-z][a-z0-9_]*$ (PLUGIN_CONTRACT.md SourceMetadata type_key constraint).
_TYPE_KEY = "clamav"


class ClamAVSource:
    """ClamAV malware-detection source plugin.

    Implements ``SourcePlugin`` + ``PullSource`` from firewatch-sdk.

    Two collection modes (ADR-0065 §3):
      - ``journald`` (default): reads detections from the systemd journal.
      - ``file``: tails ClamAV's plain-text log file (non-systemd fallback).
    """

    # ── SourcePlugin methods ─────────────────────────────────────────────────

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            type_key=_TYPE_KEY,
            display_name="ClamAV Antivirus",
            version=_VERSION,
            flavor="pull",
            # ADR-0060: canonical SecurityEvent fields this source populates. ClamAV is a
            # host-based detector — no network/HTTP/DNS/TLS fields, and no real source_ip
            # (always ""), so both are deliberately OMITTED here (never declared just
            # because the field exists on every event).
            produces=frozenset({
                "action", "category", "severity",
                "rule_id", "rule_name",
                "payload_snippet",
                "file_name",
                "ocsf_class", "ocsf_category",
                "raw_log",
            }),
        )

    def config_schema(self) -> type[BaseModel]:
        """Return the Pydantic model that drives the rjsf UI source card.

        The returned class emits JSON Schema with ``if/then/else`` for the
        journald/file mode toggle (ADR-0019). Config resolution respects env > file >
        default (ADR-0006); use ``build_config()`` at runtime to construct the instance.
        """
        return ClamAVConfig

    def validate_config(self, cfg: dict[str, Any]) -> None:
        """Validate a raw config dict against the ClamAV config schema.

        Raises ``pydantic.ValidationError`` if the config is invalid.
        """
        ClamAVConfig.model_validate(cfg)

    def normalize(self, raw: RawEvent, source_id: str) -> SecurityEvent:
        """Map a ClamAV FOUND-detection RawEvent to a SecurityEvent.

        ``source_type`` is always ``"clamav"`` (this plugin's constant). ``source_id`` is
        the caller's instance name, passed through as-is. This method MUST NOT branch on
        ``source_id`` (Flag B, PLUGIN_CONTRACT.md).
        """
        return _normalize.normalize(raw, source_id)

    async def health_check(self, cfg: BaseModel) -> bool:
        """Return True if the configured source is reachable/readable.

        Journald mode: probes the journal directly (mirrors
        ``firewatch_suricata``'s remote SSH probe pattern) — a live, typed-error-guarded
        check rather than just checking that ``journalctl`` is on PATH, since a present
        binary with no journal access would otherwise falsely report healthy.
        File mode: checks that ``log_path`` exists, is a regular file, AND is readable by
        the current process (mirrors ``firewatch_suricata``'s local-mode check).

        Returns False (never raises) on any failure.
        """
        try:
            clamav_cfg = (
                cfg
                if isinstance(cfg, ClamAVConfig)
                else ClamAVConfig.model_validate(cfg.model_dump())
            )
        except Exception:
            return False

        if clamav_cfg.mode == "file":
            path = Path(clamav_cfg.log_path)
            return path.exists() and path.is_file() and os.access(path, os.R_OK)

        try:
            reader = JournaldReader(identifiers=tuple(clamav_cfg.identifiers))
            await reader.resolve_start("tail")
            return True
        except LocalReaderError:
            return False
        except Exception:
            return False

    # ── PullSource method ────────────────────────────────────────────────────

    async def collect(
        self, cfg: BaseModel, since: str | None, ctx: PluginContext
    ) -> AsyncIterator[RawEvent]:
        """Yield ``RawEvent``s for ClamAV FOUND detections.

        ``ctx`` is the per-instance capability carrier (ADR-0027); ``ctx.kv`` persists
        the reader cursor (ADR-0065 §3 — see ``firewatch_clamav.collector``).
        """
        clamav_cfg = (
            cfg
            if isinstance(cfg, ClamAVConfig)
            else ClamAVConfig.model_validate(cfg.model_dump())
        )
        async for raw in _collector.collect(clamav_cfg, since, ctx):
            yield raw
