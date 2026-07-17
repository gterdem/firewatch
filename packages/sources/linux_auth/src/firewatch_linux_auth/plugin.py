"""LinuxAuthSource — the FireWatch Linux auth & intrusion signals source plugin.

Registered as ``linux_auth`` under the ``firewatch.sources`` entry-point group.
Adding this package to the workspace requires zero edits to firewatch-core
(PLUGIN_CONTRACT.md modularity guarantee).

This module implements:
  - ``SourcePlugin`` (metadata, config_schema, validate_config, normalize, health_check)
  - ``PullSource`` (collect)

It depends on ``firewatch-sdk`` ONLY. Never imports firewatch-core or legacy/.

Local mode only (M1, issue #3): journald-first (ADR-0065), file-tail fallback.
Push mode (fleet forwarding) is out of scope for this issue — M2.1.
"""
from __future__ import annotations

import logging
import os
import shutil
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from firewatch_sdk import PluginContext, RawEvent, SecurityEvent, SourceMetadata

from firewatch_linux_auth import collector as _collector
from firewatch_linux_auth import normalize as _normalize
from firewatch_linux_auth.config import LinuxAuthConfig

logger = logging.getLogger("firewatch.linux_auth.plugin")

_VERSION = "0.1.0"
_TYPE_KEY = "linux_auth"


class LinuxAuthSource:
    """Linux auth & intrusion signals source plugin.

    Implements ``SourcePlugin`` + ``PullSource`` from firewatch-sdk.

    Reads this machine's own authentication logs — sshd, sudo,
    useradd/usermod/groupadd/userdel, and generic PAM (``pam_unix``)
    authentication failures — with zero network configuration (ADR-0065 §1).

    Normalization (ADR-0012, ADR-0014, ADR-0016, ADR-0020, ADR-0067):
      - ``source_type`` is the constant ``"linux_auth"`` — never branches on
        ``source_id``.
      - ``action``/``severity`` per category (ALERT for the three failure
        categories, LOG for success/account-creation/unclassified) — see
        ``firewatch_linux_auth.normalize``'s module docstring for the full
        table and its ADR-0070 D1 / ADR-0069 D4(e) justification; not
        restated here to avoid the two docstrings drifting apart. Escalation
        past a single low/medium severity is always a core correlation-rule
        decision (ADR-0067 D1/RC5), never a per-event action/severity bump.
      - Distinct rule identities for SSH login failure/success, sudo
        authentication failure, generic PAM authentication failure, and new
        user account creation (T1110, T1548.003, T1136 — ADR-0014).
    """

    # ── SourcePlugin methods ─────────────────────────────────────────────────

    def metadata(self) -> SourceMetadata:
        return SourceMetadata(
            type_key=_TYPE_KEY,
            display_name="Linux Auth & Intrusion Signals",
            version=_VERSION,
            flavor="pull",
            # ADR-0067 D6 (issue #75): declared enforcement-posture default. This
            # source reads journald/auth.log — a passive telemetry collector that
            # cannot block a login attempt it observes.
            enforcement="observe",
        )

    def config_schema(self) -> type[BaseModel]:
        """Return the Pydantic model that drives the rjsf UI source card.

        Fields: mode (auto|journald|file), auth_log_path, journalctl_bin.
        Config resolution respects env > file > default (ADR-0006); use
        ``build_config()`` at runtime to construct the instance.
        """
        return LinuxAuthConfig

    def validate_config(self, cfg: dict[str, Any]) -> None:
        """Validate a raw config dict against the Linux auth config schema.

        Raises ``pydantic.ValidationError`` if the config is invalid.
        """
        LinuxAuthConfig.model_validate(cfg)

    def normalize(self, raw: RawEvent, source_id: str) -> SecurityEvent:
        """Map a Linux auth RawEvent to a SecurityEvent.

        ``source_type`` is always ``"linux_auth"`` (this plugin's constant).
        ``source_id`` is the caller's instance name, passed through as-is.
        This method MUST NOT branch on ``source_id`` (Flag B, PLUGIN_CONTRACT.md).
        """
        return _normalize.normalize(raw, source_id)

    async def health_check(self, cfg: BaseModel) -> bool:
        """Return True if the configured collection mode can plausibly run.

        - ``"journald"``: True iff ``journalctl_bin`` resolves on PATH.
        - ``"file"``: True iff ``auth_log_path`` exists, is a regular file,
          and is readable by this process.
        - ``"auto"``: True iff EITHER check above passes (mirrors the
          collector's own journald-first-with-fallback behaviour).

        Returns False (never raises) on any failure.
        """
        try:
            auth_cfg = (
                cfg
                if isinstance(cfg, LinuxAuthConfig)
                else LinuxAuthConfig.model_validate(cfg.model_dump())
            )
        except Exception:
            return False

        journald_ok = shutil.which(auth_cfg.journalctl_bin) is not None
        if auth_cfg.mode == "journald":
            return journald_ok

        file_ok = _auth_log_readable(auth_cfg.auth_log_path)
        if auth_cfg.mode == "file":
            return file_ok

        return journald_ok or file_ok

    # ── PullSource method ────────────────────────────────────────────────────

    async def collect(
        self, cfg: BaseModel, since: str | None, ctx: PluginContext
    ) -> AsyncIterator[RawEvent]:
        """Yield ``RawEvent``s for new auth-log lines.

        Resume is cursor-based via ``ctx.kv`` (ADR-0025/0027/0065) — ``since``
        is accepted (the PullSource protocol requires it) but unused; see
        ``collector.py``'s module docstring.
        """
        auth_cfg = (
            cfg
            if isinstance(cfg, LinuxAuthConfig)
            else LinuxAuthConfig.model_validate(cfg.model_dump())
        )
        async for raw in _collector.collect(auth_cfg, since, ctx):
            yield raw


def _auth_log_readable(path_str: str) -> bool:
    try:
        path = Path(path_str)
        return path.exists() and path.is_file() and os.access(path, os.R_OK)
    except OSError:
        return False
