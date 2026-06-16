"""Suricata staged connectivity diagnostics (issues #689, ADR-0034).

Implements the ``run_connectivity_check`` maintenance action as a focused
module — decomposed by concern from ``plugin.py`` and ``collector.py``.

Stages (remote mode):
  1. SSH reachable + auth + host-key  — wraps ``_connect_ssh``; maps
     ``SSHConnectionError`` text verbatim into ``stage_ssh_msg``.
  2. eve.json exists + readable       — reuses ``test -r`` probe from
     the collector; fails with an actionable path-naming message.
  3. recent alert activity            — advisory only; absence is
     ``skip``, never a hard fail (idle sensor is healthy).

Local mode runs equivalent filesystem checks (no SSH):
  stage 1 → pass/N/A; stage 2 → exists + is_file + os.access(R_OK).

Detail-key contract (issue #691 renders these verbatim):
  stage_ssh          = "pass" | "fail"
  stage_ssh_msg      = remediation text or OK text
  stage_evejson      = "pass" | "fail" | "skip"
  stage_evejson_msg  = remediation or "eve.json readable" or skip note
  stage_activity     = "pass" | "skip"
  stage_activity_msg = alert count note or idle note

Dependencies: firewatch-sdk + sibling suricata modules only.
Never imports firewatch-core or legacy/.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from firewatch_sdk import ActionResult

logger = logging.getLogger("firewatch.suricata.diagnostics")

# Status literal values for the detail-key contract.
_PASS = "pass"
_FAIL = "fail"
_SKIP = "skip"


# ---------------------------------------------------------------------------
# Internal value object
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class StageResult:
    """Result of a single diagnostic probe stage.

    Attributes
    ----------
    name:
        Stage identifier, e.g. ``"ssh"``.  Used to build detail keys.
    status:
        One of ``"pass"``, ``"fail"``, or ``"skip"``.
    message:
        Operator-facing single-line description of the outcome.
    """

    name: str
    status: str  # "pass" | "fail" | "skip"
    message: str


# ---------------------------------------------------------------------------
# Public orchestrator
# ---------------------------------------------------------------------------


async def run_connectivity_check(
    cfg: Any,
    ctx: Any,  # PluginContext — typed as Any to avoid circular import
) -> ActionResult:
    """Run the three-stage connectivity probe and return an ``ActionResult``.

    The result's ``detail`` dict carries the six contracted keys
    (``stage_ssh``, ``stage_ssh_msg``, ``stage_evejson``,
    ``stage_evejson_msg``, ``stage_activity``, ``stage_activity_msg``)
    so the UI (issue #691) can render them verbatim without parsing
    the free-text ``message`` field.

    ``ok`` is the AND of the two required stages (SSH, eve.json).
    Stage 3 (activity) is advisory and never fails the probe.

    Never raises — all exceptions are caught and surfaced as a failed
    SSH stage result.
    """
    if getattr(cfg, "mode", "local") == "remote":
        ssh, evejson, activity = await _run_remote_stages(cfg)
    else:
        ssh, evejson, activity = await _run_local_stages(cfg)

    ok = ssh.status == _PASS and evejson.status == _PASS
    message = _build_message(ok, ssh, evejson, activity)

    detail: dict[str, str] = {
        "stage_ssh": ssh.status,
        "stage_ssh_msg": ssh.message,
        "stage_evejson": evejson.status,
        "stage_evejson_msg": evejson.message,
        "stage_activity": activity.status,
        "stage_activity_msg": activity.message,
    }

    return ActionResult(ok=ok, message=message, detail=detail)


# ---------------------------------------------------------------------------
# Remote-mode stage runners
# ---------------------------------------------------------------------------


async def _run_remote_stages(
    cfg: Any,
) -> tuple[StageResult, StageResult, StageResult]:
    """Run all three stages over SSH and return (ssh, evejson, activity)."""
    ssh = await _probe_ssh(cfg)
    if ssh.status != _PASS:
        evejson = StageResult(
            name="evejson",
            status=_SKIP,
            message="Skipped — SSH stage did not pass.",
        )
        activity = StageResult(
            name="activity",
            status=_SKIP,
            message="Skipped — prior required stage failed.",
        )
        return ssh, evejson, activity

    # SSH passed — we have a live connection object; re-open for each probe
    # to keep each probe self-contained and avoid holding one connection
    # across multiple awaits (asyncssh connections are not re-entrant).
    evejson = await _probe_evejson_remote(cfg)
    if evejson.status != _PASS:
        activity = StageResult(
            name="activity",
            status=_SKIP,
            message="Skipped — prior required stage failed.",
        )
        return ssh, evejson, activity

    activity = await _probe_activity_remote(cfg)
    return ssh, evejson, activity


async def _probe_ssh(cfg: Any) -> StageResult:
    """Stage 1 (remote): attempt SSH connect; map SSHConnectionError verbatim.

    Uses ``collector._connect_ssh`` so error mapping is shared — the
    ``SSHConnectionError`` docstring explicitly states its messages are
    shown verbatim in the dashboard's Test Connection result.
    """
    from firewatch_suricata.collector import SSHConnectionError, _connect_ssh

    try:
        conn = await _connect_ssh(cfg)
        # Use async-with so asyncssh closes the connection cleanly regardless
        # of how the connection object implements close() (sync or async).
        async with conn:
            pass
        return StageResult(
            name="ssh",
            status=_PASS,
            message="SSH connection succeeded.",
        )
    except SSHConnectionError as exc:
        return StageResult(
            name="ssh",
            status=_FAIL,
            message=str(exc),
        )
    except Exception as exc:
        logger.debug("_probe_ssh: unexpected error: %s", exc)
        return StageResult(
            name="ssh",
            status=_FAIL,
            message=f"SSH error: {type(exc).__name__}: {exc}",
        )


async def _probe_evejson_remote(cfg: Any) -> StageResult:
    """Stage 2 (remote): open fresh SSH connection and run ``test -r`` on eve.json."""
    from firewatch_suricata.collector import (
        SSHConnectionError,
        _connect_ssh,
        _shell_quote,
    )

    remote_path = getattr(cfg, "remote_path", None) or "/var/log/suricata/eve.json"
    user = getattr(cfg, "remote_user", None) or "the configured user"

    try:
        conn = await _connect_ssh(cfg)
    except SSHConnectionError as exc:
        return StageResult(
            name="evejson",
            status=_FAIL,
            message=str(exc),
        )
    except Exception as exc:
        return StageResult(
            name="evejson",
            status=_FAIL,
            message=f"SSH error during eve.json check: {exc}",
        )

    try:
        async with conn:
            quoted = _shell_quote(remote_path)
            check = await conn.run(
                f"test -r {quoted} && echo OK || echo FAIL",
                check=False,
            )
            stdout = check.stdout or ""
            if "FAIL" in stdout:
                return StageResult(
                    name="evejson",
                    status=_FAIL,
                    message=(
                        f"Cannot read {remote_path}; check the file exists "
                        f"and is readable by {user}."
                    ),
                )
            return StageResult(
                name="evejson",
                status=_PASS,
                message=f"eve.json readable at {remote_path}.",
            )
    except Exception as exc:
        logger.debug("_probe_evejson_remote: error running test -r: %s", exc)
        return StageResult(
            name="evejson",
            status=_FAIL,
            message=f"Error checking eve.json: {exc}",
        )


async def _probe_activity_remote(cfg: Any) -> StageResult:
    """Stage 3 (remote, advisory): check for at least one parseable alert line.

    Uses a bounded ``grep | head -1`` over a tight recent window so the
    probe finishes quickly.  Absence of recent alerts is ``skip`` (healthy
    idle sensor), never ``fail``.
    """
    from firewatch_suricata.collector import (
        SSHConnectionError,
        _connect_ssh,
        _shell_quote,
    )

    remote_path = getattr(cfg, "remote_path", None) or "/var/log/suricata/eve.json"

    try:
        conn = await _connect_ssh(cfg)
    except (SSHConnectionError, Exception) as exc:
        logger.debug("_probe_activity_remote: SSH failed: %s", exc)
        return StageResult(
            name="activity",
            status=_SKIP,
            message="Could not re-connect for activity probe.",
        )

    try:
        async with conn:
            quoted = _shell_quote(remote_path)
            # Grab the first matching alert line — bounded, fast.
            check = await conn.run(
                f"grep '\"event_type\":\"alert\"' {quoted} | head -1",
                check=False,
            )
            line = (check.stdout or "").strip()
            if not line:
                return StageResult(
                    name="activity",
                    status=_SKIP,
                    message=(
                        "No recent alert lines found "
                        "(sensor may be idle — this is not an error)."
                    ),
                )
            # Attempt to parse to confirm it is valid JSON.
            try:
                json.loads(line)
                return StageResult(
                    name="activity",
                    status=_PASS,
                    message="At least 1 parseable alert line found.",
                )
            except json.JSONDecodeError:
                return StageResult(
                    name="activity",
                    status=_SKIP,
                    message="Alert line found but not valid JSON (sensor may be idle).",
                )
    except Exception as exc:
        logger.debug("_probe_activity_remote: error: %s", exc)
        return StageResult(
            name="activity",
            status=_SKIP,
            message="Activity probe could not complete.",
        )


# ---------------------------------------------------------------------------
# Local-mode stage runners
# ---------------------------------------------------------------------------


async def _run_local_stages(
    cfg: Any,
) -> tuple[StageResult, StageResult, StageResult]:
    """Run all three stages against the local filesystem."""
    ssh = StageResult(
        name="ssh",
        status=_PASS,
        message="Local mode — SSH not used.",
    )
    evejson = _probe_evejson_local(cfg)
    if evejson.status != _PASS:
        activity = StageResult(
            name="activity",
            status=_SKIP,
            message="Skipped — eve.json stage did not pass.",
        )
        return ssh, evejson, activity

    activity = _probe_activity_local(cfg)
    return ssh, evejson, activity


def _probe_evejson_local(cfg: Any) -> StageResult:
    """Stage 2 (local): check path exists, is_file, and is readable (os.access R_OK)."""
    local_path_str = (getattr(cfg, "local_path", None) or "").strip()
    if not local_path_str:
        return StageResult(
            name="evejson",
            status=_FAIL,
            message="local_path is not configured.",
        )

    path = Path(local_path_str)
    if not path.exists():
        return StageResult(
            name="evejson",
            status=_FAIL,
            message=f"Path does not exist: {local_path_str}",
        )
    if not path.is_file():
        return StageResult(
            name="evejson",
            status=_FAIL,
            message=f"Path is not a regular file: {local_path_str}",
        )
    if not os.access(path, os.R_OK):
        return StageResult(
            name="evejson",
            status=_FAIL,
            message=(
                f"File is not readable: {local_path_str}. "
                "Check file permissions (chmod a+r or run as the correct user)."
            ),
        )
    return StageResult(
        name="evejson",
        status=_PASS,
        message=f"eve.json readable at {local_path_str}.",
    )


def _probe_activity_local(cfg: Any) -> StageResult:
    """Stage 3 (local, advisory): check for at least one parseable alert line."""
    local_path_str = (getattr(cfg, "local_path", None) or "").strip()
    if not local_path_str:
        return StageResult(
            name="activity",
            status=_SKIP,
            message="No local_path configured.",
        )

    path = Path(local_path_str)
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    if data.get("event_type") == "alert":
                        return StageResult(
                            name="activity",
                            status=_PASS,
                            message="At least 1 parseable alert line found.",
                        )
                except json.JSONDecodeError:
                    continue
    except Exception as exc:
        logger.debug("_probe_activity_local: read error: %s", exc)
        return StageResult(
            name="activity",
            status=_SKIP,
            message="Could not read file for activity probe.",
        )

    return StageResult(
        name="activity",
        status=_SKIP,
        message=(
            "No recent alert lines found "
            "(sensor may be idle — this is not an error)."
        ),
    )


# ---------------------------------------------------------------------------
# Message builder
# ---------------------------------------------------------------------------


def _build_message(
    ok: bool,
    ssh: StageResult,
    evejson: StageResult,
    activity: StageResult,
) -> str:
    """Build the one-line top-level message for the ActionResult.

    On failure: headline + first failing stage's actionable remediation.
    On success: concise OK summary including activity note.
    """
    if not ok:
        # Surface the first failing stage's remediation text.
        for stage in (ssh, evejson):
            if stage.status == _FAIL:
                return f"Connectivity check failed ({stage.name}): {stage.message}"
        return "Connectivity check failed."

    # All required stages passed.
    activity_note = (
        f" {activity.message}"
        if activity.status == _PASS
        else " (sensor may be idle)"
    )
    return f"Reachable; eve.json readable.{activity_note}"
