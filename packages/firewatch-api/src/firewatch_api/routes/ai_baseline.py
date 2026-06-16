"""Drift-report read routes (MK-8 / issue #413).

Surfaces the persisted output of ``firewatch ai-baseline --compare`` (MI-9).

Routes
------
GET /ai/baseline
    Return baseline status: exists, model, saved_at, scenario_count.
    Returns ``{"exists": false}`` honestly when no baseline has been saved.

GET /ai/baseline/drift
    Return the latest persisted drift report, or 404 when no comparison has
    been run.  A corrupt or oversized file returns 422.

Route class: C (read-only, ADR-0026).
Pagination: not applicable -- both responses are single objects (the drift
    report may have a ``diffs`` list, but the report itself is one document;
    no cursor pagination needed, ADR-0029 D2 applies to list pages only).

Security
--------
- Files are size-capped and schema-validated before serving (``load_and_validate``
  in ``firewatch_core.ai.baseline.drift_report``).  A corrupt or intentionally
  oversized file returns 422 -- never a raw echo (ADR-0029 D3).
- The baseline file ``{category: verdict_dict}`` is NOT returned by these routes;
  only the structured status DTO and the drift report are exposed.  No attacker-
  controlled raw payload text is included in either response.

File paths
----------
Both routes look for their files at paths injected via ``app.state``:
  - ``app.state.baseline_path``   -- path to ``firewatch_verdict_baseline.json``
  - ``app.state.drift_report_path`` -- path to ``firewatch_drift_report.json``

When these attributes are absent (default for existing ``create_app`` callers),
the routes fall back to the same default filenames the CLI uses, resolved
relative to ``Path.cwd()``.  Tests pass explicit ``Path`` objects via
``create_app(baseline_path=..., drift_report_path=...)``.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Request

logger = logging.getLogger("firewatch.api.ai_baseline")

router = APIRouter(tags=["ai"])

# These defaults match the CLI defaults (firewatch_cli.commands.ai_baseline).
_DEFAULT_BASELINE_FILENAME = "firewatch_verdict_baseline.json"
_DEFAULT_DRIFT_REPORT_FILENAME = "firewatch_drift_report.json"


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------


def _get_baseline_path(request: Request) -> Path:
    """Resolve the baseline file path from app state or the CLI default."""
    path = getattr(request.app.state, "baseline_path", None)
    if path is not None:
        return Path(path)
    return Path.cwd() / _DEFAULT_BASELINE_FILENAME


def _get_drift_report_path(request: Request) -> Path:
    """Resolve the drift report file path from app state or the CLI default."""
    path = getattr(request.app.state, "drift_report_path", None)
    if path is not None:
        return Path(path)
    return Path.cwd() / _DEFAULT_DRIFT_REPORT_FILENAME


# ---------------------------------------------------------------------------
# GET /ai/baseline
# ---------------------------------------------------------------------------


@router.get(
    "/ai/baseline",
    summary="Baseline status",
    response_model=None,
)
async def get_baseline_status(request: Request) -> dict[str, Any]:
    """Return the AI verdict baseline status.

    Response when a baseline exists::

        {
            "exists": true,
            "model": "llama3.2",     // from the first verdict record, best-effort
            "saved_at": null,         // not stored in the baseline file format
            "scenario_count": 8
        }

    Response when no baseline has been saved::

        {"exists": false}

    The baseline file format (``{category: verdict_dict}``) does not carry
    metadata fields such as model or timestamp -- those are stored in the
    drift report, not the baseline.  ``model`` is returned as ``null`` and
    ``saved_at`` as ``null`` when the information is not available.
    """
    baseline_path = _get_baseline_path(request)

    if not baseline_path.exists():
        return {"exists": False}

    try:
        raw = baseline_path.read_bytes()
        data = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        logger.warning("ai/baseline: could not read baseline file %s: %s", baseline_path, exc)
        return {"exists": False}

    if not isinstance(data, dict):
        return {"exists": False}

    # Extract _meta provenance block (may be absent in old baselines — EARS-3).
    meta: dict[str, object] = data.get("_meta") or {}  # type: ignore[assignment]
    model: object = meta.get("model") if isinstance(meta, dict) else None
    saved_at: object = meta.get("saved_at") if isinstance(meta, dict) else None

    # _meta is reserved — exclude it from the scenario count (EARS-5, issue #480).
    scenario_count = sum(1 for k in data if k != "_meta")

    return {
        "exists": True,
        "model": model,
        "saved_at": saved_at,
        "scenario_count": scenario_count,
    }


# ---------------------------------------------------------------------------
# GET /ai/baseline/drift
# ---------------------------------------------------------------------------


@router.get(
    "/ai/baseline/drift",
    summary="Latest drift report",
    response_model=None,
)
async def get_drift_report(request: Request) -> dict[str, Any]:
    """Return the latest persisted drift report.

    Returns the full report dict as produced by
    ``firewatch ai-baseline --compare``.

    Errors
    ------
    404
        No drift comparison has been run yet (file does not exist).
    422
        The report file exists but is corrupt, oversized, or schema-invalid.
        The caller should prompt the operator to re-run ``--compare``.
    """
    from firewatch_core.ai.baseline.drift_report import load_and_validate

    drift_path = _get_drift_report_path(request)

    if not drift_path.exists():
        raise HTTPException(
            status_code=404,
            detail=(
                "No drift comparison has been run yet. "
                "Run: firewatch ai-baseline --compare"
            ),
        )

    try:
        raw = drift_path.read_bytes()
    except OSError as exc:
        logger.error("ai/baseline/drift: could not read report file %s: %s", drift_path, exc)
        raise HTTPException(
            status_code=422,
            detail="Drift report file could not be read; it may be corrupt.",
        ) from exc

    try:
        report = load_and_validate(raw)
    except ValueError as exc:
        logger.warning(
            "ai/baseline/drift: report file %s failed validation: %s", drift_path, exc
        )
        raise HTTPException(
            status_code=422,
            detail=f"Drift report is unreadable: {exc}",
        ) from exc

    return report
