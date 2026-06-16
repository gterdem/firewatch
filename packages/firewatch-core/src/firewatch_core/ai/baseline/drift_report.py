"""Drift-report serializer — machine-readable shape for ``--compare`` output.

Shared by the CLI (writes the file) and the API (reads + validates it).
Pure functions only — no I/O, no async.  Callers own file access.

Shape (one file per ``--compare`` run, latest wins at ``drift_report.json``)
---------------------------------------------------------------------------
.. code-block:: json

    {
        "baseline_model":   "llama3.2",
        "candidate_model":  "qwen3:14b",
        "run_at":           "2026-06-12T14:00:00+00:00",
        "scenarios":        8,
        "changed":          2,
        "escalations":      1,
        "deescalations":    1,
        "diffs": [
            {
                "scenario":             "concise_waf_no_corr",
                "baseline_verdict":     "HIGH",
                "candidate_verdict":    "CRITICAL",
                "baseline_confidence":  0.85,
                "candidate_confidence": 0.9,
                "baseline_summary":     "block",
                "candidate_summary":    "block"
            }
        ]
    }

Field semantics
---------------
- ``baseline_model`` / ``candidate_model``  — model IDs (strings; may be equal).
- ``run_at``  — ISO-8601 UTC timestamp of this comparison run.
- ``scenarios``  — total number of scenarios evaluated.
- ``changed``  — count of scenarios where any drift field differed.
- ``escalations``  — changed scenarios where ``threat_level`` moved to a higher
  severity (e.g. MEDIUM -> HIGH).  Informational; does not gate the exit code.
- ``deescalations``  — changed scenarios where ``threat_level`` moved lower.
- ``diffs``  — one entry per changed scenario (empty list when no drift).

Size cap
--------
``MAX_REPORT_BYTES`` caps the file the API will read.  Files larger than this
are rejected with a 422 (corrupt/oversized) rather than loaded.  The cap is
intentionally generous (1 MiB) -- a realistic report is a few KiB; this only
guards against a corrupted or hand-crafted oversized file.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from firewatch_core.ai.baseline.report import VerdictDrift

# Maximum bytes the API will read from a drift report file.
MAX_REPORT_BYTES: int = 1 * 1024 * 1024  # 1 MiB

# Severity ordering for escalation/de-escalation detection.
_SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "UNKNOWN": 0,
}


# ---------------------------------------------------------------------------
# Required top-level keys for schema validation
# ---------------------------------------------------------------------------

_REQUIRED_KEYS: frozenset[str] = frozenset({
    "baseline_model",
    "candidate_model",
    "run_at",
    "scenarios",
    "changed",
    "escalations",
    "deescalations",
    "diffs",
})


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def build_drift_report(
    drifts: list[VerdictDrift],
    baseline_verdicts: dict[str, dict[str, Any]],
    candidate_verdicts: dict[str, dict[str, Any]],
    baseline_model: str,
    candidate_model: str,
) -> dict[str, Any]:
    """Build the machine-readable drift report dict.

    Parameters
    ----------
    drifts:
        Output of ``compare_verdicts`` -- one entry per changed scenario.
    baseline_verdicts:
        Saved baseline dict ``{category: verdict}``.
    candidate_verdicts:
        Freshly-run verdicts ``{category: verdict}``.
    baseline_model:
        Model ID used to produce the baseline (from the baseline file or config).
    candidate_model:
        Model ID used for the candidate run (current config).

    Returns
    -------
    dict[str, Any]
        The serialisable report dict.  Caller owns JSON serialisation and I/O.
    """
    run_at = datetime.now(tz=timezone.utc).isoformat()
    # Exclude the reserved "_meta" key from scenario counts (issue #480).
    baseline_count = sum(1 for k in baseline_verdicts if k != "_meta")
    candidate_count = sum(1 for k in candidate_verdicts if k != "_meta")
    total = max(baseline_count, candidate_count)

    escalations = 0
    deescalations = 0
    diffs: list[dict[str, Any]] = []

    for drift in drifts:
        saved_v = drift.saved
        current_v = drift.current

        baseline_threat = saved_v.get("threat_level", "UNKNOWN")
        candidate_threat = current_v.get("threat_level", "UNKNOWN")

        saved_rank = _SEVERITY_ORDER.get(str(baseline_threat).upper(), 0)
        current_rank = _SEVERITY_ORDER.get(str(candidate_threat).upper(), 0)
        if current_rank > saved_rank:
            escalations += 1
        elif current_rank < saved_rank:
            deescalations += 1

        diffs.append({
            "scenario": drift.category,
            "baseline_verdict": baseline_threat,
            "candidate_verdict": candidate_threat,
            "baseline_confidence": saved_v.get("confidence", 0.0),
            "candidate_confidence": current_v.get("confidence", 0.0),
            "baseline_summary": saved_v.get("recommended_action", "unknown"),
            "candidate_summary": current_v.get("recommended_action", "unknown"),
        })

    return {
        "baseline_model": baseline_model,
        "candidate_model": candidate_model,
        "run_at": run_at,
        "scenarios": total,
        "changed": len(drifts),
        "escalations": escalations,
        "deescalations": deescalations,
        "diffs": diffs,
    }


def validate_report(data: dict[str, Any]) -> None:
    """Validate that *data* has all required top-level keys and sane types.

    Raises
    ------
    ValueError
        If any required key is missing or has an unexpected type.
    """
    missing = _REQUIRED_KEYS - set(data.keys())
    if missing:
        raise ValueError(f"Drift report missing required keys: {sorted(missing)}")

    if not isinstance(data.get("diffs"), list):
        raise ValueError("Drift report 'diffs' must be a list")

    if not isinstance(data.get("scenarios"), int):
        raise ValueError("Drift report 'scenarios' must be an integer")

    if not isinstance(data.get("changed"), int):
        raise ValueError("Drift report 'changed' must be an integer")


def load_and_validate(raw_bytes: bytes) -> dict[str, Any]:
    """Deserialise and schema-validate *raw_bytes* as a drift report.

    Parameters
    ----------
    raw_bytes:
        Raw file contents (UTF-8 encoded JSON).

    Returns
    -------
    dict[str, Any]
        Validated report dict.

    Raises
    ------
    ValueError
        If the bytes are not valid JSON, exceed ``MAX_REPORT_BYTES``, or fail
        schema validation.
    """
    if len(raw_bytes) > MAX_REPORT_BYTES:
        raise ValueError(
            f"Drift report file exceeds size cap ({MAX_REPORT_BYTES} bytes); "
            "file may be corrupt or intentionally oversized."
        )

    try:
        data = json.loads(raw_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"Drift report is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("Drift report must be a JSON object at the top level")

    validate_report(data)
    return data
