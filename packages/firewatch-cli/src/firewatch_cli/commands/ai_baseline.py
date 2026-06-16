"""``firewatch ai-baseline`` -- operator verdict-drift CLI (MI-9 / issue #390).

Lets an operator detect when their LOCAL model's verdicts drift compared to
a previously recorded baseline -- making the "regression-tested AI" claim
concretely true for operator-controlled model + runtime combos.

This is DISTINCT from the CI prompt-baseline oracle (tests/golden/ai/):
  - The prompt-baseline oracle pins PROMPT TEXT (fast, no model needed, runs in CI).
  - This command pins VERDICTS (slow, requires the live engine, operator-run only).

Modes
-----
``--save [--out <path>]``
    Run every canonical scenario through the configured engine, record each
    scenario's verdict (threat_level / recommended_action / attack_stage /
    confidence + full engine output) to a JSON baseline file.

``--compare [--baseline <path>] [--report-out <path>]``
    Re-run the scenarios, diff verdicts against the saved baseline, print a
    human-readable drift report, and exit non-zero if any verdict drifted.
    When ``--report-out`` is set (or the default data-dir path is resolvable),
    additionally persists a machine-readable JSON drift report alongside the
    baseline file so the read API (GET /ai/baseline/drift) can surface it.
    Safe for scripting (the exit code is the gate).

ai-engine-invariants boundary
------------------------------
- Does NOT modify prompts, scoring, sample-building, or engine selection.
- Does NOT auto-rebaseline -- saving is a deliberate human act.
- Does NOT commit a vendor-provided baseline (verdicts are model-dependent).
- Does NOT run in CI (no live-model CI dependency).
- Network only to the validated local AI endpoint (ADR-0022).
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("firewatch.cli.ai_baseline")

# Default paths (operator-chosen; not committed to the repo)
DEFAULT_BASELINE_FILENAME = "firewatch_verdict_baseline.json"
DEFAULT_DRIFT_REPORT_FILENAME = "firewatch_drift_report.json"


async def cmd_ai_baseline(
    mode: str,
    engine: Any,
    out_path: Path | None,
    baseline_path: Path | None,
    report_out: Path | None = None,
) -> int:
    """Run the ai-baseline command.

    Parameters
    ----------
    mode:
        ``"save"`` or ``"compare"``.
    engine:
        An AIEngine-protocol object (already constructed with the configured
        base_url and model -- caller owns construction).
    out_path:
        Where to write the baseline file (``--save`` mode).
        Defaults to ``DEFAULT_BASELINE_FILENAME`` in the current directory.
    baseline_path:
        Baseline file to compare against (``--compare`` mode).
        Defaults to ``DEFAULT_BASELINE_FILENAME`` in the current directory.
    report_out:
        Where to write the machine-readable drift report JSON (``--compare`` mode
        only).  Defaults to ``DEFAULT_DRIFT_REPORT_FILENAME`` alongside the
        baseline file.  Pass an explicit path to override.  Persistence failures
        are logged but do NOT alter the exit code.

    Returns
    -------
    int
        Exit code: 0 on success / no drift; non-zero on error or drift.
    """
    from firewatch_core.ai.baseline.report import compare_verdicts, render_report
    from firewatch_core.ai.baseline.runner import BaselineRunError, run_all_scenarios

    if mode == "save":
        return await _cmd_save(
            engine=engine,
            out_path=out_path or Path(DEFAULT_BASELINE_FILENAME),
            run_all=run_all_scenarios,
        )
    elif mode == "compare":
        resolved_baseline = baseline_path or Path(DEFAULT_BASELINE_FILENAME)
        resolved_report_out = report_out or (
            resolved_baseline.parent / DEFAULT_DRIFT_REPORT_FILENAME
        )
        return await _cmd_compare(
            engine=engine,
            baseline_path=resolved_baseline,
            report_out=resolved_report_out,
            run_all=run_all_scenarios,
            compare=compare_verdicts,
            render=render_report,
            run_error_cls=BaselineRunError,
        )
    else:
        print(f"Error: unknown mode {mode!r}; expected 'save' or 'compare'.", file=sys.stderr)
        return 1


# ---------------------------------------------------------------------------
# Save implementation
# ---------------------------------------------------------------------------


async def _cmd_save(
    engine: Any,
    out_path: Path,
    run_all: Any,
) -> int:
    """Run scenarios, write verdicts to *out_path*.  Returns exit code."""
    from firewatch_core.ai.baseline.runner import BaselineRunError

    print(f"firewatch ai-baseline --save -> {out_path}")
    try:
        results = await run_all(engine)
    except BaselineRunError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        logger.error("ai-baseline save failed: %s", exc)
        return 1

    meta = {
        "model": getattr(engine, "model", "unknown"),
        "saved_at": datetime.now(timezone.utc).isoformat(),
    }
    payload: dict[str, Any] = {"_meta": meta, **results}

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print(f"Saved {len(results)} scenario verdict(s) to: {out_path}")
    print()
    print("Re-record whenever you intentionally change the model or runtime:")
    print(f"  firewatch ai-baseline --save --out {out_path}")
    return 0


# ---------------------------------------------------------------------------
# Compare implementation
# ---------------------------------------------------------------------------


async def _cmd_compare(
    engine: Any,
    baseline_path: Path,
    report_out: Path,
    run_all: Any,
    compare: Any,
    render: Any,
    run_error_cls: type[Exception],
) -> int:
    """Re-run scenarios, compare against *baseline_path*.  Returns exit code.

    Additionally persists a machine-readable drift report to *report_out*
    (fail-safe: persistence failure is logged but does not change the exit code).
    """
    print(f"firewatch ai-baseline --compare (baseline: {baseline_path})")

    if not baseline_path.exists():
        print(
            f"Error: baseline file not found: {baseline_path}\n"
            "Run with --save first to record a verdict baseline.",
            file=sys.stderr,
        )
        return 1

    try:
        saved = json.loads(baseline_path.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"Error: could not read baseline file: {exc}", file=sys.stderr)
        return 1

    try:
        current = await run_all(engine)
    except run_error_cls as exc:
        print(f"Error: {exc}", file=sys.stderr)
        logger.error("ai-baseline compare run failed: %s", exc)
        return 1

    drifts = compare(saved, current)
    report_text = render(drifts, total=len(current))
    print(report_text)

    # Persist machine-readable drift report (fail-safe -- never alters exit code).
    _persist_drift_report(
        drifts=drifts,
        baseline_verdicts=saved,
        candidate_verdicts=current,
        engine=engine,
        report_out=report_out,
    )

    if drifts:
        return 1
    return 0


def _persist_drift_report(
    drifts: list[Any],
    baseline_verdicts: dict[str, Any],
    candidate_verdicts: dict[str, Any],
    engine: Any,
    report_out: Path,
) -> None:
    """Write machine-readable drift report to *report_out* (fail-safe).

    Any exception is logged and silently swallowed -- the CLI exit code
    is determined solely by drift detection, not by report persistence.
    """
    from firewatch_core.ai.baseline.drift_report import build_drift_report

    try:
        candidate_model: str = getattr(engine, "model", "unknown")
        # EARS-4: use _meta.model as the authoritative baseline model id when present.
        meta = baseline_verdicts.get("_meta")
        baseline_model: str = (
            meta.get("model", candidate_model)  # type: ignore[union-attr]
            if isinstance(meta, dict)
            else candidate_model
        )
        report = build_drift_report(
            drifts=drifts,
            baseline_verdicts=baseline_verdicts,
            candidate_verdicts=candidate_verdicts,
            baseline_model=baseline_model,
            candidate_model=candidate_model,
        )
        report_out.parent.mkdir(parents=True, exist_ok=True)
        report_out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"Drift report written to: {report_out}")
    except Exception as exc:
        logger.warning("ai-baseline: could not write drift report to %s: %s", report_out, exc)
