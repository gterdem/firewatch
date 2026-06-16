"""AI verdict-baseline report — pure diff comparison and human-readable rendering.

Pure functions only — no I/O, no async, no engine calls.  The caller (CLI or
test) owns printing and exit-code logic.

Drift definition
----------------
A verdict has drifted when any of the key comparison fields differ between the
saved baseline and the current run:
  - ``threat_level`` (CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN)
  - ``recommended_action`` (block / investigate / monitor / ignore)
  - ``attack_stage`` (reconnaissance / exploitation / brute_force / ...)

``confidence`` is reported in the output but is NOT included in the drift
check — floating-point values vary too much run-to-run to be a reliable
signal, and fine-grained confidence jitter is expected model behaviour.

This deliberate choice keeps the drift signal meaningful: operators see
actionable changes (the recommendation flipped, the severity changed) rather
than noise (confidence moved from 0.85 to 0.87).
"""
from __future__ import annotations

from typing import Any

# Fields that define a meaningful verdict drift.
_DRIFT_FIELDS = ("threat_level", "recommended_action", "attack_stage")


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


class VerdictDrift:
    """One drifted verdict — a single scenario where the verdict changed.

    Attributes
    ----------
    category:
        Scenario name (e.g. ``"concise_waf_no_corr"``).
    field_drifts:
        List of ``(field_name, saved_value, current_value)`` tuples for
        every field that changed.
    saved:
        Full saved verdict dict.
    current:
        Full current verdict dict.
    """

    def __init__(
        self,
        category: str,
        field_drifts: list[tuple[str, Any, Any]],
        saved: dict[str, Any],
        current: dict[str, Any],
    ) -> None:
        self.category = category
        self.field_drifts = field_drifts
        self.saved = saved
        self.current = current

    def __repr__(self) -> str:
        fields = ", ".join(f"{f}:{s!r}->{c!r}" for f, s, c in self.field_drifts)
        return f"VerdictDrift(category={self.category!r}, drifts=[{fields}])"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def compare_verdicts(
    saved: dict[str, dict[str, Any]],
    current: dict[str, dict[str, Any]],
) -> list[VerdictDrift]:
    """Diff *current* verdicts against *saved* baseline.

    Parameters
    ----------
    saved:
        Loaded baseline — ``{category: verdict_dict}``.
    current:
        Freshly-run verdicts — ``{category: verdict_dict}``.

    Returns
    -------
    list[VerdictDrift]
        One entry per scenario that drifted.  Empty list means no drift.

    Notes
    -----
    - Scenarios present in *saved* but missing from *current* are reported
      as drift (threat_level "UNKNOWN" vs. saved value).
    - Scenarios present in *current* but not in *saved* are reported as
      drift (saved "UNKNOWN" vs. current value).
    """
    drifts: list[VerdictDrift] = []

    # "_meta" is reserved provenance metadata — skip it in both dicts so it is
    # never treated as a verdict category (EARS-3 backward compat, issue #480).
    all_categories = sorted((set(saved) | set(current)) - {"_meta"})
    for category in all_categories:
        saved_v = saved.get(category, {})
        current_v = current.get(category, {})
        field_drifts = _diff_verdict(saved_v, current_v)
        if field_drifts:
            drifts.append(
                VerdictDrift(
                    category=category,
                    field_drifts=field_drifts,
                    saved=saved_v,
                    current=current_v,
                )
            )

    return drifts


def render_report(drifts: list[VerdictDrift], total: int) -> str:
    """Render a human-readable drift report.

    Parameters
    ----------
    drifts:
        List of drifted verdicts from ``compare_verdicts``.
    total:
        Total number of scenarios run (for the summary line).

    Returns
    -------
    str
        Multi-line human-readable report.  The caller prints it.
    """
    lines: list[str] = []
    lines.append(f"firewatch ai-baseline compare — {total} scenario(s)")
    lines.append("-" * 60)

    if not drifts:
        lines.append(f"No drift detected — all {total} scenario(s) OK.")
        return "\n".join(lines)

    lines.append(
        f"DRIFT DETECTED: {len(drifts)} of {total} scenario(s) changed verdict."
    )
    lines.append("")

    for d in drifts:
        lines.append(f"  DRIFT  {d.category}")
        for field, saved_val, current_val in d.field_drifts:
            lines.append(f"    {field}: {saved_val!r} -> {current_val!r}")

    lines.append("")
    lines.append(
        f"Summary: {len(drifts)} drift(s) in {total} scenario(s). "
        f"Re-record the baseline with: firewatch ai-baseline --save"
    )

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _diff_verdict(
    saved: dict[str, Any],
    current: dict[str, Any],
) -> list[tuple[str, Any, Any]]:
    """Return a list of (field, saved_value, current_value) for drifted fields."""
    diffs: list[tuple[str, Any, Any]] = []
    for field in _DRIFT_FIELDS:
        saved_val = saved.get(field, "UNKNOWN")
        current_val = current.get(field, "UNKNOWN")
        if saved_val != current_val:
            diffs.append((field, saved_val, current_val))
    return diffs
