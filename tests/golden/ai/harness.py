"""AI prompt-baseline harness.

Usage
-----
    python -m tests.golden.ai.harness --save      # capture current prompts as baselines
    python -m tests.golden.ai.harness --compare   # fail if any prompt diverged

The harness is a thin CLI wrapper around the scenario registry in ``fixtures.py``.
It makes NO network calls — it only calls the pure ``format_concise`` /
``format_detailed`` functions from ``firewatch_core.ai.prompts``.

Design
------
Baseline files live at  ``tests/golden/ai/baselines/<category>.txt``.
Each ``SCENARIOS`` entry maps to exactly one file; adding a new scenario appends
one dict to ``fixtures.SCENARIOS`` — zero harness-code changes required.
"""
from __future__ import annotations

import sys
from pathlib import Path

from firewatch_core.ai.prompts import format_concise, format_detailed

from golden.ai.fixtures import SCENARIOS

BASELINES_DIR = Path(__file__).parent / "baselines"

_FORMAT_FN = {
    "concise": format_concise,
    "detailed": format_detailed,
}


def _generate(scenario: dict) -> str:
    """Return the generated prompt for *scenario* (no network, ~microseconds)."""
    fn = _FORMAT_FN[scenario["format"]]
    return fn(**scenario["kwargs"])


def save_all() -> None:
    """Generate prompts for every scenario and write them to the baselines dir."""
    BASELINES_DIR.mkdir(parents=True, exist_ok=True)
    for sc in SCENARIOS:
        text = _generate(sc)
        path = BASELINES_DIR / f"{sc['category']}.txt"
        path.write_text(text, encoding="utf-8")
        print(f"  saved  {path.relative_to(Path(__file__).parent.parent.parent.parent)}")
    print(f"\n{len(SCENARIOS)} baseline(s) saved to {BASELINES_DIR}/")


def compare_all() -> bool:
    """Regenerate all prompts and compare against committed baselines.

    Returns True if all match; False (and prints diffs) if any diverge.
    """
    ok = True
    for sc in SCENARIOS:
        path = BASELINES_DIR / f"{sc['category']}.txt"
        if not path.exists():
            print(f"  MISSING  {sc['category']}.txt — run with --save first")
            ok = False
            continue

        current = _generate(sc)
        committed = path.read_text(encoding="utf-8")

        if current == committed:
            print(f"  OK       {sc['category']}")
        else:
            ok = False
            # Find first differing character for a diagnostic hint
            for i, (a, b) in enumerate(zip(committed, current)):
                if a != b:
                    ctx_start = max(0, i - 30)
                    print(f"  CHANGED  {sc['category']} — first diff at char {i}")
                    print(f"    baseline: ...{committed[ctx_start:i+50]}...")
                    print(f"    current:  ...{current[ctx_start:i+50]}...")
                    break
            else:
                # One is a prefix of the other
                print(
                    f"  CHANGED  {sc['category']} — length {len(committed)} → {len(current)}"
                    f" ({len(current)-len(committed):+d} chars)"
                )

    return ok


if __name__ == "__main__":
    if "--save" in sys.argv:
        save_all()
    elif "--compare" in sys.argv:
        if not compare_all():
            sys.exit(1)
    else:
        print(__doc__)
        sys.exit(0)
