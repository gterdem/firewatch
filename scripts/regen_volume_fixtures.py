#!/usr/bin/env python3
"""Single regeneration entrypoint for the volume oracle's committed derived
fixture (ADR-0068 D3/D4, issue #50).

Regenerates ``tests/volume/fixtures/derived_threats.json`` from the ambient
night manifest (breach variant — the richer artifact the frontend sibling
test consumes, since it exercises both a queue-worthy and a null-tier actor
population) via the SAME seeded generator + real-normalizer harness the
pytest suite calls. Run this after a deliberate manifest edit (with the
distribution justification recorded in the PR — README.md's discipline
section); ``test_triage_volume.py``'s determinism test fails loudly if this
file drifts from what the generator/harness actually produce.

Usage::

    uv run python scripts/regen_volume_fixtures.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).parent.parent
_VOLUME_DIR = _REPO_ROOT / "tests" / "volume"
sys.path.insert(0, str(_VOLUME_DIR))

import generator  # noqa: E402  # pyright: ignore[reportMissingImports]
import harness  # noqa: E402  # pyright: ignore[reportMissingImports]

SEED = 20260202


def main() -> None:
    manifest = generator.load_manifest()
    scenario = generator.build_ambient_scenario(manifest, seed=SEED, breach=True)
    scores = harness.score_all(scenario.raw_events, scenario.now)

    out_path = _VOLUME_DIR / "fixtures" / "derived_threats.json"
    payload = [t.model_dump(mode="json") for t in scores]
    out_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    print(f"wrote {len(payload)} actors to {out_path}")


if __name__ == "__main__":
    main()
