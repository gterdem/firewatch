"""AI verdict-baseline subpackage — MI-9 (issue #390).

This subpackage owns:
- ``fixtures``: canonical scenario registry (moved from tests/golden/ai/fixtures.py;
  bytes are pinned — relocation ≠ modification).
- ``runner``: execute all scenarios against a live AIEngine adapter.
- ``report``: pure verdict-diff comparison and human-readable rendering.

Design notes
------------
- ``fixtures`` is the canonical source of truth for both the CLI (runtime use)
  and ``tests/golden/ai/`` (which re-exports from here so the oracle stays
  byte-identical).
- ``runner`` and ``report`` are kept separate to isolate I/O (runner) from
  pure logic (report) — report is testable without any async/mock setup.
- No prompt construction, no scoring, no store access — see ai-engine-invariants
  skill for the hard out-of-scope boundary.
"""
