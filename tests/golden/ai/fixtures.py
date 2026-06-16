"""Synthetic SecurityEvent fixtures for the AI prompt-baseline oracle.

All source IPs are from RFC 5737 documentation ranges ONLY:
  - TEST-NET-1: 192.0.2.0/24
  - TEST-NET-2: 198.51.100.0/24
  - TEST-NET-3: 203.0.113.0/24

These IPs are whitelisted in .gitleaks.toml and are guaranteed non-routable.
No real attacker IPs, no PII, no secrets — this module is gitleaks-clean.

Design note: fixtures are plain Python (no DB, no network) so the oracle
runs in tens of ms and is deterministic across CI runs.

Relocation note (MI-9 / issue #390)
------------------------------------
The canonical fixture data now lives in
``firewatch_core.ai.baseline.fixtures``.  This module re-exports everything
from there so that:
  - the prompt-baseline oracle (``tests/golden/ai/``) continues to work
    without any changes to the harness or test imports;
  - the CLI command and runtime code can import from the package location
    without depending on the test tree.

Byte-identity is guaranteed by re-exporting rather than duplicating:
there is exactly ONE copy of the data.
"""
from __future__ import annotations

# Re-export everything from the canonical package location.
from firewatch_core.ai.baseline.fixtures import (  # noqa: F401
    CORRELATIONS_MIXED,
    FIRST_SEEN,
    LAST_SEEN,
    IP_ATTACKER,
    IP_MIXED,
    IP_SCANNER,
    SAMPLES_ATTACKER,
    SAMPLES_DETAILED_ATTACKER,
    SAMPLES_DETAILED_MIXED,
    SAMPLES_HOSTILE_RULEID,
    SAMPLES_MIXED,
    SAMPLES_SCANNER,
    SCENARIOS,
    _FakeDetection,
)
