#!/usr/bin/env bash
# Local backend gates — mirrors the TEMPORARILY DISABLED `ci` (ci.yml) workflow.
# Run from the repo root (or a worktree root). Exits non-zero on the first failure.
#
# Why this exists: ci.yml is disabled to conserve GitHub Actions minutes
# (private-repo $0 budget; resets monthly). RE-ENABLE before open-source:
#   gh api -X PUT /repos/gterdem/firewatch/actions/workflows/288250258/enable
# See the `ci-frontend-disabled-reenable-before-launch` memory.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
echo "==> ruff";    uv run ruff check .
echo "==> pyright"; uv run pyright
# Per-merge gate runs the FAST suite in parallel: xdist (-n auto) + excludes the
# 7 @slow KV-cardinality-cap tests (157-298s each). This is ~31s vs ~13min, and
# parallel execution also clears the load-sensitive `test_ns6` single-process hang.
# Slow tests are a separate backstop: FULL=1 ./gates-backend.sh runs everything
# (use pre-release and when touching the KV/cardinality-cap code).
# Known flaky under host oversubscription — quarantined from the per-merge gate
# only (still runs under FULL=1 and local dev). Tracking: issue #636.
_FLAKY_DESELECT=(
  --deselect "packages/firewatch-core/tests/test_supervisor_stopped_seam.py::test_ns6_cmd_run_uses_public_seam_and_correct_order"
)
if [[ "${FULL:-0}" == "1" ]]; then
  echo "==> pytest (FULL incl. @slow)"; uv run pytest -n auto
else
  echo "==> pytest (fast: -n auto, excludes @slow + #636 flake)"
  uv run pytest -n auto -m "not slow" "${_FLAKY_DESELECT[@]}"
fi
echo "✅ backend gates passed"
