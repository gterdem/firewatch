#!/usr/bin/env bash
# Local backend gates — mirrors the `ci` (ci.yml) workflow.
# Run from the repo root (or a worktree root). Exits non-zero on the first failure.
#
# The whole point of this script is that it MATCHES CI. When it drifts, a green
# run here means nothing — and that has now bitten three separate times:
#   - gitleaks was run locally over `origin/main..HEAD` while CI scans full
#     history, so agents reported "clean" on a repo that was failing
#     (fixed: scripts/gitleaks-full.sh)
#   - the gates were documented without `uv sync --all-packages`, so aws-nfw
#     could not import boto3 and every local gate reported failures CI never saw
#   - test_ns6 was deselected here as "flaky" while CI ran it and went red
# If you change ci.yml, change this file in the same commit.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# CI runs this first. Without it, packages that declare their own dependencies
# (e.g. aws-nfw -> boto3) cannot import, and ruff/pyright/pytest all report
# failures that exist only in your environment.
echo "==> sync (match CI's env)"; uv sync --all-packages

echo "==> ruff";    uv run ruff check .
echo "==> pyright"; uv run pyright
# Per-merge gate runs the FAST suite in parallel: xdist (-n auto) + excludes the
# 7 @slow KV-cardinality-cap tests (157-298s each). This is ~31s vs ~13min.
# Slow tests are a separate backstop: FULL=1 ./gates-backend.sh runs everything
# (use pre-release and when touching the KV/cardinality-cap code).
#
# NOTE: ci.yml runs a bare `uv run pytest` — i.e. INCLUDING @slow. This script is
# deliberately narrower for speed, so FULL=1 is what actually mirrors CI.
if [[ "${FULL:-0}" == "1" ]]; then
  echo "==> pytest (FULL incl. @slow — mirrors ci.yml)"; uv run pytest -n auto
else
  echo "==> pytest (fast: -n auto, excludes @slow)"
  uv run pytest -n auto -m "not slow"
fi
echo "✅ backend gates passed"
