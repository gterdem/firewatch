#!/usr/bin/env bash
# Local frontend gates — mirrors the TEMPORARILY DISABLED `ci-frontend` workflow.
# Run from the repo root (or a worktree root). Exits non-zero on the first failure.
#
# Why this exists: ci-frontend is disabled to conserve GitHub Actions minutes
# (private-repo $0 budget; resets monthly). RE-ENABLE before open-source:
#   gh api -X PUT /repos/gterdem/firewatch/actions/workflows/289455820/enable
# See the `ci-frontend-disabled-reenable-before-launch` memory.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/frontend"
echo "==> eslint";          npm run lint
echo "==> tsc --noEmit";    npm run typecheck
echo "==> vitest";          npm run test
# Build step added after fix/geojson-app-crash — catches module-graph failures
# (e.g. .geojson / non-JSON assets) that tsc and vitest do NOT catch but that
# produce a blank screen / SyntaxError at runtime.  Run last because it's the
# slowest gate; the faster gates catch most issues first.
echo "==> vite build";      npm run build
echo "✅ frontend gates passed"
