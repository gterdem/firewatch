#!/usr/bin/env bash
# Local frontend gates — mirrors the `ci-frontend` (ci-frontend.yml) workflow.
# Run from the repo root (or a worktree root). Exits non-zero on the first failure.
#
# ci-frontend is ACTIVE and runs on PRs and pushes to main (verified 2026-07-15:
# `gh api repos/gterdem/firewatch/actions/workflows` reports state=active). It was
# disabled for a period to conserve Actions minutes, and this header outlived that
# — telling readers to "re-enable before open-source" something already running.
# If you change ci-frontend.yml, change this file in the same commit.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)/frontend"

# Which tree got gated is the whole claim — see gates-backend.sh for why.
echo "==> tree:   $(git rev-parse --show-toplevel)"
echo "==> branch: $(git branch --show-current 2>/dev/null || echo '(detached)')"
echo "==> HEAD:   $(git rev-parse --short HEAD)"

echo "==> eslint";          npm run lint
echo "==> tsc --noEmit";    npm run typecheck
echo "==> vitest";          npm run test
# Build step added after fix/geojson-app-crash — catches module-graph failures
# (e.g. .geojson / non-JSON assets) that tsc and vitest do NOT catch but that
# produce a blank screen / SyntaxError at runtime.  Run last because it's the
# slowest gate; the faster gates catch most issues first.
echo "==> vite build";      npm run build
echo "✅ frontend gates passed"
