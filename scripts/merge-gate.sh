#!/usr/bin/env bash
# Merge-gate: runs the gates against a PR's real code and merges ONLY if every gate
# is green — applied at the real enforcement point, just before a GitHub PR merge.
#
# ci / ci-frontend / gitleaks are all ACTIVE in GitHub Actions (verified 2026-07-15:
# `gh api repos/gterdem/firewatch/actions/workflows` reports state=active for all
# three). This wrapper is therefore a local pre-merge BACKSTOP, not a replacement —
# an earlier header called it "the replacement for the disabled ci / ci-frontend
# workflows" long after they were re-enabled, while line ~13 said the opposite.
#
# A git hook can NOT do this: GitHub PR merges happen server-side, so local hooks
# never fire on them. This wrapper runs the area-appropriate gate scripts against
# the PR's code in an isolated worktree and ONLY merges if every gate is green.
#
# Usage:  scripts/merge-gate.sh <PR#> [--no-merge]
#   --no-merge : run the gates and report, but do not merge (dry run).
#
# Notes:
#   * gitleaks/scan still runs in CI (cheap) — this wrapper does NOT replace it.
#   * Frontend node_modules are symlinked from the primary checkout (fast).
#   * Backend runs `uv sync` in the worktree (slower, but a faithful clean check).
set -euo pipefail

PR="${1:?usage: merge-gate.sh <PR#> [--no-merge]}"
ROOT="$(git rev-parse --show-toplevel)"
BRANCH="$(gh pr view "$PR" --json headRefName --jq .headRefName)"
FILES="$(gh pr view "$PR" --json files --jq '.files[].path')"
WT="$ROOT/.claude/worktrees/merge-gate-$PR"

echo "merge-gate: PR #$PR (branch: $BRANCH)"
# ROOT is derived from the caller's cwd, and Bash is not pinned to an agent's
# worktree — run this from the wrong tree and the gates, the scratch worktree
# under $ROOT/.claude, and the node_modules symlink all silently retarget.
echo "==> root:   $ROOT"
echo "==> HEAD:   $(git -C "$ROOT" rev-parse --short HEAD) on $(git -C "$ROOT" branch --show-current 2>/dev/null || echo '(detached)')"
git -C "$ROOT" fetch origin -q
git -C "$ROOT" worktree add --force "$WT" "origin/$BRANCH" >/dev/null 2>&1
cleanup() { git -C "$ROOT" worktree remove --force "$WT" 2>/dev/null || true; }
trap cleanup EXIT

need_fe=0; need_be=0
grep -qE '^frontend/'                                   <<<"$FILES" && need_fe=1
grep -qE '^(packages/|tests/|pyproject\.toml|uv\.lock)' <<<"$FILES" && need_be=1

if [ "$need_fe" = 1 ]; then
  echo "=== frontend gates ==="
  ln -snf "$ROOT/frontend/node_modules" "$WT/frontend/node_modules"
  ( cd "$WT" && bash "$ROOT/scripts/gates-frontend.sh" )
fi
if [ "$need_be" = 1 ]; then
  echo "=== backend gates ==="
  ( cd "$WT" && uv sync --all-packages -q && bash "$ROOT/scripts/gates-backend.sh" )
fi
[ "$need_fe" = 0 ] && [ "$need_be" = 0 ] && echo "(docs/infra only — no code gates)"

# Secret scan — the gitleaks workflow is active in CI; this is the local pre-merge
# backstop. Full-history scan of the PR branch; non-zero exit aborts the merge (set -e).
echo "=== gitleaks (secret scan) ==="
( cd "$WT" && gitleaks git -c .gitleaks.toml --no-banner )

echo "✅ all gates green for PR #$PR"
if [ "${2:-}" = "--no-merge" ]; then echo "(--no-merge: stopping before merge)"; exit 0; fi
gh pr merge "$PR" --squash --delete-branch
echo "✅ merged PR #$PR"
