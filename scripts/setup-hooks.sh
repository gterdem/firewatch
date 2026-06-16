#!/usr/bin/env bash
# One-time per-clone setup for the FireWatch secret-scanning gate.
#
# Points git at the committed .githooks/ directory. A RELATIVE core.hooksPath
# resolves against each working tree's own root, so this single setting covers
# the main clone AND every git worktree the dev agents create (they inherit it
# from the shared common config — no per-worktree run needed).
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

git config core.hooksPath .githooks
chmod +x .githooks/* 2>/dev/null || true

echo "✓ core.hooksPath -> .githooks (covers this clone and all worktrees)"

if ! command -v gitleaks >/dev/null 2>&1; then
  echo "⚠ gitleaks is NOT installed — the pre-commit hook will BLOCK every commit until it is." >&2
  echo "  Install: https://github.com/gitleaks/gitleaks#installing" >&2
else
  echo "✓ gitleaks found: $(gitleaks version)"
fi
