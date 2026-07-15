#!/usr/bin/env bash
# Full-history secret scan — the EXACT command CI's gitleaks/scan job runs
# (.github/workflows/gitleaks.yml), so a clean run here means CI will be clean too.
#
# Why this exists: the committed pre-commit hook (.githooks/pre-commit) only scans
# STAGED changes, and does not fire at all in an agent's isolated worktree. A local
# check scoped to your own commits (e.g. `gitleaks git --log-opts="origin/main..HEAD"`)
# is NOT equivalent — it misses false positives that a squash-merge or an earlier
# commit already baked into full history, which is what CI actually scans
# (fetch-depth: 0). Run THIS script — not a scoped diff — before opening a PR.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

if ! command -v gitleaks >/dev/null 2>&1; then
  echo "✖ gitleaks not found — install: https://github.com/gitleaks/gitleaks#installing" >&2
  exit 1
fi

echo "==> gitleaks (full history, mirrors CI exactly)"
gitleaks git -c .gitleaks.toml --no-banner --redact
echo "✅ full-history secret scan passed"
