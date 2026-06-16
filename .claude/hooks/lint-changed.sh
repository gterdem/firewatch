#!/usr/bin/env bash
# Fast feedback: lint + typecheck the file Claude just edited.
set -euo pipefail
FILE=$(jq -r '.tool_input.file_path // empty' 2>/dev/null || true)
[ -z "${FILE:-}" ] && exit 0
case "$FILE" in
  *.py)
    uv run ruff check "$FILE" || { echo "ruff failed on $FILE" >&2; exit 2; }
    uv run pyright "$FILE"     || { echo "pyright failed on $FILE" >&2; exit 2; }
    ;;
esac
exit 0