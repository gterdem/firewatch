#!/usr/bin/env bash
# PreToolUse(Bash) guard — keep a worktree agent's shell inside its own tree.
#
# THE BUG THIS EXISTS FOR
#   Agents run in isolated worktrees under .claude/worktrees/agent-*. Write/Edit are
#   pinned to that tree; **Bash is not** (no native mechanism pins it — verified against
#   the Claude Code hooks docs, 2026-07-15). So `cd <primary-checkout> && pytest` silently
#   runs against the SHARED checkout: gates go green while proving nothing about the
#   agent's branch, and stray branches land on the primary. Both happened on 2026-07-15.
#
# WHY IT INSPECTS THE COMMAND, NOT `cwd`
#   PreToolUse fires BEFORE the command runs, so for `cd /elsewhere && pytest` the hook
#   still sees cwd = the worktree. The `cd` lives in the command string. Comparing `cwd`
#   to the expected worktree — the obvious design — cannot see this bug at all.
#
# POSTURE: observe -> enforce  (FIREWATCH_WORKTREE_GUARD=observe|enforce)
#   Two facts this relies on are NOT documented: what `cwd` means for a subagent, and
#   whether `agent_id` is populated for CLI (non-SDK) hooks. If either is wrong, a
#   blocking guard would exit 0 forever and be silently useless — the same false-green
#   failure it is meant to prevent. So it ships in `observe`: it logs what it actually
#   sees and blocks nothing. Read the log, confirm it fires with a real agent_id/cwd,
#   THEN flip the default to `enforce`. Do not trust this guard until the log proves it.
#
# FAIL-OPEN BY DESIGN
#   Every ambiguity (no jq, unparseable command, `cd "$VAR"`, nonexistent path) exits 0.
#   A guard that blocks legitimate work is a worse bug than the one it prevents; the
#   gate scripts' tree/branch/HEAD banner is the backstop for whatever slips through.
set -uo pipefail

MODE="${FIREWATCH_WORKTREE_GUARD:-observe}"
LOG="${TMPDIR:-/tmp}/firewatch-worktree-guard.log"

command -v jq >/dev/null 2>&1 || exit 0
INPUT=$(cat)

CMD=$(jq -r '.tool_input.command // empty' <<<"$INPUT" 2>/dev/null) || exit 0
CWD=$(jq -r '.cwd // empty'                <<<"$INPUT" 2>/dev/null) || exit 0
AGENT_ID=$(jq -r '.agent_id // empty'      <<<"$INPUT" 2>/dev/null)
AGENT_TYPE=$(jq -r '.agent_type // empty'  <<<"$INPUT" 2>/dev/null)
[ -n "$CMD" ] && [ -n "$CWD" ] || exit 0

# Observe mode records EVERY invocation — including the fields whose semantics are
# undocumented. This log is the evidence that decides whether enforce is safe.
if [ "$MODE" = "observe" ]; then
  printf '%s\tagent_id=%s\tagent_type=%s\tcwd=%s\tcmd=%s\n' \
    "$(date -Iseconds)" "${AGENT_ID:-<empty>}" "${AGENT_TYPE:-<empty>}" "$CWD" "${CMD:0:200}" >>"$LOG" 2>/dev/null || true
fi

SESSION_TREE=$(git -C "$CWD" rev-parse --show-toplevel 2>/dev/null) || exit 0
GIT_DIR=$(git -C "$CWD" rev-parse --absolute-git-dir 2>/dev/null) || exit 0
COMMON_DIR=$(git -C "$CWD" rev-parse --path-format=absolute --git-common-dir 2>/dev/null) || exit 0

# Only guard LINKED worktrees. In the primary checkout these two paths are equal, and
# the coordinator session legitimately works there (and legitimately inspects worktrees).
# This deliberately does not depend on `agent_id`, whose CLI availability is undocumented.
[ "$GIT_DIR" = "$COMMON_DIR" ] && exit 0

# Literal absolute `cd`/`pushd` targets only. Anything with a variable or glob is
# unresolvable here, so we let it through rather than guess.
while read -r target; do
  [ -n "$target" ] || continue
  target_tree=$(git -C "$target" rev-parse --show-toplevel 2>/dev/null) || continue
  [ "$target_tree" = "$SESSION_TREE" ] && continue

  REASON="BLOCKED: 'cd $target' leaves your worktree.

  You are in:  $SESSION_TREE
  That path is in a DIFFERENT git tree: $target_tree

Bash is not pinned to your worktree, so this would run against a checkout other
sessions are using: gate results there say nothing about your branch, and git
commands there move someone else's HEAD.

Use worktree-relative paths instead. To confirm where you are, ask git:
  git rev-parse --show-toplevel
If you genuinely need to read from another tree without entering it, use
'git -C <path> ...' or an absolute path to the file — do not cd."

  if [ "$MODE" = "enforce" ]; then
    echo "$REASON" >&2
    exit 2
  fi
  printf '%s\tWOULD-BLOCK\ttarget=%s\ttarget_tree=%s\tsession_tree=%s\n' \
    "$(date -Iseconds)" "$target" "$target_tree" "$SESSION_TREE" >>"$LOG" 2>/dev/null || true
done < <(grep -oE '(^|[;&|]|&&|\|\|)[[:space:]]*(cd|pushd)[[:space:]]+/[^[:space:];&|)"'"'"']*' <<<"$CMD" 2>/dev/null \
         | grep -oE '/[^[:space:];&|)"'"'"']*$' 2>/dev/null)

exit 0
