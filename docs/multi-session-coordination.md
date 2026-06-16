# Multi-Session Coordination

How to run **several Claude Code sessions against this one repo at the same time**
without drifting branches, clobbering each other's work, or bringing scrubbed
content back into `main`. Read this before opening a second session.

## TL;DR

- **Exactly one session lives in the main checkout** (the *coordinator*). Every
  other session runs in its own worktree: `claude --worktree <name>`.
- **Never rewrite/force-push `main` while another session has an unmerged branch.**
  History rewrites are a solo operation.
- `/firewatch-end` from a **worktree** session is always safe (it touches nothing
  but its own branch). The **main-checkout** garbage-collect is coordinator-only.

## The model: one coordinator + N isolated dev sessions

This repo's workflow assumes a split, and `firewatch-end` detects which side you're
on automatically (it compares `git rev-parse --git-common-dir` vs `--git-dir`).

```
┌─ Terminal 0: COORDINATOR ───────────────┐   runs IN the main checkout
│  cd firewatch && claude                  │   owns: PROGRESS.md, merging PRs,
│  → planning, merge, GC, history rewrites │   worktree GC, history rewrites
└──────────────────────────────────────────┘   ⚠ ONLY ONE of these, ever
┌─ Terminal 1: DEV ────────────────────────┐
│  claude --worktree issue-642             │   own checkout + branch + context
├─ Terminal 2: DEV ────────────────────────┤
│  claude --worktree issue-605             │   never touches the main checkout
└──────────────────────────────────────────┘
```

**Why a coordinator at all?** Some agents isolate themselves and some don't.
Only `backend-dev`, `ui-dev`, and `ui-tester` carry `isolation: worktree`. The
`architect`, `security-reviewer`, `product-strategist`, and `claude` agents run
**in the session's own checkout**. If two sessions share the main checkout — or a
non-isolated agent does branch/commit ops there — the primary `HEAD` drifts onto
an agent branch ("main-checkout drift"). Keeping all but one session in a worktree
removes the shared surface that drift needs.

## Two hard rules

1. **One main-checkout session at a time.** All other sessions must be
   `--worktree`. Do not start a second `claude` in the repo root while the
   coordinator is live.
2. **No history rewrites while others have unmerged branches.** Force-pushing
   `main` (e.g. a git-history secret scrub) rewrites every descendant SHA. Any
   session whose branch was cut from the old history will then re-flag the old
   content and fail its gate. Do scrubs **solo**, then have each other session
   rebase: `git fetch origin && git rebase origin/main`.

## `claude --worktree` cheat sheet

> Flags evolve — confirm against `claude --help` / the
> [worktrees doc](https://code.claude.com/docs/en/worktrees) on your version.

| Command | Effect |
|---|---|
| `claude --worktree <name>` (`-w`) | Creates `.claude/worktrees/<name>/`, branches from `origin/HEAD` (clean tree), checks out `worktree-<name>`. Isolated files + branch + context window. |
| `claude --worktree` (no name) | Same, with an auto-generated name. |
| `git worktree list` | See every session's worktree + branch. |

`.claude/worktrees/` is already gitignored in this repo, so worktree files never
show up as untracked noise in the main checkout.

## What `/firewatch-end` prunes (the important part)

`firewatch-end` behaves differently depending on where you run it:

| Run it in… | What it prunes | Safe alongside other sessions? |
|---|---|---|
| **A `--worktree` dev session** | **Nothing else.** Gates → commit → sync `main` into *its* branch → push → open/refresh a **draft PR** → leaves its own worktree until the PR merges. | ✅ **Yes, always.** This is the common case. |
| **The main checkout (coordinator)** | GCs worktrees whose branch is **already merged** (an *unmerged* worktree is never touched), **plus** blanket-deletes `worktree-agent-*` isolation branches. | ⚠️ **Mostly.** Git refuses to delete a branch checked out in a *live* worktree, so active agents elsewhere are protected. Only risk: a stale, **unpushed** `worktree-agent-*` from an idle session. |

The GC keys off **merged-PR status** (this repo squash-merges, so `git branch
--merged` won't recognize merged branches). It explicitly **will not** auto-delete
`scratch/` or `work/*` branches it can't confirm are merged — it lists them for you.

**Practical rule:** run `/firewatch-end` freely from dev sessions; run the
main-checkout GC only from the single coordinator, ideally when dev sessions are
ended or idle.

## History-rewrite protocol (force-pushing `main`)

1. Announce it / make sure no dev session has work mid-flight that isn't pushed.
2. Coordinator performs the rewrite + force-push to `origin/main` **solo**.
3. Each other session, before continuing:
   ```bash
   git fetch origin --prune
   git rebase origin/main          # resolve conflicts KEEPING the scrubbed version
   git merge-base --is-ancestor <old-bad-sha> HEAD && echo "STILL DIRTY — stop" || echo "clean"
   git push --force-with-lease origin <branch>
   ```
4. Merge those PRs with **squash** (`gh pr merge <n> --squash --delete-branch`),
   never a merge-commit — a merge-commit would re-attach the old (pre-scrub)
   ancestry to `main` and undo the rewrite.

## Quick hygiene checklist

- [ ] Only one session in the repo root; the rest are `claude --worktree …`.
- [ ] `git worktree list` periodically; `git worktree remove <path> --force` stale ones.
- [ ] Sync before committing on main: `git fetch origin --prune && git merge --ff-only origin/main`.
- [ ] Dev sessions finish via `/firewatch-end` → draft PR (never self-merge).
- [ ] Coordinator owns merges, PROGRESS.md, GC, and any history rewrite.
