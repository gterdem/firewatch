First detect the context:
Run `git rev-parse --git-common-dir` and `git rev-parse --git-dir`. If they DIFFER, this is a
linked worktree (a dev session). If they're the SAME, this is the main checkout (planning session).

## If in a WORKTREE (dev session finishing an issue)
1. Run gates: `uv run ruff check .`, `uv run pyright`, `uv run pytest`. If any fail, STOP and
   report — do not push broken work.
2. Ensure all work is committed (the pre-commit hook scans for secrets on each commit — note it only
   fires once this branch has `.githooks/` from main, which step 3's sync brings in). If there are
   uncommitted changes, summarize and commit them.
3. **Sync `main` before pushing** — mirrors `backend-dev.md` step 5; never push a stale branch:
   `git fetch origin`; if behind `origin/main`, `git merge origin/main` (merge, NOT rebase — the
   branch is pushed). Then cheap-gated reconcile on the merged delta (`git diff --name-only`):
   - touched an ADR / PLUGIN_CONTRACT.md / ARCHITECTURE.md section this issue references → re-read
     just that and reconcile the code;
   - touched code/config → re-run the gates (step 1);
   - docs-only / nothing relevant → proceed.
   Reconcile IN THIS branch; never open a second PR to catch up to `main`.
4. Push the branch: `git push -u origin "$(git branch --show-current)"`.
5. Open or update a DRAFT PR: `gh pr create --draft --fill` (or update the existing one). Link the
   issue it closes, and summarize what was implemented, which EARS criteria are met, and the gate
   results. Do NOT mark ready, do NOT merge.
6. Do NOT touch PROGRESS.md — it's main-only.
7. Report the PR URL. Remind me that the remaining gates are mine: the security-reviewer (CLAUDE.md
   "done" also needs no blocking findings), review, mark-ready, and merge. Remove the worktree only
   after the PR merges.

## If in the MAIN checkout (planning session)
1. **Fetch first — never commit on a stale `main`:** `git fetch origin --prune`; if local `main` is
   behind, `git merge --ff-only origin/main` (origin advances whenever an agent PR merges mid-session).
   `--prune` drops remote-tracking refs for branches deleted on origin after merge.
2. **Garbage-collect merged worktrees & branches** (the dev-session worktrees never clean themselves —
   `backend-dev`/the worktree path of this skill leaves them for here). This repo **squash-merges**, so
   `git branch --merged` will NOT recognize them — drive the cleanup off merged-PR status instead:
   - Build the set of merged PR head branches:
     `gh pr list --state merged --limit 100 --json headRefName -q '.[].headRefName'`.
   - For every linked worktree (`git worktree list`) whose branch is in that set, remove it:
     `git worktree remove <path> --force`, then `git worktree prune`.
   - Delete every local branch (except `main`) that is in the merged set, plus internal
     `worktree-agent-*` isolation branches: `git branch -D <branch>` (use `-D`; `-d` rejects
     squash-merged branches).
   - **Scratch/`work/*` branches with no matching merged PR:** do NOT auto-delete. Verify their
     content is already in `main` first — confirm the feature's PR merged and grep `main` for a
     signature line from the branch's commits (a stale branch shows mostly *deletions* vs `main` and
     only old versions of shared files as "insertions" — that's superseded, not unmerged). If you
     can't confirm, LIST them for me and leave them.
   - Report what was removed (and anything left pending). The goal: end every planning session with
     `git worktree list` showing only the main checkout and `git branch` showing only `main`.
3. Update PROGRESS.md: what got done, what's next, open decisions / new ADRs needed. Also reflect
   **board state**: which issues were closed / milestones advanced this session. If a milestone
   closed (its DoD sentence demonstrated), run the verification matrix
   (`docs/internal/use-case-matrix.md`) on the real fleet BEFORE calling it closed — findings file
   per the walkthrough triage rule.
4. Run gates if code changed.
5. Commit to `main` (the pre-commit hook runs gitleaks). **PROGRESS.md is gitignored / local-only —
   update the file, never commit it.** For any tracked doc/ADR edit, show me the diff and wait for
   my go-ahead first (verify-in-changeset rule). Report what you committed.
6. Do NOT push automatically — print the exact `git push` command for me to run. (Deliberate
   safety gate at session end — with parallel sessions in flight, the maintainer controls when
   `main` advances on origin. Mid-session pushes explicitly approved by the maintainer are fine;
   this gate is for the end-of-session commit.)
