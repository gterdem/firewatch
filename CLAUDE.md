# FireWatch — Working Agreement (read every session)

## What this is
FireWatch is a modular threat-monitoring platform. Telemetry sources
(Azure WAF, Suricata, …) are PLUGINS against a single contract. The core never
imports a plugin. Adding a source must require ZERO edits to firewatch-core.

## Sources of truth (always defer to these, in this order)
1. docs/adr/          — settled decisions (ADRs); never re-argue an accepted one unless a maintainer reopens it
2. PLUGIN_CONTRACT.md — the source-plugin interface (architect-owned)
3. ARCHITECTURE.md    — the design
4. GitHub issues      — task ledger

## The non-negotiables
1. **Modularity is the base standard.** A new source = a new package under
   packages/sources/, implementing SourcePlugin, registered via entry points,
   with zero core edits.
2. **Dependency rule.** Plugins and core both depend on firewatch-sdk.
   Core never imports a plugin. Plugins never import core.
3. **Regression oracle.** tests/golden must show stable scoring: the same input
   logs always produce the same scores.

## Workflow orchestration (how we work)
1. **Plan-mode default.** Enter Plan Mode for any non-trivial task (3+ steps or
   any architectural decision). If something goes sideways, STOP and re-plan —
   don't keep pushing. Use Plan Mode for verification, not just building.
2. **Subagent strategy.** Use subagents liberally to keep the main context clean.
   Offload research, exploration, and parallel analysis. One focused task per
   subagent. Only the summary returns to the main thread.
3. **Verification before done.** Never mark a task complete without proving it
   works. Where relevant, diff behavior against the regression oracle. Ask:
   "Would a staff engineer approve this?" Run the gates; show the result.
4. **Demand elegance (balanced).** For non-trivial changes, pause and ask "is
   there a simpler, more elegant way?" If a fix feels hacky, redo it properly.
   Skip this for small obvious fixes — don't over-engineer.
5. **Autonomous bug-fixing.** Given a bug report or failing CI, just fix it —
   point at the logs/errors/failing tests and resolve them. No hand-holding.
6. **Multiple sessions → isolate.** Exactly one session lives in the main
   checkout (the coordinator); every other runs in its own `claude --worktree`.
   Never rewrite/force-push `main` while another session has an unmerged branch.
   See `docs/multi-session-coordination.md`.

## Task & progress management (ONE ledger — do not create a second)
1. **Plan first.** The architect turns a one-paragraph intent into a spec with
   EARS acceptance criteria and a task breakdown, filed as GitHub issues with an
   explicit "Out of scope" section.
2. **Verify the plan** with a maintainer before implementation begins.
3. **One issue → one branch → one PR.** Track progress by closing issues.
4. **Explain changes** with a short high-level summary at each step.
5. **Maintain a session ledger** — record done / next / open decisions at the
   end of every session.

## Self-improvement loop (this is how the agents "keep learning")
- After ANY correction from a maintainer, append the pattern to your lessons log
  (`docs/internal/lessons.md`, kept local) as a short rule that prevents the same mistake
  next time.
- Review your lessons at the start of each session for relevant items.
- (Native option: `#` during a session quick-adds a memory; `/memory` edits files.)

## Model policy
- Architecture / contract / planning → Fable 5 (the architect subagent) — highest-leverage,
  lowest-volume work; architecture errors multiply across every downstream PR.
- Product strategy / UX innovation / competitive benchmarking → Fable 5 (the product-strategist
  subagent) — advise-only; same low-volume / high-judgment profile. No web tools: pair it with a
  Haiku web-research pass (coordinator-orchestrated) for fresh competitive data.
- Implementation against the contract → Sonnet (backend-dev, ui-dev).
- File search / test running / web research → Haiku.
- Subagents set their own model; if unset they inherit, so we set it explicitly.

## Build / test / lint (the gates)
```bash
uv run ruff check .     # lint
uv run pyright          # type check
uv run pytest           # tests, including tests/golden
```
"Done" = all three green AND the security review raises no blocking findings.

## Core principles
- **Simplicity first** — make every change as small as possible; touch only what's needed.
- **No laziness** — find root causes; no temporary patches; senior-engineer standard.
- **Minimal blast radius** — avoid changes that risk introducing regressions.
- **Decompose by concern.** Prefer focused modules over monoliths — target files ≤ ~500 lines, one
  class ≈ one concern; split a multi-concern class into a subpackage (or justify keeping it cohesive).
  Balance against over-fragmentation: cohesive shared state stays together. The architect specifies the
  module layout for complex components; the implementer self-checks structure before opening a PR.
- **Verify against the industry standard — never assume.** When something is unknown or a
  design choice is being made, check the relevant published standard first (OCSF, ECS, MITRE
  ATT&CK, OWASP, NIST, RFCs, 12-factor, …) and cite the source in the ADR / doc / code comment.
  If FireWatch deliberately deviates, write down *why* the deviation is justified. Don't anchor
  decisions on memory or convenience alone.
