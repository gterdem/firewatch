# ADR-0028: Frontend Project Layout & Toolchain — Standalone `frontend/` Vite App, Per-Language CI, rjsf↔shadcn Convention

**Date:** 2026-06-04
**Status:** Accepted

> **Pointer (2026-06-05, non-substantive):** Decision D6 (deferred SOC visual theme) is now **actionable** —
> Maintainer live-tested the running UI on 2026-06-05; the ui-tester's read was that the rough edges are *purely
> presentation-layer* (structure/routing/data-flow/modal/schema-form all verified working).
>
> **D6 source updated (2026-06-05, non-substantive):** the SOC visual theme is now concretely **defined by
> `legacy/FireWatch SOC Design System/`** (v2, multi-source: tokens, component library, the `soc-console`
> layout oracle, adherence lint) **+ the `firewatch-design` skill** (`.claude/skills/firewatch-design/SKILL.md`).
> This supersedes the earlier "Claude Design" candidate-tool note in D6 as the theme's *source of truth*.
> Application is planned in `docs/design-application-plan.md` and tracked under the renamed milestone
> **"MD — Apply the FireWatch SOC Design System (v2)"** — Phase 1 foundations (**#107** tokens+shell ·
> **#108** primitives · **#109** v2 source+filter components · **#110** rjsf re-skin · **#111** emoji+mono+adherence lint)
> and Phase 2 pages (**#112** Logs · **#113** Dashboard · **#114** drill-down · **#115** AI · **#116** Settings),
> with Analytics restyle **deferred** (**#117**). The bootstrap issues **#96** (token system) · **#97** (AI-status chip) ·
> **#98** (empty/loading/error states) remain closed — their *structure* is reused, their *values/recipes* are
> replaced by the exact v2 spec; the umbrella **#99** is closed as superseded by the concrete issue set.
> This pointer does **not** reopen or amend the accepted decision text below.

**Relates to:** ADR-0019 (frontend stack — React + Vite + TS + rjsf + Tailwind/shadcn; **not reopened**),
ADR-0010 (unified source cards — one schema-driven card per source; **not reopened**),
ADR-0006 (config precedence; `SecretStr`), ADR-0026 (loopback-only API for MA), ADR-0016 (multi-source-per-type; per-instance scope deferred to MB).
**Implements / gates:** MA.4 Settings UI (#33).
**Standards consulted:** The Twelve-Factor App (I — codebase; V — build/release/run; X — dev/prod parity),
Vite project conventions (official docs), react-jsonschema-form v6 docs (themes, custom widgets/templates, `customize-the-default-theme`),
`@rjsf/validator-ajv8` (AJV 2020-12 / `if`/`then`/`else` support), standard monorepo CI practice (path-filtered jobs per language).

---

## Context

ADR-0019 settled the *stack* (React/Vite/TS + rjsf + Tailwind/shadcn) and *strategy* (clean rewrite,
Settings-first) but left three mechanical questions unanswered, which MA.4 (#33) now forces:

1. **Where does the frontend live and how is it managed** relative to the Python `packages/` tree?
2. **How does CI gate it**, given the repo is otherwise Python-only (`uv` / ruff / pyright / pytest)?
3. **How do rjsf forms render against shadcn**, and how do conditional schemas behave in the card?

ADR-0019 predates the work; it assumed an `@rjsf/mui`-style theme and rjsf v5 conventions. As of the
MA.4 build the ecosystem has moved: rjsf is at **v6.6.1**, and the rjsf team now ships an **official
`@rjsf/shadcn` theme** (GA since 6.0.0, Oct 2025; MIT; same `rjsf-team` org). This ADR records the
layout/tooling decisions and the rjsf↔shadcn convention without re-litigating the stack choice.

---

## Decision

### D1 — Placement: standalone `frontend/` at repo root (no TS workspace)

The React app lives at **`frontend/`** at the repository root, as a **standalone Vite app** — *not*
a TS/JS workspace member, *not* nested under `packages/`. The Python tree (`uv` workspace under
`packages/`) and the JS tree (`frontend/`) are **two independent toolchains in one Git codebase**
(12-Factor I: one codebase, many deploys — the API and the UI are two deploys of the same repo). The
UI talks to the backend only over HTTP (the loopback API, ADR-0026); there is no build-time coupling,
so there is no benefit to a shared JS/TS workspace and a real cost to forcing `packages/` (a `uv`
workspace) to also be an npm workspace.

### D2 — Package manager: **npm** (pnpm documented as the escape hatch)

`frontend/` uses **npm** with a committed `package-lock.json`. Rationale: it is the zero-install
default for a Python-first contributor base (Node ships npm; nothing extra to learn), and the app is a
single package with no workspace fan-out where pnpm's content-addressed store would pay off.

- **pnpm is the documented escape hatch** if install speed or disk use ever bites — it is a drop-in
  with a lockfile migration and no source changes.
- **bun is deferred**: it adds separate-install friction for a Python-first contributor base and is
  not yet an industry default for CI-gated production frontends; revisit only if it becomes the norm.

### D3 — CI: gates-per-language, path-filtered

Frontend gets its **own CI job**, filtered to `frontend/**`, running **eslint + `tsc --noEmit` +
vitest**, sitting *alongside* (not inside) the existing Python job filtered to `packages/**`. The two
jobs are peers: a Python change does not run Node, a UI change does not run pytest. This mirrors the
"gates" model in CLAUDE.md (ruff/pyright/pytest) — same shape, second language. "Done" for a
`frontend/**` change = its three frontend gates green.

| Concern | Python (`packages/**`) | Frontend (`frontend/**`) |
|---|---|---|
| Lint | `ruff check` | `eslint` |
| Types | `pyright` | `tsc --noEmit` |
| Tests | `pytest` (incl. `tests/golden`) | `vitest` (+ testing-library) |

### D4 — rjsf↔shadcn rendering convention

Use **`@rjsf/core` v6 + `@rjsf/validator-ajv8`** with a **theme**. Two viable paths exist now that an
official shadcn theme ships; the convention is:

- **Default to the official `@rjsf/shadcn` theme** as the base, then layer a **project-local widget/
  template registry** for the cases the contract needs explicit control over — at minimum a
  `PasswordWidget` for `SecretStr` fields (masked input, never echoed/logged) and the
  `ObjectFieldTemplate`/`FieldTemplate` that carry the unified-card layout slots (ADR-0010). rjsf v6
  composes a custom registry *over* a theme via `widgets={...}` / `templates={...}` props or
  `withTheme`, so the official theme and a thin override registry coexist — we get shadcn primitives
  for free and keep a single seam for the contract-specific widgets.
- **The contract-specific registry is the load-bearing artifact**, not the theme choice: if
  `@rjsf/shadcn` ever diverges from our Tailwind tokens (legacy `--bg`/`--accent`/severity vars,
  ADR-0019), we can drop the theme and point the *same* registry at our own shadcn primitives with no
  change to the card-rendering code. This is the hedge ADR-0019 wanted.

**Decided (2026-06-04):** official `@rjsf/shadcn` theme as base + thin contract-specific override
registry, as recommended above. (The earlier "no official theme; build from scratch" premise was
stale — `@rjsf/shadcn@6.6.1` is an official GA MIT rjsf-team theme.)

### D5 — Conditional-schema convention: **reveal, not require**

Conditional fields render via JSON Schema `if`/`then`/`else`, validated by `@rjsf/validator-ajv8`
(AJV 2020-12). The convention: the `then`/`else` branch adds the relevant fields' **`properties`**
(so the fields are *revealed* on toggle), not merely `required` (which leaves them always-visible and
only makes them mandatory). For Suricata, the SSH fields are **hidden until remote mode is selected**.
The schema-emitting plugin owns this shape (`SuricataConfig.json_schema_extra`); it is a schema-only
change with no collector-behavior change.

### D6 — Visual theme (SOC aesthetic) is a separate concern, deferred to a later milestone

The rjsf↔shadcn decision (D4) is the form-**rendering mechanics**, not the app's visual design. The
two are independent: shadcn/ui is not a locked look — it is component source + Tailwind design tokens
the project fully owns, so the target SOC aesthetic from `legacy/dashboard.html` (dark theme, severity
color-coding, monospace data, card layout) is reproducible by customizing Tailwind tokens over the same
shadcn primitives, with **zero change to form logic**. Therefore:

- **MA ships functional, lightly themed.** MA.4 (#33) targets correct, schema-driven behavior on the
  default shadcn tokens; a bespoke visual theme is **not** an MA exit criterion.
- **The custom SOC theme lands in a later milestone**, after Maintainer live-tests the running UI (a
  visual-feedback loop is far more reliable than deciding the look in the abstract). It restyles the
  Tailwind token set; it does not touch the schema→card pipeline or the override registry.
- **Candidate generation path: Claude Design** (Anthropic Labs, research preview — reads a codebase /
  web-captures an existing UI to build a design system and export tokens/HTML). It can ingest
  `legacy/dashboard.html` and produce a refined token set / component spec, which is then implemented in
  `frontend/` as Tailwind tokens. It is an **external, subscription-gated design tool driven by Maintainer**,
  not a build-time dependency and not something the FireWatch CI or agents invoke; its *output* (tokens,
  palette, component specs) feeds the later theming milestone. Recorded as a candidate, not a commitment.

---

## Consequences

- The repo carries two lockfiles (`uv.lock`, `frontend/package-lock.json`) and two CI jobs — expected
  for a two-language codebase; documented above as the deliberate model.
- rjsf v6 (not the v5 ADR-0019 implicitly assumed) is the target; `@rjsf/validator-ajv8` is the
  validator. No change to ADR-0019's stack decision — this is the same stack at its current version.
- Plugins must keep `config_schema()` output rjsf-v6-consumable; the Suricata reference plugin's
  `if`/`then`/`else` must reveal (add `properties`), per D5.
- Per-instance config UI (N instances per type, ADR-0016) is **out of scope** here; MA.4 is
  per-source-**type**. The config HTTP routes MA.4 adds are keyed by `type_key`.

- The **visual theme** (SOC aesthetic) is deliberately decoupled from the form mechanics (D6) and
  deferred to a post-live-test milestone; it restyles Tailwind tokens without touching card rendering.

---

## Alternatives considered

- **`frontend/` as a member of an npm/pnpm workspace spanning `packages/`** — rejected: forces the
  `uv` Python workspace to double as a JS workspace for zero build-time benefit (HTTP-only coupling).
- **Single combined CI job** — rejected: couples unrelated toolchains; a Python-only change would pay
  Node install cost and vice versa. Path-filtered peers are the standard monorepo practice.
- **`@rjsf/mui` (or Ant/Chakra) theme** — rejected (consistent with ADR-0019): fights Tailwind/shadcn
  tokens; pulls a second design system into a shadcn app.
- **Fully-custom registry over bare `@rjsf/core` (no theme)** — viable and was the orchestrator's
  lean, but now strictly more work than D4 given the official `@rjsf/shadcn` theme exists; kept as the
  documented fallback if the official theme diverges from our tokens.
- **bun / pnpm as the default PM** — deferred / escape-hatch per D2.
- **A bespoke (non-shadcn) component library / fully custom design now** — rejected for MA: shadcn +
  Tailwind tokens already reproduce the target SOC aesthetic (D6) and the custom theme is a token
  restyle that can land later without reworking forms; building a bespoke library now is cost without
  an MA payoff.
