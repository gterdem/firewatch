# ADR-0053: AI-Drafted Case File — Surface Identity, Slide-Over Seam, and Auth-Aware Note Model

**Date:** 2026-06-13
**Status:** Accepted (architect-decided under delegated authority; Maintainer approved the Analytics
Phase-0 set including B1-core + B1-polish pre-launch, and the auth-aware note requirement)

**Relates to:** ADR-0037 (entity slide-over — the host primitive), ADR-0043 (AI Engine page
identity — AI accountability), ADR-0044 (verdict ledger — the timeline/evidence substrate),
ADR-0045 (feedback store — disposition precedent), ADR-0041 (evidence chain — claim→event links),
ADR-0035 (provenance tagging — AI-drafted labeling), ADR-0026 (auth posture — note authorship
hardens here, does NOT block), ADR-0025 (DB contract — core-owned canonical tables, no plugin
DDL), ADR-0007 (SQLite), ADR-0029 (read API; D3 attacker-controlled text).
**Implements:** B1 (AI-drafted Case File) from `scratch/analytics-suggestions-opus.md`, milestone
MO. Coordinates with issue #482 (sqlite_store split).

---

## Context

FireWatch has deep *detection* (entity graph ADR-0050, narration ADR-0043, beaconing/DGA/exfil,
verdict ledger ADR-0044, feedback ADR-0045) but **no surface for the workflow that turns a
detection into a documented conclusion** — the analyst's "what happened, what I checked, what I
decided." Every SIEM ships case management (universal; even lean Security Onion via Sguil). Its
absence is the most conspicuous workflow hole, and it is the natural home for the local-LLM
summarization that is FireWatch's standout differentiator: **the AI drafts, the human owns,
provenance is honest, and case notes never leave the box** — a privacy story cloud copilots
(Security Copilot, Charlotte AI) structurally cannot match.

Two decisions must be settled before B1 is implementable: (1) **where the Case File lives** —
the 5-tab nav is fixed, no 6th tab; (2) **how note authorship works before auth (ADR-0026)
lands**, so auth slots in with zero rework.

## Decision

### D1 — Surface identity & seam: a Case File slide-over launched from the AI Engine tab

The Case File is **not a new tab**. It is a **slide-over surface** hosted by the ADR-0037 entity
slide-over shell, opened from the **AI Engine** tab (ADR-0043) and from any entity/verdict
context via an "Open case" action.

- **Why AI Engine, not the entity slide-over generically:** the AI Engine page's identity is
  *AI accountability* (ADR-0043 — "every verdict, what the model saw, proof nothing left this
  box"). The Case File **is** that accountability artifact taken to its conclusion: an AI-drafted,
  human-owned, evidence-linked record of an investigation. It belongs to the same surface that
  owns verdict cards, the evidence chain, and the zero-egress strip. A verdict card gets an
  "Open case" affordance; the case opens in the slide-over with the verdict's evidence already
  threaded in.
- **Reuse the slide-over, do not build a parallel panel.** ADR-0037's shell is already
  entity-typed (`{kind, value}`, `kind` extensible from day one). Add **`kind: "case"`**
  (`{kind: "case", value: caseId}`). The slide-over's overlay semantics, focus trap, pivot
  breadcrumb, and "text nodes only" XSS posture (ADR-0029 D3 — case content is partly
  attacker-derived event data) are inherited unchanged. A case opened from an entity pushes onto
  the existing nav stack (IP → case → related event), so investigation context is never lost.

### D2 — Case File composition (the surface, top to bottom)

1. **Header:** case id, title, status/disposition chip (`true-positive` / `false-positive` /
   `benign` / `open`), created/updated timestamps.
2. **Timeline:** related events/alerts assembled from the verdict ledger (ADR-0044) and the
   evidence chain (ADR-0041) — chronological, each row linking to its source event/verdict. The
   timeline is **recomputed/assembled at read time** from canonical tables (ADR-0041 discipline);
   the case stores *references*, not denormalized copies.
3. **Notes:** analyst-editable markdown notes, each with `author` + `created_at` (D3 below).
   Rendered as text/sanitized markdown — no raw HTML injection.
4. **AI-drafted summary (B1-polish):** a one-click local-LLM draft summary, reusing the shipped
   ML-7 narration path (ADR-0043, `/threats/{ip}/narration` adapter), explicitly **labeled
   AI-drafted** (`AI` chip, ADR-0035), with every claim linked back to verdict-ledger evidence
   (ADR-0041). The analyst **edits and owns** the result — the edited text is the source of
   truth, stored as a note authored by the operator; the original AI draft retains its `AI`
   provenance. On-box / zero-egress (ADR-0022/0047). Drafting is **suggest-only** — no auto-close,
   no auto-disposition (mirrors ADR-0015's suggest tier; the human decides).

### D3 — Auth-aware note model from day one (zero-migration auth seam)

Case notes store an **`author` TEXT column populated with `"local operator"` today**, and with
real identity once ADR-0026 (auth) is implemented — **no schema change, no data migration**.

- B1 ships now in the loopback single-operator posture with `author = "local operator"`.
- When auth lands, the API populates `author` from the authenticated principal; existing rows keep
  their honest `"local operator"` provenance. This is the same additive-column discipline ADR-0039
  used for ASN fields (`ALTER TABLE … ADD COLUMN`, `None`/default for old rows) — here the column
  exists from the first migration, so even that is unnecessary.
- **B1 does NOT block on auth.** Only the deferred audit log (B3, out of scope for MO) is
  hard-blocked on ADR-0026 — an audit trail of one local operator is empty theater until
  multi-user identity exists.

### D4 — Storage: a `cases` subpackage mirroring the `ledger` subpackage

A new core-owned canonical store (ADR-0025) under
`packages/firewatch-core/src/firewatch_core/adapters/cases/`, structured exactly like the proven
`adapters/ledger/` package (schema · store · caps):

```
adapters/cases/
  __init__.py
  schema.py        # CREATE TABLE DDL + apply_schema(db) — caller owns the connection (ADR-0023 §F)
  sqlite_cases.py  # SqliteCaseStore — CRUD for case_files / case_notes / case_events
  caps.py          # per-case note/event caps + note-length cap (mirrors ledger/caps.py)
```

Tables (DDL sketch — implementer refines):

```
case_files(  id PK, title, status, disposition, created_at, updated_at )
case_notes(  id PK, case_id FK→case_files ON DELETE CASCADE,
             author TEXT NOT NULL DEFAULT 'local operator',   -- D3 auth seam
             body_md TEXT NOT NULL, ai_drafted INTEGER NOT NULL DEFAULT 0,  -- ADR-0035 provenance
             created_at, updated_at )
case_events( id PK, case_id FK→case_files ON DELETE CASCADE,
             ref_kind TEXT, ref_id TEXT, created_at )   -- references to ledger/events, NOT copies (ADR-0041)
```

- **Coordinate with #482** (the `sqlite_store.py` split into `adapters/sqlite/`). The case store
  is a **sibling subpackage**, not a member of the store-split — it owns its own tables and follows
  the ledger precedent, so it does not depend on #482 landing and does not enlarge #482's blast
  radius. It shares the loop-bound aiosqlite connection via the same connection-holder pattern the
  ledger uses (ADR-0023 §F — single-owner connection lifecycle).

## Alternatives considered

- **Case File off the entity slide-over generically (not tied to AI Engine)** — coherent, but it
  scatters the AI-accountability story across surfaces. The Case File's distinctive value is the
  *glass-box AI-drafted, human-owned* summary; anchoring it to the AI Engine identity (ADR-0043)
  keeps that story whole. We still reuse the slide-over *shell*, so we get both.
- **A 6th nav tab** — rejected: the 5-tab nav is fixed (ADR-0043 context, Maintainer).
- **Block B1 on auth (ADR-0026)** — rejected: the auth-aware `author` column lets B1 ship now and
  harden later with zero rework; blocking would stall the highest-leverage pre-launch differentiator.
- **Reuse the `ai_feedback`/`anomaly_verdicts` tables for disposition** — insufficient: a case is a
  first-class multi-note, multi-event aggregate with its own lifecycle, not a per-verdict judgment.
  A dedicated store is warranted; it reuses the *ledger as input* (timeline/evidence), not its schema.

## Reasoning

B1 is "assemble existing pieces into a workflow," not new ML: the verdict ledger (ADR-0044) is the
timeline substrate, the evidence chain (ADR-0041) is the claim→event link, narration (ADR-0043) is
the draft generator, the slide-over (ADR-0037) is the host, and provenance tagging (ADR-0035) keeps
the AI-drafted/human-owned boundary honest. Hosting it on the AI Engine surface makes the
accountability story coherent; the auth-aware note column makes auth a zero-cost future drop-in;
the `cases` subpackage follows the ledger precedent so the structure is proven, not invented.
On-box / zero-egress throughout — the launch headline ("glass-box case summarization") no incumbent
can honestly claim.
