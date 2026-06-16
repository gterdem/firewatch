# ADR-0033: The UI Action Seam — `onAction(actor, verb)` (SIEM Alerting Now, SOAR Execution Later)

**Date:** June 2026
**Status:** Accepted

**Context:** The SOC Design System v2 (the Phase-3 kit, applied as milestone MF) makes the
dashboard *triage-first*: it leads with a banner ("N actors need a BLOCK decision") and renders
**actionable recommendation cards** with **Block / Investigate / Dismiss** buttons against each
threat actor. Two questions fall out of that: (1) what do those buttons *do* today, and (2) how do
we avoid re-working the entire triage UI when FireWatch later grows the ability to *execute* a block
(push an IP to an upstream firewall / blocklist)? This ADR fixes the seam between the two so the UI
is built once.

The distinction is the long-settled industry split between **SIEM** (detect, correlate, alert,
record the analyst's decision) and **SOAR** (orchestrate and *execute* the response). NIST SP
800-61r2 frames incident response as Detection & Analysis → Containment/Eradication/Recovery → Post-
Incident; the triage card's Block/Investigate/Dismiss verbs live in *Detection & Analysis* (deciding
and recording), while *executing* containment is a later, higher-privilege capability. FireWatch's
own ADR-0015 already encodes exactly this as tiered autonomy (Suggest → One-click approve →
Conditional auto), with full autonomy deferred for documented AI-safety reasons. This ADR is the
*UI-layer* expression of that boundary.

**Decision:** All triage actions flow through a **single, stable action seam**:

```
onAction(actor: ThreatActor, verb: "block" | "investigate" | "dismiss") => void | Promise<void>
```

- **One hook, three verbs.** Every Block / Investigate / Dismiss button — on the dashboard triage
  cards, the recommendation cards, and (where it appears) the drill-down — calls this one function.
  Components never branch on "is SOAR installed"; they only emit `(actor, verb)`.
- **What the seam does in MF (SIEM behavior — ships now):**
  - `investigate` → open the IP drill-down (navigate to the existing detailed view). Read-only.
  - `dismiss` → acknowledge/resolve the actor in the triage queue (record the analyst's decision;
    remove it from the "needs a decision" banner count). No external side effect.
  - `block` → **record a block *decision*** (mark the actor as "operator decided to block" /
    raise the alert), **not** execute it. This is SIEM alerting + decision capture, matching
    ADR-0015's "Suggest" tier ("AI recommends Block, user clicks to apply" — where "apply" today
    means *record/alert*, not *enforce*).
- **What plugs in later (SOAR execution — Out of scope here):** a future SOAR milestone
  (un-milestoned; see ADR-0015) supplies the *executor* behind `verb === "block"` — the responder
  port that actually pushes the IP to a firewall/blocklist, with ADR-0015's guardrails (allowlist,
  rate cap, TTL, confirm + undo + audit). **It binds to the same `onAction` hook.** No triage-UI
  component changes when it lands; only the seam's `block` implementation gains an execution step
  behind the decision-record.
- **The seam is owned by the page container, not the card.** Cards/banners are presentational and
  receive `onAction` as a prop. The container (Dashboard route) holds the single implementation, so
  the SIEM→SOAR upgrade is a one-file change at the container, not a sweep across every card.

**Module shape (sketch — for the MF implementer):**
- `frontend/src/lib/triageActions.ts` — the seam: the `ThreatAction` verb type, the
  `onAction(actor, verb)` signature, and the MF (SIEM) implementation (`investigate` → navigate;
  `dismiss` → acknowledge; `block` → record-decision/alert). The single place a future SOAR executor
  is wired in behind `block`.
- Triage banner + recommendation cards take `onAction` as a prop; they hold **no** policy and **no**
  per-verb side-effect logic of their own.
- Buttons are real, focusable, labeled controls (a11y, per #67); the destructive affordance
  (confirm + undo + audit) is deferred to the SOAR executor and is **not** built in MF.

**Alternatives considered:**
- **Per-verb callbacks (`onBlock` / `onInvestigate` / `onDismiss`) threaded separately** — rejected:
  three props to plumb through every card, and adding the SOAR executor later means touching every
  call site. One `(actor, verb)` hook keeps the surface stable as behavior grows.
- **Build the real block executor now (skip the seam, do SOAR in MF)** — rejected: violates the
  ADR-0015 tiered-autonomy posture (executing blocks is the high-risk tier, gated behind guardrails
  and a deliberate decision), and SOAR scope (responder port, allowlist/rate/TTL policy, audit, undo)
  is far larger than a UI restyle. Deferring keeps MF a UI milestone.
- **Make the buttons inert placeholders (no decision recorded)** — rejected: the triage banner's
  whole value is the *SIEM* decision-and-alert loop (acknowledge/dismiss/raise), which is real,
  shippable behavior today and does not need SOAR. Inert buttons would ship a non-functional banner.

**Reasoning:** This is the smallest commitment that lets MF build the triage surface *once*. SIEM
alerting (correlate → surface → let the analyst decide/dismiss/record) is genuinely useful with zero
execution capability, and it is exactly the behavior NIST's *Detection & Analysis* phase and
ADR-0015's *Suggest* tier describe. By pinning a single `(actor, verb)` seam now, the later SOAR
executor (the responder port, ADR-0015 guardrails) drops in behind one function with **zero triage-UI
rework** — the same modularity discipline the platform applies to source plugins, applied to the
response side. The OCSF event model is response-action-agnostic at the read surface, so no canonical-
schema change is implied by recording a block *decision*.

**Out of scope (this ADR):**
- **SOAR execution** — the responder port that actually enforces a block (firewall/blocklist push),
  its guardrails (allowlist, rate cap, TTL, protected-asset list), and the confirm/undo/audit UX.
  That is a future SOAR milestone (un-milestoned; anchored on ADR-0015). This ADR commits only the
  *seam*, not the executor.
- The ADR-0015 autonomy *tiers* themselves (Suggest / approve / conditional-auto policy) — settled
  there; this ADR only fixes where the UI hooks into them.
- Any change to the canonical `SecurityEvent` / read API. The MF SIEM verbs are UI-local
  (navigate / acknowledge / record); persisting a decision, if/when needed, is a later additive
  concern, not part of this seam contract.

**References / standards consulted:**
- NIST SP 800-61r2, *Computer Security Incident Handling Guide* — IR lifecycle (Detection & Analysis
  vs Containment) that places "decide/record" before "execute".
- OCSF (Open Cybersecurity Schema Framework) — read/event model is response-action-agnostic; no
  schema change implied by recording a block decision.
- ADR-0015 (Tiered Autonomy for Active Response) — the responder/SOAR anchor; this seam is its
  UI-layer expression. ADR-0026 (auth posture) — any future execution write path inherits the
  fail-closed / gate-writes-≥-reads constraint.
- Industry SIEM-vs-SOAR distinction (alerting/decision vs orchestrated execution) as the framing for
  shipping triage now and execution later behind one hook.
