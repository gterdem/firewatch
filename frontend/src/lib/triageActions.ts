/**
 * triageActions — the UI action seam (ADR-0033).
 *
 * Exposes a single stable entrypoint:
 *
 *   onAction(actor: ThreatScore, verb: ThreatActionVerb) => void | Promise<void>
 *
 * All triage UI components (triage banner, recommendation cards, drill-down)
 * receive `onAction` as a prop and call it. They hold NO per-verb logic.
 *
 * SIEM behaviour (ADR-0033 § "What the seam does in MF"):
 *   investigate → open the entity slide-over for the actor's IP (ADR-0037, issue #204)
 *   expected    → "Expected — this is me" (issue #45, ADR-0072 D6): persisted
 *                 server-side as an `expected` decision — actor-identity
 *                 suppression (fail2ban `ignoreip` precedent, ADR-0070 D6).
 *   dismiss     → resolve/close the actor — persisted server-side as a
 *                 `dismissed` decision (ADR-0072, issue #47). Queue membership
 *                 (suppression) is computed server-side and read via
 *                 `lib/triageDecisions.ts`'s `isSuppressed` — this seam does
 *                 NOT decide suppression, it only records the operator's verb.
 *   harden      → advice-only (issue #45, ADR-0033): NO server call, NO
 *                 execution. The UI surfaces `escalationCopy.ts`'s
 *                 `HARDEN_ADVICE` text; the seam exists so a future
 *                 SOAR-adjacent flow can hook in without component changes.
 *   block       → record the block *decision* / raise the alert (NOT execute
 *                 enforcement) — persisted the same way as `dismiss` (the
 *                 server-side vocabulary has no separate "block" verb; ADR-0072
 *                 D6's three verbs are expected/dismissed/false_positive).
 *
 * `false_positive` is deliberately NOT a `ThreatActionVerb` (ADR-0072 D6,
 * issue #45 O-1): it targets a (actor, rule) pair, not the actor, and lives on
 * the entity-panel detection row, never the actor card. See
 * `recordFalsePositive` below — called directly from the detection-row UI,
 * bypassing this actor-scoped seam.
 *
 * SOAR execution (ADR-0033 § "What plugs in later"):
 *   A future SOAR milestone supplies the enforcement executor behind verb === "block".
 *   It binds here — no triage-UI component changes when it lands.
 *   The single wire-in point is the `block` branch of `makeOnAction`, AFTER
 *   the existing decision-record step.
 *
 * Persistence (ADR-0072, issue #47; #45 adds `expected`):
 *   `dismiss`/`block` persist a `dismissed` decision; `expected` persists an
 *   `expected` decision — both via `POST /decisions` (api/decisions.ts). The
 *   server computes and stores the tier/score snapshot; this seam never
 *   self-reports them. Persistence is best-effort: a failed POST is logged
 *   and swallowed (this stays a SIEM record/alert action, not a blocking one
 *   — ADR-0015 additive-only precedent). `harden` persists nothing (advice
 *   only — see above).
 *
 *   The pre-#47 localStorage implementation (isDismissed/reconcileAcknowledged/
 *   hasMaterialChange/acknowledge, issues #727/#755) is RETIRED — see
 *   ADR-0072 D7's retire list. The one-shot migration reader and the
 *   queue-membership predicate now live in `lib/triageDecisions.ts`.
 *
 * `acknowledge` is RETIRED (ADR-0072 D6, maintainer ruling): its "suppress
 * now, re-surface on material change" semantics are subsumed by
 * `expected`/`dismissed` + server-side re-entry (#56). It is no longer part
 * of `ThreatActionVerb`.
 *
 * References: NIST SP 800-61r2 (Detection & Analysis phase), ADR-0015 (tiered autonomy),
 * ADR-0033 (this seam), ADR-0037 (entity slide-over), ADR-0026 (auth posture),
 * ADR-0072 (server-side triage decisions).
 */

import { createDecision } from '../api/decisions'
import type { ThreatScore } from '../api/types'
import type { EntityRef } from '../components/entity/EntityPanelContext'

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/**
 * The triage verbs exposed by the action seam.
 * `acknowledge` is retired (ADR-0072 D6) — removed from this union.
 * `expected` and `harden` added by issue #45 (ADR-0072 D6 queue-card
 * vocabulary). `false_positive` is intentionally NOT here — it is
 * rule-scoped, not actor-scoped (see the module doc's `recordFalsePositive`
 * note) and is called directly from the detection-row UI, not this seam.
 */
export type ThreatActionVerb = 'block' | 'investigate' | 'dismiss' | 'expected' | 'harden'

/**
 * The `onAction` function signature.
 * Components receive this as a prop; the container (Dashboard route) supplies
 * the implementation via `makeOnAction`.
 *
 * Returns `void | Promise<void>` — `dismiss`/`block` return a promise for the
 * server persistence call; callers are not required to await it (fire-and-forget
 * from an onClick handler is the common case).
 */
export type OnAction = (actor: ThreatScore, verb: ThreatActionVerb) => void | Promise<void>

// ---------------------------------------------------------------------------
// N-2: IP-format guard (defense-in-depth for the SOAR executor, issue #171)
//
// Validates that a string looks like a plausible IPv4 or IPv6 address before
// it is used as a Set key or flows into entity-panel state.
//
// IPv4: four decimal octets 0-255 separated by dots.
// IPv6: standard colon-hex notation, including compressed forms (::).
//
// This is a shape check, not a full RFC 791/RFC 4291 semantic validator.
// encodeURIComponent already neutralizes URL injection downstream; this guard
// prevents arbitrarily long or structurally bizarre strings from being stored
// as set keys (defense-in-depth for the forthcoming SOAR executor, ADR-0033).
// ---------------------------------------------------------------------------

const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/
const IPV6_RE = /^[0-9a-fA-F:]+$/

/**
 * Returns true when `ip` has the shape of an IPv4 or IPv6 address.
 * Exported for unit-testing.
 */
export function isValidIpFormat(ip: string): boolean {
  if (IPV4_RE.test(ip)) return true
  // IPv6: must contain at least one colon and consist only of hex digits and colons.
  if (ip.includes(':') && IPV6_RE.test(ip)) return true
  return false
}

// ---------------------------------------------------------------------------
// Server-side decision persistence (ADR-0072, issue #47)
// ---------------------------------------------------------------------------

/**
 * Persist a `dismissed` decision for `actor` via `POST /decisions`
 * (ADR-0072 D3). Best-effort: a failed request is logged and swallowed — the
 * seam is a SIEM record/alert action, not a blocking one (ADR-0015).
 *
 * Both the `dismiss` and `block` UI verbs map to this same server-side verb:
 * ADR-0072's store vocabulary is `expected | dismissed | false_positive`
 * (D6) — there is no separate "block" row. `block`'s future SOAR wire-in
 * (see the `block` branch below) executes AFTER this persistence step.
 */
async function persistDismissed(actor: ThreatScore): Promise<void> {
  try {
    await createDecision({ actor_ip: actor.source_ip, verb: 'dismissed' })
  } catch (err) {
    console.warn('[triageActions] failed to persist dismissed decision:', err)
  }
}

/**
 * Persist an `expected` decision for `actor` via `POST /decisions`
 * (ADR-0072 D3, issue #45). Best-effort — same swallow-and-log contract as
 * `persistDismissed`. Actor-identity scoped (fail2ban `ignoreip` precedent,
 * ADR-0070 D6): suppresses all queue entries for this actor, not just the
 * one currently shown.
 */
async function persistExpected(actor: ThreatScore): Promise<void> {
  try {
    await createDecision({ actor_ip: actor.source_ip, verb: 'expected' })
  } catch (err) {
    console.warn('[triageActions] failed to persist expected decision:', err)
  }
}

/**
 * Record a `false_positive` decision for a single (actor, rule) pair
 * (ADR-0072 D2/D4, issue #45 O-1). Deliberately NOT part of the
 * `ThreatActionVerb` seam — it targets a rule, not the actor, and is called
 * directly from the entity-panel detection-row UI (the "detection targets a
 * rule" placement rule, D6).
 *
 * Best-effort, same swallow-and-log contract as the other persistence
 * helpers here — a failed POST must not break the entity panel.
 *
 * `ruleName` must be a non-empty string identity (the raw event's
 * `rule_name`, e.g. `SecurityEvent.rule_name` echoed back on the stored log
 * row) — the caller is responsible for only surfacing this action when such
 * an identity exists (ADR-0072's fail-toward-visibility boundary: an
 * anonymous/rule-less detection can never be FP-suppressed).
 */
export async function recordFalsePositive(actorIp: string, ruleName: string): Promise<void> {
  if (!isValidIpFormat(actorIp) || ruleName === '') return
  try {
    await createDecision({ actor_ip: actorIp, verb: 'false_positive', rule_name: ruleName })
  } catch (err) {
    console.warn('[triageActions] failed to persist false_positive decision:', err)
  }
}

// ---------------------------------------------------------------------------
// SIEM implementation factory
//
// `makeOnAction` builds the concrete implementation for a page container.
// The container passes its `openEntity` function and optional callbacks
// so it can re-render after an action.
//
// Parameters:
//   openEntity — from useEntityActions().openEntity; used for `investigate`
//   onDismiss  — optional callback called after `dismiss` (e.g. a toast)
//   onBlock    — optional callback called after `block` records the decision
// ---------------------------------------------------------------------------

export interface OnActionCallbacks {
  /**
   * Opens the entity slide-over for the given ref (ADR-0037).
   * Used by the `investigate` verb — replaces the old navigate-to-drill-down.
   * Container (DashboardRoute) supplies this from useEntityPanel().openEntity.
   */
  openEntity: (ref: EntityRef) => void
  /**
   * @deprecated navigate is no longer used by `investigate` (switched to openEntity
   * per ADR-0037 / issue #204). Kept here for backward-compat in tests that still
   * pass it; it is ignored. Will be removed in a future clean-up.
   */
  navigate?: (path: string) => void
  onDismiss?: (actor: ThreatScore) => void
  onBlock?: (actor: ThreatScore) => void
  /** Optional callback called after `expected` records the decision (issue #45). */
  onExpected?: (actor: ThreatScore) => void
  /**
   * Optional callback called when `harden` fires (issue #45). ADR-0033:
   * advice-only — this callback is for UI feedback (e.g. showing the
   * `HARDEN_ADVICE` copy) only; it must never trigger an execution path.
   */
  onHarden?: (actor: ThreatScore) => void
}

/**
 * Creates the `onAction` SIEM implementation.
 *
 * This is the ONE place a future SOAR executor is wired in behind `block`.
 * To add enforcement: extend the `block` branch with the executor call AFTER
 * the existing decision-record step — no component changes needed.
 */
export function makeOnAction(callbacks: OnActionCallbacks): OnAction {
  return function onAction(actor: ThreatScore, verb: ThreatActionVerb): void | Promise<void> {
    // N-2 (issue #171): guard source_ip format before any use.
    // encodeURIComponent already neutralizes URL injection; this is defense-in-depth
    // for the SOAR executor. Invalid IPs are silently dropped — no throw.
    if (!isValidIpFormat(actor.source_ip)) {
      console.warn('[triageActions] source_ip failed IP-format guard — action dropped:', verb)
      return
    }

    switch (verb) {
      case 'investigate': {
        // MH (issue #204): open the entity slide-over for this IP (ADR-0037).
        // Dashboard stays visible behind the panel — no route navigation occurs.
        callbacks.openEntity({ kind: 'ip', value: actor.source_ip })
        return
      }

      case 'expected': {
        // "Expected — this is me" (issue #45, ADR-0072 D6): actor-identity
        // suppression, fail2ban `ignoreip` precedent (ADR-0070 D6). Persisted
        // server-side; suppression is computed at read time by the server —
        // this seam does not mutate any local state.
        callbacks.onExpected?.(actor)
        return persistExpected(actor)
      }

      case 'harden': {
        // Advice-only (issue #45, ADR-0033): NO persistence, NO execution.
        // The caller (UI) is responsible for surfacing HARDEN_ADVICE copy;
        // this seam only exists so a future flow can hook in without any
        // component change. Must-NOT (ADR-0033): this branch performs no
        // network call and no side effect beyond the optional callback.
        callbacks.onHarden?.(actor)
        return
      }

      case 'dismiss': {
        // SIEM: resolve/close the actor. Persisted server-side (ADR-0072,
        // issue #47) — queue suppression is computed at read time from this
        // decision by the server; this seam does not mutate any local state.
        callbacks.onDismiss?.(actor)
        return persistDismissed(actor)
      }

      case 'block': {
        // SIEM: record the block *decision* / raise the alert.
        // ADR-0033: "mark the actor as 'operator decided to block'"
        // This is ADR-0015 "Suggest" tier — AI recommends Block, analyst confirms
        // → FireWatch records/alerts; enforcement is the future SOAR executor.
        //
        // *** SOAR WIRE-IN POINT ***
        // When the SOAR milestone lands: add the responder-port call here,
        // after the existing decision-record step, with ADR-0015 guardrails
        // (allowlist, rate cap, TTL) and confirm+undo+audit UX. Zero component
        // changes needed.
        callbacks.onBlock?.(actor)
        return persistDismissed(actor) // also consumes the actor's queue entry
      }

      default: {
        // Exhaustive — TypeScript enforces this at compile time via the union type.
        const _exhaustive: never = verb
        console.warn('[triageActions] unknown verb:', _exhaustive)
      }
    }
  }
}
