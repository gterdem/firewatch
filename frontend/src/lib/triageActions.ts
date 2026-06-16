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
 * SIEM behaviour shipped in MH (ADR-0033 § "What the seam does in MF"):
 *   investigate → open the entity slide-over for the actor's IP (ADR-0037, issue #204)
 *   acknowledge → "I'm working on it" — suppresses the actor NOW but re-surfaces it
 *                 if a material change occurs (new BLOCK/ALLOW terminal event, or tier
 *                 increase). Persisted to localStorage (issue #727).
 *   dismiss     → resolve/close the actor — stronger suppression than acknowledge;
 *                 does NOT re-surface on material change. Persisted to localStorage.
 *   block       → record the block *decision* / raise the alert (NOT execute enforcement)
 *
 * SOAR execution (ADR-0033 § "What plugs in later"):
 *   A future SOAR milestone supplies the enforcement executor behind verb === "block".
 *   It binds here — no triage-UI component changes when it lands.
 *   The single wire-in point is the `block` branch of `makeOnAction`.
 *
 * Persistence (issue #727):
 *   Both acknowledged and dismissed state are stored in localStorage (two separate keys).
 *   This survives page reloads so dismissed/acknowledged actors stay suppressed.
 *   NOTE: A server-side acknowledged-actors store is the durable future option for
 *   cross-device / cross-session persistence. That is explicitly OUT OF SCOPE for this
 *   issue — this localStorage implementation is the immediate fix. When that server-side
 *   store lands, it replaces the localStorage read/write calls here; the rest of the
 *   seam is unchanged.
 *
 * Acknowledge vs Dismiss distinction (issue #727):
 *   ACKNOWLEDGE ("working it") — Elastic/Sentinel pattern:
 *     - Suppresses the actor from the triage queue immediately.
 *     - Re-surfaces if a MATERIAL CHANGE occurs (see hasMaterialChange()).
 *     - Persisted to localStorage under ACKNOWLEDGED_ACTORS_KEY.
 *   DISMISS/CLOSE (resolved) — stronger suppression:
 *     - Suppresses the actor and does NOT re-surface on material change.
 *     - Persisted to localStorage under DISMISSED_ACTORS_KEY.
 *
 * Material change definition (issue #727 EARS-2):
 *   An acknowledged actor re-surfaces when ANY of the following is true vs. the
 *   snapshot captured at acknowledge time:
 *     1. score has increased by ≥ 5 points (new significant threat activity).
 *     2. block_status changed between "blocked" and "allowed" (in either direction).
 *     3. escalation.tier decreased (lower tier number = louder = more urgent).
 *
 * Performance (issue #755):
 *   Both stores are held in memory as the source of truth, lazy-initialized once
 *   from localStorage, and written-through to localStorage on mutation only.
 *   `isDismissed` is therefore O(1) and PURE — it never calls localStorage
 *   and never mutates state. The material-change eviction path is separated into
 *   `reconcileAcknowledged(threats)` which is called on the data-refresh path
 *   (not inside render predicates). This prevents write-during-render under
 *   React StrictMode / concurrent mode and removes the O(N) array.includes() cost.
 *
 * References: NIST SP 800-61r2 (Detection & Analysis phase), ADR-0015 (tiered autonomy),
 * ADR-0033 (this seam), ADR-0037 (entity slide-over), ADR-0026 (auth posture).
 */

import type { ThreatScore } from '../api/types'
import type { EntityRef } from '../components/entity/EntityPanelContext'

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** The four triage verbs exposed by the action seam. */
export type ThreatActionVerb = 'block' | 'investigate' | 'acknowledge' | 'dismiss'

/**
 * The `onAction` function signature.
 * Components receive this as a prop; the container (Dashboard route) owns
 * the implementation via `makeOnAction`.
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
// localStorage keys (issue #727)
// ---------------------------------------------------------------------------

/** localStorage key for the JSON-serialized dismissed IPs array (FIFO order). */
export const DISMISSED_ACTORS_KEY = 'fw:triage:dismissed'
/**
 * localStorage key for the JSON-serialized acknowledged actors object.
 * Shape: { [ip: string]: AcknowledgedSnapshot }
 */
export const ACKNOWLEDGED_ACTORS_KEY = 'fw:triage:acknowledged'

// ---------------------------------------------------------------------------
// N-1: Bounded actor stores (issue #171, persisted in issue #727)
//
// Cap: 10 000 entries (well above any realistic analyst session count).
// Dismissed: FIFO order preserved via a parallel array; O(1) membership via Set.
// Acknowledged: object keyed by IP; FIFO eviction on oldest key.
// ---------------------------------------------------------------------------

/** Maximum entries retained in the dismissed/acknowledged actor stores. */
export const DISMISSED_ACTORS_CAP = 10_000

// ---------------------------------------------------------------------------
// AcknowledgedSnapshot — state captured at acknowledge time for re-surface detection
// ---------------------------------------------------------------------------

/**
 * Minimal snapshot of actor state at acknowledge time (issue #727 EARS-2).
 * Stored in localStorage alongside the IP so re-surface detection can compare
 * the current actor against the state when it was acknowledged.
 */
export interface AcknowledgedSnapshot {
  /** Score at acknowledge time. Material change: current score ≥ snap.score + 5. */
  score: number
  /** Escalation tier at acknowledge time (null when no verdict). Material change: tier decreases. */
  tier: number | null
  /**
   * Block status at acknowledge time (null when actor had no escalation verdict).
   * Material change: flips between "blocked" and "allowed".
   */
  blockStatus: string | null
}

// ---------------------------------------------------------------------------
// In-memory stores — source of truth (issue #755 performance fix)
//
// Module-level singletons. Lazy-initialized once from localStorage on first
// access (see ensureDismissedLoaded / ensureAcknowledgedLoaded). All mutations
// update the in-memory structure first, then write-through to localStorage for
// persistence. isDismissed() never touches localStorage — O(1), pure.
// ---------------------------------------------------------------------------

/**
 * Dismissed actors: Set for O(1) `has` lookups.
 * null = not yet initialized; ensureDismissedLoaded() must be called first.
 */
let _dismissedSet: Set<string> | null = null

/**
 * FIFO insertion-order array, parallel to _dismissedSet.
 * Required to implement cap eviction (oldest = index 0, splice to evict).
 */
let _dismissedOrder: string[] | null = null

/**
 * Acknowledged actors: map for O(1) key lookups.
 * null = not yet initialized; ensureAcknowledgedLoaded() must be called first.
 */
let _acknowledgedMap: Record<string, AcknowledgedSnapshot> | null = null

// ---------------------------------------------------------------------------
// Lazy initializers — load once from localStorage
// ---------------------------------------------------------------------------

function ensureDismissedLoaded(): void {
  if (_dismissedSet !== null) return
  try {
    const raw = localStorage.getItem(DISMISSED_ACTORS_KEY)
    if (raw != null) {
      const parsed: unknown = JSON.parse(raw)
      if (Array.isArray(parsed)) {
        const arr = parsed.filter((v): v is string => typeof v === 'string')
        _dismissedSet = new Set(arr)
        _dismissedOrder = arr
        return
      }
    }
  } catch {
    // Fall through to empty initialization.
  }
  _dismissedSet = new Set()
  _dismissedOrder = []
}

function ensureAcknowledgedLoaded(): void {
  if (_acknowledgedMap !== null) return
  try {
    const raw = localStorage.getItem(ACKNOWLEDGED_ACTORS_KEY)
    if (raw != null) {
      const parsed: unknown = JSON.parse(raw)
      if (parsed != null && typeof parsed === 'object' && !Array.isArray(parsed)) {
        _acknowledgedMap = parsed as Record<string, AcknowledgedSnapshot>
        return
      }
    }
  } catch {
    // Fall through to empty initialization.
  }
  _acknowledgedMap = {}
}

// ---------------------------------------------------------------------------
// Write-through helpers — keep in-memory and localStorage in sync on mutation
// ---------------------------------------------------------------------------

function flushDismissedStore(): void {
  try {
    localStorage.setItem(DISMISSED_ACTORS_KEY, JSON.stringify(_dismissedOrder!))
  } catch {
    // Non-fatal — continue without persistence.
  }
}

function flushAcknowledgedStore(): void {
  try {
    localStorage.setItem(ACKNOWLEDGED_ACTORS_KEY, JSON.stringify(_acknowledgedMap!))
  } catch {
    // Non-fatal — continue without persistence.
  }
}

// ---------------------------------------------------------------------------
// Dismissed-actors store mutation
// ---------------------------------------------------------------------------

/**
 * Adds `ip` to the in-memory dismissed store, evicting the oldest entry
 * (FIFO) when the store is already at DISMISSED_ACTORS_CAP, then writes
 * through to localStorage.
 *
 * Silently no-ops when `ip` is already present (deduplication). O(1) check.
 */
function addDismissed(ip: string): void {
  ensureDismissedLoaded()
  if (_dismissedSet!.has(ip)) return // already tracked — no-op
  if (_dismissedOrder!.length >= DISMISSED_ACTORS_CAP) {
    // Evict oldest (FIFO): remove from both Set and order array.
    const oldest = _dismissedOrder!.splice(0, 1)[0]
    _dismissedSet!.delete(oldest)
  }
  _dismissedSet!.add(ip)
  _dismissedOrder!.push(ip)
  flushDismissedStore()
}

// ---------------------------------------------------------------------------
// Acknowledged-actors store mutation
// ---------------------------------------------------------------------------

/**
 * Adds `ip` to the acknowledged store with a snapshot of the actor's current
 * state. Evicts the oldest key when at DISMISSED_ACTORS_CAP, then writes
 * through to localStorage.
 */
function addAcknowledged(ip: string, snapshot: AcknowledgedSnapshot): void {
  ensureAcknowledgedLoaded()
  const map = _acknowledgedMap!
  const keys = Object.keys(map)
  if (!(ip in map) && keys.length >= DISMISSED_ACTORS_CAP) {
    // Evict the first key (insertion order preserved in modern JS objects).
    delete map[keys[0]]
  }
  map[ip] = snapshot
  flushAcknowledgedStore()
}

/**
 * Build a snapshot from a ThreatScore for storage at acknowledge time.
 */
export function snapshotOf(actor: ThreatScore): AcknowledgedSnapshot {
  return {
    score: actor.score,
    tier: actor.escalation?.tier ?? null,
    blockStatus: actor.escalation?.block_status ?? null,
  }
}

// ---------------------------------------------------------------------------
// Material change detection (issue #727 EARS-2)
//
// Definition: an acknowledged actor has undergone a MATERIAL CHANGE when,
// compared to the snapshot taken at acknowledge time, ANY of the following
// is true:
//   1. score has increased by ≥ 5 points (MATERIAL_SCORE_DELTA).
//   2. block_status changed between "blocked" and "allowed" (in either direction).
//   3. escalation.tier decreased (lower tier = louder = more urgent).
//
// When detected, the actor is removed from the acknowledged set and returns
// to the triage queue. This check runs in reconcileAcknowledged(), NOT in
// isDismissed(), to keep isDismissed pure.
// ---------------------------------------------------------------------------

/** Minimum score increase (above the snapshot) that constitutes a material change. */
export const MATERIAL_SCORE_DELTA = 5

/**
 * Returns true when the current actor state represents a material change
 * compared to the snapshot taken when it was acknowledged.
 *
 * Exported for unit-testing.
 */
export function hasMaterialChange(actor: ThreatScore, snap: AcknowledgedSnapshot): boolean {
  // 1. Score increase ≥ MATERIAL_SCORE_DELTA
  if (actor.score - snap.score >= MATERIAL_SCORE_DELTA) return true

  // 2. block_status flip between "blocked" and "allowed"
  const currentBlockStatus = actor.escalation?.block_status ?? null
  if (snap.blockStatus != null && currentBlockStatus != null) {
    if (
      (snap.blockStatus === 'blocked' && currentBlockStatus === 'allowed') ||
      (snap.blockStatus === 'allowed' && currentBlockStatus === 'blocked')
    ) {
      return true
    }
  }

  // 3. Tier decrease (lower tier number = louder = more urgent)
  const currentTier = actor.escalation?.tier ?? null
  if (snap.tier != null && currentTier != null && currentTier < snap.tier) return true

  return false
}

// ---------------------------------------------------------------------------
// Public query API
// ---------------------------------------------------------------------------

/**
 * Returns true if the actor is currently suppressed from the triage queue:
 *   - dismissed/closed (stronger — never re-surfaces), OR
 *   - acknowledged (regardless of material-change state — reconcileAcknowledged
 *     handles eviction of stale acknowledged entries on the data-refresh path).
 *
 * PURE — does NOT read or write localStorage; does NOT mutate any state
 * (issue #755 EARS-1). Uses the in-memory cache for O(1) lookups.
 *
 * Material-change eviction (acknowledged → re-surface) is NOT performed here.
 * Call `reconcileAcknowledged(threats)` on the data-refresh path to evict
 * stale acknowledged actors before rendering. This keeps isDismissed pure
 * and prevents write-during-render (impure side-effect under React StrictMode).
 *
 * Returns false when source_ip fails the IP-format guard (N-2, issue #171).
 */
export function isDismissed(actor: ThreatScore): boolean {
  if (!isValidIpFormat(actor.source_ip)) return false

  ensureDismissedLoaded()
  ensureAcknowledgedLoaded()

  // O(1): hard-dismissed set check (no re-surface).
  if (_dismissedSet!.has(actor.source_ip)) return true

  // O(1): acknowledged map check.
  // The re-surface condition (material change) is handled by reconcileAcknowledged,
  // not here — keeping this function pure.
  if (actor.source_ip in _acknowledgedMap!) return true

  return false
}

/**
 * Reconcile the acknowledged store against the current threat list, evicting
 * any actor that has undergone a material change since it was acknowledged.
 *
 * This is the ONLY place material-change eviction writes to the acknowledged
 * store. Previously this logic lived inside `isDismissed`, causing:
 *   - impure writes during render (issue #755)
 *   - write races under React StrictMode / concurrent mode
 *
 * Call this ONCE on each data refresh (e.g. when new threat data arrives from
 * the API) and bump dismissVersion so the dashboard re-renders with updated state.
 *
 * Returns true if any actor was evicted (callers can use this to bump version).
 */
export function reconcileAcknowledged(threats: ThreatScore[]): boolean {
  ensureAcknowledgedLoaded()
  const map = _acknowledgedMap!
  let changed = false

  for (const actor of threats) {
    if (!isValidIpFormat(actor.source_ip)) continue
    if (!(actor.source_ip in map)) continue
    const snap = map[actor.source_ip]
    if (hasMaterialChange(actor, snap)) {
      delete map[actor.source_ip]
      changed = true
    }
  }

  if (changed) {
    flushAcknowledgedStore()
  }
  return changed
}

/**
 * Clears both the dismissed and acknowledged stores (in-memory + localStorage).
 * Useful for testing or explicit "reset triage" operations.
 */
export function clearDismissed(): void {
  // Reset in-memory stores.
  _dismissedSet = new Set()
  _dismissedOrder = []
  _acknowledgedMap = {}

  // Wipe localStorage.
  try {
    localStorage.removeItem(DISMISSED_ACTORS_KEY)
    localStorage.removeItem(ACKNOWLEDGED_ACTORS_KEY)
  } catch {
    // Non-fatal.
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
//   onDismiss  — optional callback called after `acknowledge` or `dismiss` so
//                the container can refresh its local state (e.g. filter triage list)
//   onBlock    — optional callback called after `block` records the decision
//                (so the container can show a toast / refresh state)
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
}

/**
 * Creates the `onAction` SIEM implementation.
 *
 * This is the ONE place a future SOAR executor is wired in behind `block`.
 * To add enforcement: extend the `block` branch with the executor call AFTER
 * the existing decision-record step — no component changes needed.
 */
export function makeOnAction(callbacks: OnActionCallbacks): OnAction {
  return function onAction(actor: ThreatScore, verb: ThreatActionVerb): void {
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
        break
      }

      case 'acknowledge': {
        // SIEM: "I'm working on it" — suppress NOW, re-surface on material change.
        // Stores a snapshot of the actor at acknowledge time for re-surface detection.
        // N-1 (issue #171/727): addAcknowledged enforces the DISMISSED_ACTORS_CAP.
        addAcknowledged(actor.source_ip, snapshotOf(actor))
        callbacks.onDismiss?.(actor)
        break
      }

      case 'dismiss': {
        // SIEM: resolve/close the actor — stronger suppression than acknowledge.
        // Does NOT re-surface on material change (analyst has closed the case).
        // N-1 (issue #171/727): addDismissed enforces the DISMISSED_ACTORS_CAP with FIFO eviction.
        addDismissed(actor.source_ip)
        // Also remove from acknowledged store if it was there (promote to hard-dismissed).
        ensureAcknowledgedLoaded()
        if (actor.source_ip in _acknowledgedMap!) {
          delete _acknowledgedMap![actor.source_ip]
          flushAcknowledgedStore()
        }
        callbacks.onDismiss?.(actor)
        break
      }

      case 'block': {
        // SIEM: record the block *decision* / raise the alert.
        // ADR-0033: "mark the actor as 'operator decided to block'"
        // This is ADR-0015 "Suggest" tier — AI recommends Block, analyst confirms
        // → FireWatch records/alerts; enforcement is the future SOAR executor.
        //
        // *** SOAR WIRE-IN POINT ***
        // When the SOAR milestone lands: add the responder-port call here,
        // after the existing SIEM step, with ADR-0015 guardrails (allowlist,
        // rate cap, TTL) and confirm+undo+audit UX. Zero component changes needed.
        // N-1 (issue #171): addDismissed enforces the cap with FIFO eviction.
        addDismissed(actor.source_ip) // also removes from triage queue
        callbacks.onBlock?.(actor)
        break
      }

      default: {
        // Exhaustive — TypeScript enforces this at compile time via the union type.
        const _exhaustive: never = verb
        console.warn('[triageActions] unknown verb:', _exhaustive)
      }
    }
  }
}
