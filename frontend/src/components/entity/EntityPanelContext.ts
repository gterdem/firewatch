/**
 * EntityPanelContext — app-wide entity panel context + hooks (ADR-0037).
 *
 * Issue #324 — context split for render hygiene:
 *
 *   EntityPanelActionsContext  — STABLE reference (never changes after mount).
 *     Contains: openEntity, closeEntity, closePanelAll.
 *     Action-only consumers (DashboardRoute, ClickableIp, ThreatActors, LogsRoute,
 *     AIRoute) subscribe here and do NOT re-render when the slide-over opens/closes.
 *
 *   EntityPanelContext         — STATE + ACTIONS (backward compatible).
 *     Contains: stack + all actions.
 *     Consumers that render panel state subscribe here (re-renders on stack change).
 *
 * Public hooks:
 *   useEntityActions()  — action-only (stable, no re-renders on open/close).
 *   useEntityState()    — state-only  (re-renders on every stack change).
 *   useEntityPanel()    — combined (backward compat; re-renders on stack change).
 *
 * The entity ref shape `{kind, value}` is extensible: `kind` is "ip" today;
 * wave-2 adds "asn" and "cidr" group views without reshaping the host.
 *
 * openEntity({kind: "ip", value: "192.0.2.1"}) — pushes onto the breadcrumb stack.
 * closeEntity()                               — pops the top of stack.
 * closePanelAll()                             — clears the entire stack.
 */

import { createContext, useContext } from 'react'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type EntityKind = 'ip' | 'asn' | 'cidr' | 'case'

export interface EntityRef {
  kind: EntityKind
  value: string
  /**
   * Optional opaque metadata payload — used by wave-2 group views (kind="asn"|"cidr").
   * Carries the ActorGroup record from ThreatActors to GroupPanel without a separate
   * data-fetch (the group data was already computed client-side by actorRollup).
   * Typed as unknown to keep the context layer decoupled from actorRollup types.
   */
  meta?: unknown
}

/** Actions only — stable reference, never changes after the provider mounts. */
export interface EntityPanelActionsValue {
  /** Push a new entity onto the stack (or open if empty). */
  openEntity: (ref: EntityRef) => void
  /** Pop the top entity off the stack. */
  closeEntity: () => void
  /** Clear the entire stack (close the panel completely). */
  closePanelAll: () => void
}

/** Combined (state + actions) — kept for backward compatibility. */
export interface EntityPanelContextValue extends EntityPanelActionsValue {
  /** Breadcrumb stack — top (last) element is the active panel. */
  stack: EntityRef[]
}

// ---------------------------------------------------------------------------
// Contexts
// ---------------------------------------------------------------------------

/**
 * EntityPanelActionsContext — STABLE.
 *
 * EntityPanelProvider wraps the actions in useMemo so the context value object
 * reference NEVER changes after mount. Action-only consumers subscribe here and
 * do not re-render when the slide-over opens or closes (issue #324).
 */
export const EntityPanelActionsContext = createContext<EntityPanelActionsValue>({
  openEntity: () => {},
  closeEntity: () => {},
  closePanelAll: () => {},
})

/**
 * EntityPanelContext — STATE + ACTIONS (backward compatible).
 *
 * Changes whenever the stack changes. Kept unchanged so existing tests that
 * wrap components with <EntityPanelContext.Provider value={ctx}> continue to
 * work without modification.
 */
export const EntityPanelContext = createContext<EntityPanelContextValue>({
  stack: [],
  openEntity: () => {},
  closeEntity: () => {},
  closePanelAll: () => {},
})

// ---------------------------------------------------------------------------
// Hooks
// ---------------------------------------------------------------------------

/**
 * useEntityActions — consume ONLY the stable actions context.
 *
 * Use this in components that call openEntity/closeEntity/closePanelAll but
 * do NOT need to render panel state. These components WILL NOT re-render when
 * the slide-over opens or closes (issue #324 render hygiene).
 *
 * Usage:
 *   const { openEntity } = useEntityActions()
 *   openEntity({ kind: 'ip', value: '192.0.2.1' })
 */
export function useEntityActions(): EntityPanelActionsValue {
  return useContext(EntityPanelActionsContext)
}

/**
 * useEntityState — consume ONLY the panel stack state.
 *
 * Use this in components that conditionally render based on panel open/closed
 * status (e.g. breadcrumb count, isOpen guard). Re-renders on every stack
 * change.
 */
export function useEntityState(): Pick<EntityPanelContextValue, 'stack'> {
  const { stack } = useContext(EntityPanelContext)
  return { stack }
}

/**
 * useEntityPanel — consume the combined entity panel context (backward compat).
 *
 * Returns both state (stack) and actions. Re-renders on every stack change.
 * Existing consumers that need BOTH can keep using this hook unchanged.
 *
 * Prefer useEntityActions() for action-only consumers (better render hygiene).
 *
 * Usage:
 *   const { openEntity } = useEntityPanel()
 *   openEntity({ kind: 'ip', value: '192.0.2.1' })
 */
export function useEntityPanel(): EntityPanelContextValue {
  return useContext(EntityPanelContext)
}
