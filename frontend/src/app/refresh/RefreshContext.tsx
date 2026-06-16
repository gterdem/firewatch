/**
 * RefreshContext — app-wide live-refresh signal provider.
 *
 * ADR-0064 D1: RefreshProvider is mounted exactly once at the app root
 * (sibling/parent of EntityPanelProvider, the ADR-0037 precedent).  It calls
 * useStatsHeartbeat() once — the ONE polling interval — and publishes the
 * resulting RefreshSignal via React context.  No page or component may create
 * a second GET /stats interval.
 *
 * useRefreshSignal() is the reader hook pages use to subscribe to the signal
 * without prop-drilling.  It throws when used outside a RefreshProvider so
 * missing-wrapper bugs surface immediately in development.
 *
 * ADR-0019: React + TS.
 * ADR-0026: loopback-only; no off-host requests.
 *
 * Fast-refresh note: this file intentionally exports both a component
 * (RefreshProvider) and a hook (useRefreshSignal) — they are tightly coupled
 * (one produces the context, the other reads it) and splitting would be
 * artificial.  The react-refresh/only-export-components rule is suppressed.
 */
/* eslint-disable react-refresh/only-export-components */

import { createContext, useContext } from 'react'
import type { ReactNode } from 'react'
import type { RefreshSignal } from './types'
import { useStatsHeartbeat } from './useStatsHeartbeat'

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

/**
 * The context value is RefreshSignal | null — null only before the provider
 * mounts (should never happen in production; caught by the guard in
 * useRefreshSignal).
 */
const RefreshContext = createContext<RefreshSignal | null>(null)

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

/**
 * RefreshProvider — calls useStatsHeartbeat() once and publishes the signal.
 *
 * Mount once at the app root, wrapping the entire shell (or at minimum all
 * routed pages + AppHeader).  The provider is deliberately thin: it is a
 * pass-through that delegates all polling logic to useStatsHeartbeat so the
 * concerns stay separated.
 */
export function RefreshProvider({ children }: { children: ReactNode }) {
  const signal = useStatsHeartbeat()

  return (
    <RefreshContext.Provider value={signal}>
      {children}
    </RefreshContext.Provider>
  )
}

// ---------------------------------------------------------------------------
// Reader hook
// ---------------------------------------------------------------------------

/**
 * useRefreshSignal — returns the current RefreshSignal from context.
 *
 * Callable from any routed page without prop-drilling (ADR-0064 D3).
 * Throws if called outside a RefreshProvider — this surfaces missing-wrapper
 * bugs clearly in development rather than silently returning stale data.
 */
export function useRefreshSignal(): RefreshSignal {
  const signal = useContext(RefreshContext)
  if (signal === null) {
    throw new Error(
      '[useRefreshSignal] Must be used inside a <RefreshProvider>. ' +
      'Ensure RefreshProvider is mounted at the app root (App.tsx).',
    )
  }
  return signal
}
