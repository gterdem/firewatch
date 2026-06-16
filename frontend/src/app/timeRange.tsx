/**
 * timeRange.tsx — Dashboard-wide time-range context + useTimeRange hook (issue #249).
 *
 * Single source of truth for the active brush range on the dashboard.
 *
 * Design:
 *   - The range is represented as { start: string; end: string } in ISO-8601 UTC.
 *   - When no brush is active, `activeRange` is null — every consumer defaults
 *     to its own default window (unchanged from pre-brush behaviour).
 *   - `setRange(range)` activates a range; `clearRange()` returns to null.
 *   - The provider is scoped to the Dashboard — no cross-route propagation.
 *
 * URL persistence is NOT implemented (issue #249 out-of-scope flag):
 *   It would require encoding ISO timestamps in search params and keeping them
 *   in sync with back-navigation.  Cheap if used without the router but non-trivial
 *   with react-router v7 controlled params.  Flagged as architect follow-up.
 *
 * ADR-0028 D6: no raw hex.
 * ADR-0029 D1: no new backend query params invented here — only endpoints that
 *   already accept start/end (fetchTimeline, fetchPaginatedLogs) are wired.
 */

import {
  createContext,
  useContext,
  useState,
  useCallback,
  type ReactNode,
} from 'react'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface TimeRange {
  /** ISO-8601 UTC string, e.g. "2026-06-11T02:00:00.000Z" */
  start: string
  /** ISO-8601 UTC string, e.g. "2026-06-11T04:00:00.000Z" */
  end: string
}

export interface TimeRangeContextValue {
  /** The active brush range, or null when no brush is applied. */
  activeRange: TimeRange | null
  /** Set the active range (activates brush mode). */
  setRange: (range: TimeRange) => void
  /** Clear the active range — all panes return to default windows. */
  clearRange: () => void
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

const TimeRangeContext = createContext<TimeRangeContextValue | null>(null)

// ---------------------------------------------------------------------------
// Provider
// ---------------------------------------------------------------------------

/**
 * TimeRangeProvider — wraps the Dashboard page; do NOT place at app root
 * (the range is intentionally scoped to the dashboard only — issue #249).
 */
export function TimeRangeProvider({ children }: { children: ReactNode }) {
  const [activeRange, setActiveRange] = useState<TimeRange | null>(null)

  const setRange = useCallback((range: TimeRange) => {
    setActiveRange(range)
  }, [])

  const clearRange = useCallback(() => {
    setActiveRange(null)
  }, [])

  return (
    <TimeRangeContext.Provider value={{ activeRange, setRange, clearRange }}>
      {children}
    </TimeRangeContext.Provider>
  )
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * useTimeRange — consume the active dashboard time range.
 *
 * Must be called inside <TimeRangeProvider>.
 *
 * @example
 *   const { activeRange, clearRange } = useTimeRange()
 *   // Pass activeRange?.start / activeRange?.end to fetch calls.
 *   // When activeRange is null, omit the params → default backend window.
 */
// eslint-disable-next-line react-refresh/only-export-components
export function useTimeRange(): TimeRangeContextValue {
  const ctx = useContext(TimeRangeContext)
  if (!ctx) throw new Error('useTimeRange must be used inside <TimeRangeProvider>')
  return ctx
}
