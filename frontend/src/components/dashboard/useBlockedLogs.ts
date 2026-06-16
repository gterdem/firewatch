/**
 * useBlockedLogs — data hook for the "Recently Blocked Network Logs" pane (#253).
 *
 * Issues a single server-side query with:
 *   - action=blocked  (the #252 shorthand — backend expands to BLOCK/DROP)
 *   - category=<tab>  (when a non-all tab is selected)
 *   - ip=<value>      (debounced backend IP search, replacing the old client-side
 *                      filter which silently missed matches beyond the page window)
 *   - limit=25        (bounded recent feed — no in-pane pagination)
 *   - start/end       (optional time range from the dashboard brush, issue #249)
 *                     When null, the backend default window applies (unchanged behaviour).
 *
 * The hook re-fetches whenever the combined params object changes.
 * Debounce is applied only to the ip input (300 ms) so the fetch is not
 * dispatched on every keystroke.
 *
 * SECURITY (ADR-0029 D3): the ip value is analyst-typed but reflects attacker IPs.
 * It is passed as a URL param only — never injected into the DOM and never
 * concatenated into HTML.
 *
 * issue #249: start/end are ISO-8601 UTC strings already accepted by
 * GET /logs/paginated (LogsFilter.start / LogsFilter.end — ADR-0029 D1).
 * No new backend params are invented here.
 */

import { useState, useEffect, useRef } from 'react'
import { fetchPaginatedLogs } from '../../api/logs'
import type { LogEntry } from '../../api/types'
import type { TimeRange } from '../../app/timeRange'

/** Top-N rows shown in the pane (issue #333). View-all deep-links for the rest. */
export const BLOCKED_FEED_LIMIT = 8
const IP_DEBOUNCE_MS = 300

export interface UseBlockedLogsResult {
  logs: LogEntry[]
  /** True total matching on the server (may exceed BLOCKED_FEED_LIMIT). */
  total: number
  loading: boolean
  error: boolean
}

/**
 * Fetch blocked logs.
 *
 * @param category - active category tab value; 'all' means no category filter.
 * @param ipSearch - raw value from the IP search input (debounced before sending).
 * @param timeRange - optional time range from the dashboard brush (issue #249).
 *                   When null (default), the backend default window applies.
 */
export function useBlockedLogs(
  category: string,
  ipSearch: string,
  timeRange: TimeRange | null = null,
): UseBlockedLogsResult {
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(false)

  // Debounced IP value — only updates 300 ms after the last keystroke.
  const [debouncedIp, setDebouncedIp] = useState(ipSearch)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  useEffect(() => {
    if (timerRef.current !== null) clearTimeout(timerRef.current)
    timerRef.current = setTimeout(() => {
      setDebouncedIp(ipSearch)
    }, IP_DEBOUNCE_MS)
    return () => {
      if (timerRef.current !== null) clearTimeout(timerRef.current)
    }
  }, [ipSearch])

  useEffect(() => {
    let cancelled = false

    const run = async () => {
      try {
        const data = await fetchPaginatedLogs({
          action: 'blocked',
          ...(category !== 'all' ? { category } : {}),
          ...(debouncedIp.trim() ? { ip: debouncedIp.trim() } : {}),
          ...(timeRange ? { start: timeRange.start, end: timeRange.end } : {}),
          limit: BLOCKED_FEED_LIMIT,
        })
        if (!cancelled) {
          setLogs(data.logs)
          setTotal(data.total_matching)
          setLoading(false)
          setError(false)
        }
      } catch {
        if (!cancelled) {
          setError(true)
          setLoading(false)
        }
      }
    }

    void run()

    return () => {
      cancelled = true
    }
  }, [category, debouncedIp, timeRange])

  return { logs, total, loading, error }
}
