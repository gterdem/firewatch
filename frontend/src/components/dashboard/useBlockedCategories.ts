/**
 * useBlockedCategories — stable category tabs for the Blocked Logs pane (#253).
 *
 * Fetches GET /logs/categories and returns the categories sorted alphabetically.
 * This keeps the tab set ORDER STABLE across refreshes and data changes, unlike
 * deriving tabs from the loaded rows (which reshuffled when data changed —
 * the old BlockedLogsPanel.tsx:88-98 approach).
 *
 * The categories endpoint is shared with other panes (Dispositions, Analytics).
 * The hook filters/orders them deterministically so the tab bar never jumps.
 *
 * "All" is always first with a count derived from the total of all categories.
 */

import { useState, useEffect } from 'react'
import { fetchCategories } from '../../api/client'
import type { TabItem } from '../ds'

export interface UseBlockedCategoriesResult {
  tabItems: TabItem[]
  loading: boolean
}

export function useBlockedCategories(): UseBlockedCategoriesResult {
  const [tabItems, setTabItems] = useState<TabItem[]>([{ id: 'all', label: 'All' }])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false

    fetchCategories()
      .then((cats) => {
        if (!cancelled) {
          // Defensive client-side dedup: server guarantees unique labels after
          // #322 fix, but guard against any future regression by merging any
          // same-label categories before building tab items.  This prevents the
          // React duplicate-key warning and broken click-to-filter behaviour
          // that arise when two categories share the same label (issue #322).
          const merged = new Map<string, number>()
          for (const c of cats) {
            merged.set(c.category, (merged.get(c.category) ?? 0) + c.count)
          }

          // Sort alphabetically for stable order; "All" is prepended.
          const dedupedEntries = [...merged.entries()].sort(([a], [b]) =>
            a.localeCompare(b),
          )
          const totalCount = dedupedEntries.reduce((sum, [, count]) => sum + count, 0)
          const items: TabItem[] = [
            { id: 'all', label: 'All', count: totalCount },
            ...dedupedEntries.map(([label, count]) => ({
              id: label,
              label,
              count,
            })),
          ]
          setTabItems(items)
          setLoading(false)
        }
      })
      .catch(() => {
        // Non-fatal: fall back to "All" only tab on categories fetch failure.
        if (!cancelled) setLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [])

  return { tabItems, loading }
}
