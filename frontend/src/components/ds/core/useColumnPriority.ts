/**
 * useColumnPriority — responsive column-hiding for DS tables (issue #263).
 *
 * Philosophy: DataTables Responsive (https://datatables.net/extensions/responsive/priority)
 * — declare a numeric priority on each column definition; when the table's container is
 * narrower than the natural table width, hide columns in ascending priority order (lowest
 * priority drops first). Columns with `never: true` are protected and NEVER hidden.
 *
 * This is a generic DS primitive. It has no knowledge of specific source types, IP
 * addresses, or any domain model — it operates purely on the column definition array
 * and the observed container width.
 *
 * Usage:
 *   const columnDefs: ColumnDef[] = [
 *     { key: 'ip',      priority: 1, never: true },   // always shown
 *     { key: 'score',   priority: 1, never: true },   // always shown
 *     { key: 'events',  priority: 2 },                 // drops second
 *     { key: 'blocked', priority: 3 },                 // drops first (lowest)
 *   ]
 *   const { containerRef, visibleColumns } = useColumnPriority(columnDefs, minColWidth)
 *
 * Algorithm:
 *   1. Attach a ResizeObserver to the returned `containerRef`.
 *   2. On each resize, start with all columns visible.
 *   3. Compute the total minimum width: sum of minColWidth across all columns.
 *   4. While (visible non-never columns exist) AND (total > container width):
 *        hide the visible non-never column with the highest priority number (lowest
 *        importance), breaking ties by highest column index (rightmost drops first).
 *        Subtract minColWidth from the running total.
 *   5. Return the set of visible column keys.
 *
 * Priority semantics (DataTables convention):
 *   - Numerically lower = higher importance.
 *   - Priority 1 columns are the last to be hidden (or never hidden if `never: true`).
 *   - Priority 100 (or any large number) is the first to be hidden.
 *   - `never: true` overrides priority: the column is always shown regardless.
 *
 * Invariants:
 *   - Columns with `never: true` NEVER appear in the hidden set.
 *   - If all non-never columns are hidden and the table STILL overflows, the hook
 *     stops hiding (never-columns stay visible, scroll prevention is caller's concern).
 *   - Server-side rendering: hook returns ALL columns visible on first render
 *     (no ResizeObserver on server; consumers must handle SSR themselves if needed).
 *
 * ADR-0028 D6 compliance:
 *   - No raw hex colors or px literals — this hook has no style logic.
 *
 * Security:
 *   - No attacker-controlled string is interpolated into the DOM; this hook is
 *     a pure computation layer.
 *
 * Pure utility `computeVisibleColumns` is exported for direct unit testing
 * without needing to stub ResizeObserver.
 */

import { useState, useEffect, useRef } from 'react'
import type { RefObject } from 'react'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Definition for a single table column.
 *
 * `key`      — stable column identifier (used as React key and for the
 *              visible-set membership test).
 * `priority` — hiding order: numerically lower = higher importance (last to hide).
 *              DataTables Responsive convention.
 * `never`    — when true the column is NEVER hidden regardless of priority.
 *              Use for the most critical columns (IP, Score).
 * `minWidth` — optional per-column override of the default minimum width in px.
 *              Defaults to the `defaultMinColWidth` argument passed to the hook.
 */
export interface ColumnDef {
  key: string
  priority: number
  never?: boolean
  minWidth?: number
}

/**
 * Return value of useColumnPriority.
 *
 * `containerRef`   — attach to the element that wraps the table (the element
 *                    whose width the ResizeObserver watches).
 * `visibleColumns` — Set of column keys that are currently visible. Check
 *                    `visibleColumns.has(col.key)` before rendering each <th>/<td>.
 */
export interface UseColumnPriorityResult {
  containerRef: RefObject<HTMLElement | null>
  visibleColumns: Set<string>
}

// ---------------------------------------------------------------------------
// Pure computation (exported for unit tests)
// ---------------------------------------------------------------------------

/**
 * Given a container width and column definitions, compute the Set of column keys
 * that should be visible.
 *
 * This is the pure inner logic of useColumnPriority. It is exported separately
 * so it can be unit-tested without needing a ResizeObserver stub.
 *
 * @param columns            - Ordered array of column definitions.
 * @param containerWidth     - Available width in pixels for the table container.
 * @param defaultMinColWidth - Minimum width per column when ColumnDef.minWidth is absent.
 * @returns Set of visible column keys.
 */
export function computeVisibleColumns(
  columns: ColumnDef[],
  containerWidth: number,
  defaultMinColWidth = 80,
): Set<string> {
  // Start fully visible.
  const visible = new Set(columns.map((c) => c.key))

  // Total width = sum of each column's minWidth (or default).
  let totalWidth = columns.reduce(
    (sum, col) => sum + (col.minWidth ?? defaultMinColWidth),
    0,
  )

  // Candidate columns for hiding — excludes `never: true` columns.
  // Sorted by priority DESCENDING (highest priority number = lowest importance = hides first),
  // then by descending index (rightmost drops first on ties).
  const hideable = columns
    .map((col, idx) => ({ col, idx }))
    .filter(({ col }) => !col.never)
    .sort((a, b) => {
      // Primary sort: descending priority number (higher number = lower importance = hides first).
      if (a.col.priority !== b.col.priority) return b.col.priority - a.col.priority
      // Tie-break: descending index (rightmost column hides first).
      return b.idx - a.idx
    })

  // Greedily hide columns until we fit in containerWidth or run out.
  let hideCursor = 0
  while (totalWidth > containerWidth && hideCursor < hideable.length) {
    const { col } = hideable[hideCursor]
    if (visible.has(col.key)) {
      visible.delete(col.key)
      totalWidth -= col.minWidth ?? defaultMinColWidth
    }
    hideCursor++
  }

  return visible
}

// ---------------------------------------------------------------------------
// Hook
// ---------------------------------------------------------------------------

/**
 * useColumnPriority — observe a container's width and return which columns
 * should be visible given each column's declared priority.
 *
 * @param columns           - Ordered array of column definitions.
 * @param defaultMinColWidth - Minimum width in pixels assumed for each column
 *                             (used when `ColumnDef.minWidth` is not set).
 *                             Defaults to 80 px.
 * @returns containerRef + visibleColumns Set.
 */
export function useColumnPriority(
  columns: ColumnDef[],
  defaultMinColWidth = 80,
): UseColumnPriorityResult {
  const containerRef = useRef<HTMLElement | null>(null)

  // Initial state: all columns visible.
  const [visibleColumns, setVisibleColumns] = useState<Set<string>>(
    () => new Set(columns.map((c) => c.key)),
  )

  // Stable string key for the column set — avoids re-running the effect when
  // column objects are recreated but logically identical.
  const columnKeys = columns.map((c) => c.key).join(',')

  useEffect(() => {
    const el = containerRef.current
    if (el == null || typeof ResizeObserver === 'undefined') return

    const update = (width: number) => {
      setVisibleColumns(computeVisibleColumns(columns, width, defaultMinColWidth))
    }

    const observer = new ResizeObserver((entries) => {
      for (const entry of entries) {
        update(entry.contentRect.width)
      }
    })

    observer.observe(el)

    // Run once immediately with the current size.
    update(el.getBoundingClientRect().width)

    return () => observer.disconnect()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [columnKeys, defaultMinColWidth])

  return { containerRef, visibleColumns }
}
