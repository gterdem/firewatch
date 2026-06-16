/**
 * useRowExpansion — per-row expand/collapse state for the logs table (ADR-0063 D2).
 *
 * Maintains a Set<rowId> of currently-expanded rows. Multiple rows may be
 * expanded simultaneously (comparison is a feature — no single-open invariant).
 *
 * Keyboard interaction (WAI-ARIA Disclosure pattern, ADR-0063 D2):
 *   Enter / Space on the chevron button → toggle the row.
 *   Esc while the expanded region or chevron has focus → collapse that row.
 *
 * Usage:
 *   const { expandedIds, toggle, makeChevronKeyDown, makeRegionKeyDown } = useRowExpansion()
 *
 *   // Chevron button:
 *   <button onClick={() => toggle(rowId)} onKeyDown={makeChevronKeyDown(rowId)} ... />
 *
 *   // Expanded region:
 *   <tr role="region" ... onKeyDown={makeRegionKeyDown(rowId)} ... />
 */

import { useState, useCallback } from 'react'

export interface UseRowExpansionResult {
  /** Set of row IDs whose detail panel is currently expanded. */
  expandedIds: ReadonlySet<string | number>
  /** Toggle the expansion state of the given row. */
  toggle: (rowId: string | number) => void
  /** True when the given row is expanded. */
  isExpanded: (rowId: string | number) => boolean
  /**
   * onKeyDown handler factory for the chevron button.
   * Enter/Space toggle; other keys are native defaults.
   * (Click already handled by onClick; no need to duplicate toggle here for
   * Enter/Space since <button> fires onClick on those keys — kept for explicit
   * keyboard semantics documentation and custom cases.)
   */
  makeChevronKeyDown: (rowId: string | number) => React.KeyboardEventHandler<HTMLButtonElement>
  /**
   * onKeyDown handler factory for the expanded region <tr>.
   * Esc collapses the open row.
   */
  makeRegionKeyDown: (rowId: string | number) => React.KeyboardEventHandler<HTMLTableRowElement>
}

export function useRowExpansion(): UseRowExpansionResult {
  const [expandedIds, setExpandedIds] = useState<Set<string | number>>(new Set())

  const toggle = useCallback((rowId: string | number) => {
    setExpandedIds((prev) => {
      const next = new Set(prev)
      if (next.has(rowId)) {
        next.delete(rowId)
      } else {
        next.add(rowId)
      }
      return next
    })
  }, [])

  const isExpanded = useCallback(
    (rowId: string | number) => expandedIds.has(rowId),
    [expandedIds],
  )

  const makeChevronKeyDown = useCallback(
    (rowId: string | number): React.KeyboardEventHandler<HTMLButtonElement> =>
      (e) => {
        // Enter/Space: browser already fires onClick for <button>, but we also
        // handle here defensively for edge cases (e.g. role="button" on non-button).
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault()
          toggle(rowId)
        }
      },
    [toggle],
  )

  const makeRegionKeyDown = useCallback(
    (rowId: string | number): React.KeyboardEventHandler<HTMLTableRowElement> =>
      (e) => {
        if (e.key === 'Escape') {
          e.preventDefault()
          // Collapse only this row on Esc.
          setExpandedIds((prev) => {
            if (!prev.has(rowId)) return prev
            const next = new Set(prev)
            next.delete(rowId)
            return next
          })
        }
      },
    [],
  )

  return { expandedIds, toggle, isExpanded, makeChevronKeyDown, makeRegionKeyDown }
}
