/**
 * Bucketing utility for HorizontalBarList (issue #206).
 *
 * Extracted from HorizontalBarList.tsx so the component file
 * exports only the React component (react-refresh/only-export-components rule).
 */

import type { BarRow } from './HorizontalBarList'

/**
 * Returns the top-N rows plus the total count for the tail ("Other").
 * When rows.length <= maxBars, otherCount is 0 and all rows are returned.
 */
export function bucketRows(
  rows: BarRow[],
  maxBars: number,
): { topRows: BarRow[]; otherCount: number } {
  if (rows.length <= maxBars) {
    return { topRows: rows, otherCount: 0 }
  }
  const topRows = rows.slice(0, maxBars)
  const otherCount = rows.slice(maxBars).reduce((sum, r) => sum + r.count, 0)
  return { topRows, otherCount }
}
