/**
 * CategoryBreakdown — Dispositions (outcome) pane (issue #206 refactor).
 *
 * Data comes from GET /logs/categories (ADR-0029 D1).
 * These are BLOCKED/DROPPED event counts grouped by rule category — what the
 * WAF/IDS *did* (disposition), not what the attacker tried.
 *
 * Presentational: renders top-5 bars + "Other (n)" bucket via HorizontalBarList.
 * No inner scrollbar — bounded height (issue #206 EARS criterion 2).
 *
 * Click-through: clicking a bar navigates to /logs?q=<category> so the analyst
 * can reach filtered evidence in one click (issue #206 EARS criterion 3).
 *
 * Bar hue: category name mapped to DS hue tokens (--fw-*). No raw hex.
 *
 * Kept as `CategoryBreakdown` for backward compatibility with existing tests and
 * dashboard routing; the pane title ("Dispositions") is set by the parent.
 *
 * ADR-0028 D6: all colors via var(--fw-*) tokens.
 * ADR-0029 D3: category strings are rule-engine output, rendered as text nodes only.
 */

import { useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import type { CategoryCount } from '../../api/types'
import HorizontalBarList, { type BarRow } from './HorizontalBarList'

interface CategoryBreakdownProps {
  /** Raw rows from GET /logs/categories; may contain per-source duplicates. */
  categories: CategoryCount[]
}

/** Map category name to a hue token — mirrors kit data.js CATS color intent. */
function categoryColor(name: string): string {
  const lower = name.toLowerCase()
  if (lower.includes('sql') || lower.includes('sqli')) return 'var(--fw-orange)'
  if (lower.includes('rate') || lower.includes('limit')) return 'var(--fw-red)'
  if (lower.includes('bot') || lower.includes('scan')) return 'var(--fw-blue)'
  if (lower.includes('xss')) return 'var(--fw-accent)'
  if (lower.includes('anomaly') || lower.includes('score')) return 'var(--fw-purple)'
  if (lower.includes('geo') || lower.includes('geo-block')) return 'var(--fw-cyan)'
  if (lower.includes('command') || lower.includes('cmdi') || lower.includes('ids')) return 'var(--fw-purple)'
  if (lower.includes('lfi') || lower.includes('file')) return 'var(--fw-orange)'
  if (lower.includes('brute') || lower.includes('force')) return 'var(--fw-red)'
  if (lower.includes('malware')) return 'var(--fw-red)'
  if (lower.includes('port')) return 'var(--fw-blue)'
  if (lower.includes('block') || lower.includes('blocked')) return 'var(--fw-red)'
  // Default neutral
  return 'var(--fw-t3)'
}

/** Aggregate counts across source_type variants for the same category label. */
function aggregateCounts(categories: CategoryCount[]): BarRow[] {
  const agg = new Map<string, number>()
  for (const row of categories) {
    agg.set(row.category, (agg.get(row.category) ?? 0) + row.count)
  }
  return Array.from(agg.entries())
    .map(([label, count]) => ({ label, count }))
    .sort((a, b) => b.count - a.count)
}

export default function CategoryBreakdown({ categories }: CategoryBreakdownProps) {
  const navigate = useNavigate()
  const rows = useMemo(() => aggregateCounts(categories), [categories])

  function handleBarClick(label: string) {
    navigate(`/logs?q=${encodeURIComponent(label)}`)
  }

  if (categories.length === 0) {
    return (
      <p
        className="text-sm text-muted-foreground text-center py-4"
        data-testid="categories-empty"
      >
        No category data
      </p>
    )
  }

  return (
    <div data-testid="category-breakdown">
      <HorizontalBarList
        rows={rows}
        colorFor={categoryColor}
        onBarClick={handleBarClick}
        data-testid="category-breakdown-bars"
      />
    </div>
  )
}
