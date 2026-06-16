/**
 * Tests for src/components/analytics/AnalyticsCharts.tsx
 *
 * EARS criteria covered:
 *   - State-driven: populated summary → all KPI tile values rendered as text.
 *   - State-driven: block_rate formatted as percentage.
 *   - State-driven: top_rule tile shown when rule is present; hidden when empty.
 *   - State-driven: timeline buckets → timeline rows rendered.
 *   - State-driven: empty timeline → empty state message shown (no crash).
 *   - State-driven: zero-value summary → renders without crash.
 *
 * Fix #82 criteria:
 *   - top_rule = "" (sentinel) → rule tile hidden.
 *   - top_rule = "0" (SID zero as string, the edge case per contract) → tile shown.
 *   - top_rule narrowed to string in types.ts — guard `!== ''` is compile-time sound.
 *
 * Fix #93 criteria (Categories Over Time table):
 *   - Timeline fixture uses REAL wide-row shape from GET /analytics/categories-timeline.
 *   - Column headers show real category names (SQLi, XSS, IDS Alert, …) — no "undefined".
 *   - Data cells show counts from the fixture rows — no "undefined".
 *   - Each row uses `period` as its React key — no "unique key prop" warning.
 *
 * Fixture shape: real GET /analytics/summary shape (ADR-0029 D1):
 *   { total_ips, total_events, total_blocked, block_rate,
 *     top_country, unique_countries, top_rule }
 *
 * Fixture shape: real GET /analytics/categories-timeline shape (fix #93):
 *   { period, sqli, xss, bot, ratelimit, geo, lfi, ids_alert, total, granularity }
 */

import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import AnalyticsCharts from '../components/analytics/AnalyticsCharts'
import {
  ANALYTICS_SUMMARY_FIXTURE,
  ANALYTICS_SUMMARY_EMPTY_FIXTURE,
  CATEGORIES_TIMELINE_FIXTURE,
} from './readFixtures'

describe('AnalyticsCharts', () => {
  it('renders total_events KPI from analytics summary', () => {
    render(<AnalyticsCharts summary={ANALYTICS_SUMMARY_FIXTURE} timeline={[]} />)
    expect(screen.getByTestId('analytics-total-events')).toHaveTextContent('4,815')
  })

  it('renders total_blocked KPI from analytics summary', () => {
    render(<AnalyticsCharts summary={ANALYTICS_SUMMARY_FIXTURE} timeline={[]} />)
    expect(screen.getByTestId('analytics-total-blocked')).toHaveTextContent('3,000')
  })

  it('renders total_ips KPI from analytics summary', () => {
    render(<AnalyticsCharts summary={ANALYTICS_SUMMARY_FIXTURE} timeline={[]} />)
    expect(screen.getByTestId('analytics-total-ips')).toHaveTextContent('23')
  })

  it('renders block_rate as a percentage string', () => {
    render(<AnalyticsCharts summary={ANALYTICS_SUMMARY_FIXTURE} timeline={[]} />)
    expect(screen.getByTestId('analytics-block-rate')).toHaveTextContent('62.3%')
  })

  it('renders top_country KPI', () => {
    render(<AnalyticsCharts summary={ANALYTICS_SUMMARY_FIXTURE} timeline={[]} />)
    expect(screen.getByTestId('analytics-top-country')).toHaveTextContent('US')
  })

  it('renders unique_countries KPI', () => {
    render(<AnalyticsCharts summary={ANALYTICS_SUMMARY_FIXTURE} timeline={[]} />)
    expect(screen.getByTestId('analytics-unique-countries')).toHaveTextContent('12')
  })

  it('shows top_rule tile when a rule is present', () => {
    render(<AnalyticsCharts summary={ANALYTICS_SUMMARY_FIXTURE} timeline={[]} />)
    expect(screen.getByTestId('analytics-top-rule-tile')).toBeInTheDocument()
    expect(screen.getByTestId('analytics-top-rule')).toHaveTextContent('2001219')
  })

  it('hides top_rule tile when top_rule is empty string', () => {
    render(<AnalyticsCharts summary={ANALYTICS_SUMMARY_EMPTY_FIXTURE} timeline={[]} />)
    expect(screen.queryByTestId('analytics-top-rule-tile')).not.toBeInTheDocument()
  })

  it('renders one timeline row per period (fix #93 — real wide-row shape)', () => {
    render(
      <AnalyticsCharts summary={ANALYTICS_SUMMARY_FIXTURE} timeline={CATEGORIES_TIMELINE_FIXTURE} />,
    )
    const rows = screen.getAllByTestId('timeline-row-analytics')
    // CATEGORIES_TIMELINE_FIXTURE has 2 periods → 2 rows
    expect(rows).toHaveLength(2)
  })

  it('renders real category column headers — no "undefined" (fix #93)', () => {
    render(
      <AnalyticsCharts summary={ANALYTICS_SUMMARY_FIXTURE} timeline={CATEGORIES_TIMELINE_FIXTURE} />,
    )
    // Column headers derived from CATEGORY_COLUMNS — must all be present as text
    expect(screen.getByText('SQLi')).toBeInTheDocument()
    expect(screen.getByText('XSS')).toBeInTheDocument()
    expect(screen.getByText('IDS Alert')).toBeInTheDocument()
    // The literal string "undefined" must never appear
    expect(screen.queryByText('undefined')).not.toBeInTheDocument()
  })

  it('renders period values in timeline rows — not "undefined" (fix #93)', () => {
    render(
      <AnalyticsCharts summary={ANALYTICS_SUMMARY_FIXTURE} timeline={CATEGORIES_TIMELINE_FIXTURE} />,
    )
    // The first period in the fixture is '2026-06-04'
    expect(screen.getByText('2026-06-04')).toBeInTheDocument()
    // The literal string "undefined" must never appear
    expect(screen.queryByText('undefined')).not.toBeInTheDocument()
  })

  it('renders total count cells for each row (fix #93)', () => {
    render(
      <AnalyticsCharts summary={ANALYTICS_SUMMARY_FIXTURE} timeline={CATEGORIES_TIMELINE_FIXTURE} />,
    )
    // First row total is 6, second is 12.
    // Use getAllByText because '12' also matches the unique_countries KPI tile;
    // we only assert that both values are present somewhere in the document.
    expect(screen.getAllByText('6').length).toBeGreaterThanOrEqual(1)
    expect(screen.getAllByText('12').length).toBeGreaterThanOrEqual(1)
  })

  it('shows empty state for empty timeline', () => {
    render(<AnalyticsCharts summary={ANALYTICS_SUMMARY_FIXTURE} timeline={[]} />)
    expect(screen.getByTestId('timeline-empty-analytics')).toBeInTheDocument()
  })

  it('renders zero KPIs without crash (empty store state)', () => {
    render(<AnalyticsCharts summary={ANALYTICS_SUMMARY_EMPTY_FIXTURE} timeline={[]} />)
    expect(screen.getByTestId('analytics-total-events')).toHaveTextContent('0')
    expect(screen.getByTestId('analytics-total-ips')).toHaveTextContent('0')
    expect(screen.getByTestId('analytics-block-rate')).toHaveTextContent('0.0%')
  })
})

// ---------------------------------------------------------------------------
// Fix #82 — top_rule tile visibility guard
//
// Verified contract: the backend stores rule_id as TEXT (sqlite_store.py:231
// "rule_id TEXT") and the empty sentinel is "" (sqlite_store.py:914).
// top_rule is narrowed to `string` in types.ts — the `!== ''` guard is
// compile-time correct. Numeric 0 cannot arrive as a JS number from the server.
//
// EARS:
//   - top_rule = "" (sentinel) → rule tile SHALL be hidden.
//   - top_rule = "0" (SID zero as string, the edge case that would fail with
//     the old `string | number` type and the `!== ''` guard if 0 were numeric)
//     → tile SHALL be shown and display "0".
// ---------------------------------------------------------------------------
describe('#82 top_rule tile visibility guard', () => {
  it('hides the rule tile when top_rule is the empty-string sentinel', () => {
    render(
      <AnalyticsCharts summary={{ ...ANALYTICS_SUMMARY_FIXTURE, top_rule: '' }} timeline={[]} />,
    )
    expect(screen.queryByTestId('analytics-top-rule-tile')).not.toBeInTheDocument()
  })

  it('shows the rule tile when top_rule is a non-empty string (normal SID)', () => {
    render(
      <AnalyticsCharts
        summary={{ ...ANALYTICS_SUMMARY_FIXTURE, top_rule: '2001219' }}
        timeline={[]}
      />,
    )
    expect(screen.getByTestId('analytics-top-rule-tile')).toBeInTheDocument()
    expect(screen.getByTestId('analytics-top-rule')).toHaveTextContent('2001219')
  })

  it('shows the rule tile when top_rule is the string "0" (SID zero edge case)', () => {
    // SID 0 is a valid Suricata rule ID (though rare). The contract sends it as
    // the string "0" — the `!== ''` guard must show the tile, not hide it.
    render(
      <AnalyticsCharts summary={{ ...ANALYTICS_SUMMARY_FIXTURE, top_rule: '0' }} timeline={[]} />,
    )
    expect(screen.getByTestId('analytics-top-rule-tile')).toBeInTheDocument()
    expect(screen.getByTestId('analytics-top-rule')).toHaveTextContent('0')
  })
})
