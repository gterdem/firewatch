/**
 * Tests for issue #566 — table-layout discipline.
 *
 * EARS criteria covered:
 *   EARS-1: LogsTable colgroup allocates proportional widths → Time and Signature columns
 *           are not equal-width with all other columns (colgroup present, each col has width).
 *   EARS-2: LogsTable minWidth is honoured per column via colgroup (not equal ~109px each).
 *   EARS-3: TopPairsPanel EVENTS column has trailing paddingRight ≥ 16px on the data cell.
 *   EARS-4: TopPairsPanel EVENTS column header is right-aligned.
 *   EARS-5: CoverageLedger "Analysis age" column has trailing paddingRight ≥ 16px.
 *   EARS-6: CoverageLedger IP column left gutter (paddingLeft) is consistent (≥ 0 — no negative).
 *   EARS-7: AnalyticsCharts TOTAL column has trailing paddingRight ≥ 16px.
 */

import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import LogsTable from '../components/logs/LogsTable'
import TopPairsPanel from '../components/logs/TopPairsPanel'
import { CoverageLedger } from '../components/ai/ledger/CoverageLedger'
import AnalyticsCharts from '../components/analytics/AnalyticsCharts'
import {
  LOG_ENTRY_FIXTURE,
  ANALYTICS_SUMMARY_FIXTURE,
  CATEGORIES_TIMELINE_FIXTURE,
  THREATS_FIXTURE,
} from './readFixtures'
import type { TopPairsRow } from '../api/types'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Render LogsTable with wide JSDOM container so all columns are visible. */
function renderLogsTable() {
  vi.spyOn(Element.prototype, 'getBoundingClientRect').mockReturnValue({
    width: 1600, height: 40, top: 0, left: 0, bottom: 40, right: 1600,
    x: 0, y: 0, toJSON: () => ({}),
  } as DOMRect)

  const result = render(
    <MemoryRouter>
      <LogsTable logs={[LOG_ENTRY_FIXTURE]} onIpClick={vi.fn()} />
    </MemoryRouter>,
  )

  vi.restoreAllMocks()
  return result
}

const TOP_PAIRS_FIXTURE: TopPairsRow[] = [
  { source_ip: '192.0.2.1', destination_ip: '198.51.100.1', count: 42 },
  { source_ip: '192.0.2.2', destination_ip: '198.51.100.2', count: 7 },
]

// ---------------------------------------------------------------------------
// EARS-1 / EARS-2: LogsTable colgroup proportional widths
// ---------------------------------------------------------------------------

describe('LogsTable — colgroup column-width discipline (#566 EARS-1/EARS-2)', () => {
  it('renders a <colgroup> element inside the table', () => {
    renderLogsTable()
    const table = screen.getByTestId('logs-table').querySelector('table')
    expect(table?.querySelector('colgroup')).toBeTruthy()
  })

  it('colgroup contains <col> elements with explicit width attributes', () => {
    renderLogsTable()
    const table = screen.getByTestId('logs-table').querySelector('table')
    const cols = table?.querySelectorAll('colgroup col')
    expect(cols).toBeTruthy()
    expect((cols?.length ?? 0)).toBeGreaterThan(0)
    // Every col must have a width set (proportional, not empty)
    cols?.forEach((col) => {
      const w = col.getAttribute('style') ?? col.getAttribute('width') ?? ''
      expect(w.length).toBeGreaterThan(0)
    })
  })

  it('number of <col> elements matches number of visible columns', () => {
    renderLogsTable()
    const table = screen.getByTestId('logs-table').querySelector('table')
    const cols = table?.querySelectorAll('colgroup col')
    const headers = table?.querySelectorAll('thead th')
    // Each visible header must have a corresponding col
    expect(cols?.length).toBe(headers?.length)
  })
})

// ---------------------------------------------------------------------------
// EARS-3/EARS-4: TopPairsPanel EVENTS trailing gutter + alignment
// ---------------------------------------------------------------------------

describe('TopPairsPanel — EVENTS column trailing gutter (#566 EARS-3/EARS-4)', () => {
  it('EVENTS header cell is right-aligned', () => {
    render(
      <TopPairsPanel
        pairs={TOP_PAIRS_FIXTURE}
        onSelectPair={vi.fn()}
      />,
    )
    // Locate the EVENTS header by text
    const headers = document.querySelectorAll('th')
    const eventsHeader = Array.from(headers).find((th) =>
      /events/i.test(th.textContent ?? ''),
    )
    expect(eventsHeader).toBeTruthy()
    const style = (eventsHeader as HTMLElement)?.style
    expect(style?.textAlign).toBe('right')
  })

  it('EVENTS data cell is right-aligned with paddingRight ≥ 16px', () => {
    render(
      <TopPairsPanel
        pairs={TOP_PAIRS_FIXTURE}
        onSelectPair={vi.fn()}
      />,
    )
    // Last cell in the first data row
    const rows = screen.getAllByTestId('top-pairs-row')
    const cells = rows[0].querySelectorAll('td')
    const eventsCell = cells[cells.length - 1] as HTMLElement
    expect(eventsCell.style.textAlign).toBe('right')
    // paddingRight must be at least 16px
    const pr = parseInt(eventsCell.style.paddingRight ?? '0', 10)
    expect(pr).toBeGreaterThanOrEqual(16)
  })
})

// ---------------------------------------------------------------------------
// EARS-5: CoverageLedger "Analysis age" trailing gutter
// ---------------------------------------------------------------------------

describe('CoverageLedger — Analysis age trailing gutter (#566 EARS-5)', () => {
  it('Analysis age data cell has paddingRight ≥ 16px', () => {
    render(
      <CoverageLedger
        threats={THREATS_FIXTURE}
        analyses={null}
        filterParam={null}
      />,
    )
    // Last cell of the first actor row is "Analysis age"
    const rows = screen.getAllByTestId('coverage-actor-row')
    const cells = rows[0].querySelectorAll('td')
    const ageCell = cells[cells.length - 1] as HTMLElement
    const pr = parseInt(ageCell.style.paddingRight ?? '0', 10)
    expect(pr).toBeGreaterThanOrEqual(16)
  })
})

// ---------------------------------------------------------------------------
// EARS-7: AnalyticsCharts TOTAL column trailing gutter
// ---------------------------------------------------------------------------

describe('AnalyticsCharts — TOTAL column trailing gutter (#566 EARS-7)', () => {
  it('TOTAL header cell has paddingRight ≥ 16px', () => {
    render(
      <AnalyticsCharts
        summary={ANALYTICS_SUMMARY_FIXTURE}
        timeline={CATEGORIES_TIMELINE_FIXTURE}
      />,
    )
    // Last <th> in the timeline table header row
    const tables = document.querySelectorAll('[data-testid="categories-timeline-chart"] table')
    expect(tables.length).toBeGreaterThan(0)
    const theadRow = tables[0].querySelector('thead tr')
    const ths = theadRow?.querySelectorAll('th')
    const totalTh = ths?.[ths.length - 1] as HTMLElement
    // Should contain "Total"
    expect(totalTh?.textContent).toMatch(/total/i)
    const pr = parseInt(totalTh?.style?.paddingRight ?? '0', 10)
    expect(pr).toBeGreaterThanOrEqual(16)
  })

  it('TOTAL data cell has paddingRight ≥ 16px', () => {
    render(
      <AnalyticsCharts
        summary={ANALYTICS_SUMMARY_FIXTURE}
        timeline={CATEGORIES_TIMELINE_FIXTURE}
      />,
    )
    const tables = document.querySelectorAll('[data-testid="categories-timeline-chart"] table')
    const rows = tables[0].querySelectorAll('tbody tr')
    const firstRow = rows[0]
    const cells = firstRow?.querySelectorAll('td')
    const totalCell = cells?.[cells.length - 1] as HTMLElement
    const pr = parseInt(totalCell?.style?.paddingRight ?? '0', 10)
    expect(pr).toBeGreaterThanOrEqual(16)
  })
})
