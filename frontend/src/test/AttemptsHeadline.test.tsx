/**
 * Tests for AttemptsHeadline (issue #55, ADR-0070 D1/D3/D5).
 *
 * EARS criteria covered here (see components/dashboard/AttemptsHeadline.tsx
 * module doc for the full mapping):
 *   - The headline sentence renders from GET /banner/summary's server
 *     integers verbatim — never recomputed client-side.
 *   - "0 succeeded" derives from succeeded_count ONLY, including the
 *     breach-visible case (succeeded_count > 0 renders NON-zero).
 *   - The pressure strip renders at most 5 rows, no decision verbs, each row
 *     links to the actor's detail (ClickableIp → entity slide-over), and the
 *     remainder links to Network Logs.
 *   - No inner scrollbar (house rule).
 */

import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import AttemptsHeadline from '../components/dashboard/AttemptsHeadline'
import { EntityPanelContext } from '../components/entity/EntityPanelContext'
import type { EntityPanelContextValue } from '../components/entity/EntityPanelContext'
import type { BannerAttemptSummary } from '../api/types'
import {
  BANNER_SUMMARY_ACTIVE,
  BANNER_SUMMARY_SUCCEEDED,
} from './readFixtures'

// ---------------------------------------------------------------------------
// Mock react-router-dom useNavigate (the remainder link navigates to /logs)
// ---------------------------------------------------------------------------

const mockNavigate = vi.fn()

vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>()
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  }
})

function renderWithPanel(summary: BannerAttemptSummary, openEntity = vi.fn()) {
  const ctx: EntityPanelContextValue = {
    stack: [],
    openEntity,
    closeEntity: vi.fn(),
    closePanelAll: vi.fn(),
  }
  return {
    openEntity,
    ...render(
      <EntityPanelContext.Provider value={ctx}>
        <AttemptsHeadline summary={summary} />
      </EntityPanelContext.Provider>,
    ),
  }
}

describe('AttemptsHeadline', () => {
  // ---------------------------------------------------------------------------
  // Headline sentence — server integers verbatim
  // ---------------------------------------------------------------------------

  it('renders the exact headline sentence from server-provided integers', () => {
    render(<AttemptsHeadline summary={BANNER_SUMMARY_ACTIVE} />)
    expect(screen.getByTestId('attempts-headline')).toHaveTextContent(
      '412 hostile attempts from 87 actors — 0 succeeded · 2 need review',
    )
  })

  it('pluralizes singular counts correctly (1 attempt / 1 actor / 1 needs review)', () => {
    const singular: BannerAttemptSummary = {
      attempt_count: 1,
      actor_count: 1,
      succeeded_count: 0,
      queue_size: 1,
      top_pressure: [{ source_ip: '192.0.2.99', attempt_count: 1, span_minutes: 0 }],
      generated_at: '2026-06-04T10:00:00Z',
    }
    render(<AttemptsHeadline summary={singular} />)
    expect(screen.getByTestId('attempts-headline')).toHaveTextContent(
      '1 hostile attempt from 1 actor — 0 succeeded · 1 needs review',
    )
  })

  // ---------------------------------------------------------------------------
  // "0 succeeded" derives from succeeded_count ONLY — including the
  // breach-visible (nonzero) case, ADR-0070 D3 tier-attribution correction.
  // ---------------------------------------------------------------------------

  it('renders "0 succeeded" when succeeded_count is 0', () => {
    render(<AttemptsHeadline summary={BANNER_SUMMARY_ACTIVE} />)
    expect(screen.getByTestId('attempts-headline')).toHaveTextContent('0 succeeded')
  })

  it('renders a NON-zero succeeded count verbatim — the breach-visible case (ADR-0070 D3)', () => {
    render(<AttemptsHeadline summary={BANNER_SUMMARY_SUCCEEDED} />)
    expect(screen.getByTestId('attempts-headline')).toHaveTextContent('1 succeeded')
    expect(screen.getByTestId('attempts-headline')).not.toHaveTextContent('0 succeeded')
  })

  it('colors the headline red when succeeded_count > 0 (breach-visible, not calm)', () => {
    render(<AttemptsHeadline summary={BANNER_SUMMARY_SUCCEEDED} />)
    expect(screen.getByTestId('attempts-headline')).toHaveStyle({ color: 'var(--fw-red)' })
  })

  // ---------------------------------------------------------------------------
  // Pressure strip — bounded top-N, no decision verbs, links
  // ---------------------------------------------------------------------------

  it('renders one pressure row per top_pressure entry (5 rows for the active fixture)', () => {
    render(<AttemptsHeadline summary={BANNER_SUMMARY_ACTIVE} />)
    expect(screen.getAllByTestId('pressure-row')).toHaveLength(5)
  })

  it('caps the pressure strip at 5 rows even if the server sends more (defensive bound)', () => {
    const overflow: BannerAttemptSummary = {
      attempt_count: 999,
      actor_count: 7,
      succeeded_count: 0,
      queue_size: 0,
      top_pressure: Array.from({ length: 7 }, (_, i) => ({
        source_ip: `192.0.2.${20 + i}`,
        attempt_count: 10 - i,
        span_minutes: 5,
      })),
      generated_at: '2026-06-04T10:00:00Z',
    }
    render(<AttemptsHeadline summary={overflow} />)
    expect(screen.getAllByTestId('pressure-row')).toHaveLength(5)
  })

  it('renders each row as actor IP + attempt count + span — no decision verbs', () => {
    render(<AttemptsHeadline summary={BANNER_SUMMARY_ACTIVE} />)
    const strip = screen.getByTestId('pressure-strip')
    expect(strip).toHaveTextContent('42 attempts over 18 min')
    // No decision verbs anywhere in the strip (issue #55 acceptance criterion).
    const text = strip.textContent?.toLowerCase() ?? ''
    expect(text).not.toMatch(/\bblock\b/)
    expect(text).not.toMatch(/\binvestigate\b/)
    expect(text).not.toMatch(/\bdismiss\b/)
  })

  it('renders the singular "1 attempt" (no trailing "s") for a single-attempt actor', () => {
    const single: BannerAttemptSummary = {
      attempt_count: 1,
      actor_count: 1,
      succeeded_count: 0,
      queue_size: 0,
      top_pressure: [{ source_ip: '192.0.2.77', attempt_count: 1, span_minutes: 0 }],
      generated_at: '2026-06-04T10:00:00Z',
    }
    render(<AttemptsHeadline summary={single} />)
    expect(screen.getByTestId('pressure-strip')).toHaveTextContent('1 attempt')
    expect(screen.getByTestId('pressure-strip')).not.toHaveTextContent('1 attempts')
  })

  it('each pressure row IP links to the actor detail (opens entity slide-over)', async () => {
    const openEntity = vi.fn()
    renderWithPanel(BANNER_SUMMARY_ACTIVE, openEntity)

    const ips = screen.getAllByTestId('clickable-ip')
    await userEvent.click(ips[0])

    expect(openEntity).toHaveBeenCalledWith({ kind: 'ip', value: '192.0.2.10' })
  })

  it('the remainder link navigates to Network Logs (/logs) when actors exist beyond the strip', async () => {
    const withRemainder: BannerAttemptSummary = {
      attempt_count: 500,
      actor_count: 12,
      succeeded_count: 0,
      queue_size: 1,
      top_pressure: BANNER_SUMMARY_ACTIVE.top_pressure,
      generated_at: '2026-06-04T10:00:00Z',
    }
    render(<AttemptsHeadline summary={withRemainder} />)

    const link = screen.getByTestId('pressure-strip-remainder')
    expect(link).toHaveTextContent('+7 more actors → Network Logs')

    await userEvent.click(link)
    expect(mockNavigate).toHaveBeenCalledWith('/logs')
  })

  it('does NOT render a remainder link when every actor is already shown', () => {
    // actor_count equals the number of top_pressure rows — nothing left to link.
    const allShown: BannerAttemptSummary = {
      attempt_count: 20,
      actor_count: BANNER_SUMMARY_ACTIVE.top_pressure.length,
      succeeded_count: 0,
      queue_size: 0,
      top_pressure: BANNER_SUMMARY_ACTIVE.top_pressure,
      generated_at: '2026-06-04T10:00:00Z',
    }
    render(<AttemptsHeadline summary={allShown} />)
    expect(screen.queryByTestId('pressure-strip-remainder')).toBeNull()
  })

  it('does not render a pressure strip when top_pressure is empty', () => {
    const noPressure: BannerAttemptSummary = {
      attempt_count: 0,
      actor_count: 0,
      succeeded_count: 0,
      queue_size: 0,
      top_pressure: [],
      generated_at: '2026-06-04T10:00:00Z',
    }
    render(<AttemptsHeadline summary={noPressure} />)
    expect(screen.queryByTestId('pressure-strip')).toBeNull()
  })

  // ---------------------------------------------------------------------------
  // House rule — no nested scrollbar
  // ---------------------------------------------------------------------------

  it('introduces no inner scrollbar (no overflow:auto/scroll anywhere in the strip)', () => {
    render(<AttemptsHeadline summary={BANNER_SUMMARY_ACTIVE} />)
    const strip = screen.getByTestId('pressure-strip')
    expect(strip).not.toHaveStyle({ overflow: 'auto' })
    expect(strip).not.toHaveStyle({ overflow: 'scroll' })
    expect(strip).not.toHaveStyle({ overflowY: 'auto' })
    expect(strip).not.toHaveStyle({ overflowY: 'scroll' })
  })

  // ---------------------------------------------------------------------------
  // Security — text nodes only (ADR-0029 D3)
  // ---------------------------------------------------------------------------

  it('renders source_ip as a text node only (no dangerouslySetInnerHTML)', () => {
    render(<AttemptsHeadline summary={BANNER_SUMMARY_ACTIVE} />)
    const strip = screen.getByTestId('pressure-strip')
    expect(strip.innerHTML).not.toContain('<script')
    expect(strip).toHaveTextContent('192.0.2.10')
  })
})
