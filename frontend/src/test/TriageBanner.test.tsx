/**
 * Tests for TriageBanner (MF-2, issue #159; MH update, issue #204;
 * ADR-0058 D2 escalation axis, issue #649).
 *
 * EARS criteria:
 *   - WHILE pendingActors.length > 0 → active banner with count + actor chips.
 *   - WHILE pendingActors.length === 0 → calm/all-clear state + escalation legend.
 *   - Banner headline shows correct actor count text.
 *   - WHEN analyst clicks (or keyboard-activates) the IP token → entity slide-over
 *     opens for that IP; no route navigation occurs.
 *   - Ubiquitous: banner SHALL NOT render a "Drill down" button.
 *   - Dismiss chip button calls onAction(actor, 'dismiss').
 *   - Active banner has role="alert"; calm banner has role="status".
 *   - No per-verb side-effect logic in this component (seam-only).
 *   - A11y: IP token is focusable and labeled ("Investigate <ip>").
 *   - Security: IP and justification rendered as text nodes (no innerHTML injection).
 *
 * ADR-0058 D2 criteria (issue #649):
 *   - WHEN actor carries escalation tier 1/2 → chip shows justification + disposition label.
 *   - WHERE chip shows justification → rendered as a text node (ADR-0029 D3).
 *   - WHILE queue is empty → legend shows 4 tier rows explaining the model.
 *   - Legend rows present testids legend-tier-1 … legend-tier-4.
 *   - No inner scrollbar introduced by the banner or legend.
 */

import { describe, it, expect, vi, type MockedFunction } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import TriageBanner, { TOP_ACTORS_DEFAULT } from '../components/dashboard/TriageBanner'
import { EntityPanelContext } from '../components/entity/EntityPanelContext'
import type { EntityPanelContextValue } from '../components/entity/EntityPanelContext'
import type { ThreatScore, EscalationVerdict } from '../api/types'
import type { OnAction } from '../lib/triageActions'
import type { ObservedRecordSummary } from '../lib/triageBand'

// ---------------------------------------------------------------------------
// Mock react-router-dom useNavigate (issue #43 — the observed-record link)
// ---------------------------------------------------------------------------

const mockNavigate = vi.fn()

vi.mock('react-router-dom', async (importOriginal) => {
  const actual = await importOriginal<typeof import('react-router-dom')>()
  return {
    ...actual,
    useNavigate: () => mockNavigate,
  }
})

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const ACTOR_CRITICAL: ThreatScore = {
  source_ip: '192.0.2.1',
  threat_level: 'CRITICAL',
  score: 95,
  total_events: 200,
  blocked_events: 180,
  attack_types: ['SQL Injection'],
  first_seen: '2026-06-04T06:00:00Z',
  last_seen: '2026-06-04T10:00:00Z',
  source_types: ['suricata'],
  detections: [],
  ai_insights: null,
  ai_confidence: null,
  ai_status: 'active',
  location: null,
  score_breakdown: [],
  asn: null,
  as_name: null,
  score_delta: null,
}

const ACTOR_HIGH: ThreatScore = {
  source_ip: '192.0.2.2',
  threat_level: 'HIGH',
  score: 78,
  total_events: 120,
  blocked_events: 95,
  attack_types: ['Brute Force'],
  first_seen: '2026-06-04T06:00:00Z',
  last_seen: '2026-06-04T10:00:00Z',
  source_types: ['azure_waf'],
  detections: [],
  ai_insights: null,
  ai_confidence: null,
  ai_status: 'unavailable',
  location: null,
  score_breakdown: [],
  asn: null,
  as_name: null,
  score_delta: null,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Render TriageBanner with an EntityPanelProvider that exposes an observable
 * openEntity spy.  Without a provider, ClickableIp falls back to the default
 * no-op context, which is fine for tests that don't need to assert openEntity.
 */
function renderWithPanel(
  pendingActors: ThreatScore[],
  onAction: OnAction,
  openEntity = vi.fn(),
) {
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
        <TriageBanner pendingActors={pendingActors} onAction={onAction} />
      </EntityPanelContext.Provider>,
    ),
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('TriageBanner', () => {
  // EARS state-driven: empty pending list → calm state
  it('shows calm/all-clear state when pendingActors is empty', () => {
    const onAction: OnAction = vi.fn()
    render(<TriageBanner pendingActors={[]} onAction={onAction} />)

    expect(screen.getByTestId('triage-banner-calm')).toBeInTheDocument()
    expect(screen.queryByTestId('triage-banner-active')).toBeNull()
  })

  // Calm banner has role="status" (informational, not alarm)
  it('calm banner has role="status"', () => {
    render(<TriageBanner pendingActors={[]} onAction={vi.fn()} />)
    expect(screen.getByRole('status')).toBeInTheDocument()
    expect(screen.getByTestId('triage-banner-calm')).toHaveAttribute('role', 'status')
  })

  // EARS state-driven: 1 pending actor → active banner
  it('shows active banner when one actor is pending', () => {
    render(<TriageBanner pendingActors={[ACTOR_CRITICAL]} onAction={vi.fn()} />)

    expect(screen.getByTestId('triage-banner-active')).toBeInTheDocument()
    expect(screen.queryByTestId('triage-banner-calm')).toBeNull()
  })

  // Active banner has role="alert" (announces to screen readers)
  it('active banner has role="alert"', () => {
    render(<TriageBanner pendingActors={[ACTOR_CRITICAL]} onAction={vi.fn()} />)
    expect(screen.getByRole('alert')).toBeInTheDocument()
    expect(screen.getByTestId('triage-banner-active')).toHaveAttribute('role', 'alert')
  })

  // Headline shows singular "1 actor needs"
  it('shows "1 actor" in headline for a single pending actor', () => {
    render(<TriageBanner pendingActors={[ACTOR_CRITICAL]} onAction={vi.fn()} />)
    expect(screen.getByTestId('triage-banner-headline')).toHaveTextContent('1 actor')
  })

  // Headline shows plural "2 actors need"
  it('shows "2 actors" in headline for two pending actors', () => {
    render(<TriageBanner pendingActors={[ACTOR_CRITICAL, ACTOR_HIGH]} onAction={vi.fn()} />)
    expect(screen.getByTestId('triage-banner-headline')).toHaveTextContent('2 actors')
  })

  // Actor chips: one chip per pending actor
  it('renders one chip per pending actor', () => {
    render(<TriageBanner pendingActors={[ACTOR_CRITICAL, ACTOR_HIGH]} onAction={vi.fn()} />)
    const chips = screen.getAllByTestId('triage-actor-chip')
    expect(chips).toHaveLength(2)
  })

  // ---------------------------------------------------------------------------
  // Issue #204: IP click opens slide-over; "Drill down" button is gone
  // ---------------------------------------------------------------------------

  // EARS: WHEN the analyst clicks the IP token, openEntity is called for that IP.
  it('clicking the IP token calls openEntity with {kind:"ip", value} (issue #204)', async () => {
    const openEntity = vi.fn()
    const { openEntity: spy } = renderWithPanel([ACTOR_CRITICAL], vi.fn(), openEntity)

    await userEvent.click(screen.getByTestId('clickable-ip'))

    expect(spy).toHaveBeenCalledOnce()
    expect(spy).toHaveBeenCalledWith({ kind: 'ip', value: ACTOR_CRITICAL.source_ip })
  })

  // EARS: keyboard activation (Enter) on IP token also opens slide-over.
  it('pressing Enter on the IP token opens the slide-over (keyboard a11y)', async () => {
    const openEntity = vi.fn()
    renderWithPanel([ACTOR_CRITICAL], vi.fn(), openEntity)

    screen.getByTestId('clickable-ip').focus()
    await userEvent.keyboard('{Enter}')

    expect(openEntity).toHaveBeenCalledOnce()
    expect(openEntity).toHaveBeenCalledWith({ kind: 'ip', value: ACTOR_CRITICAL.source_ip })
  })

  // EARS: keyboard activation (Space) on IP token also opens slide-over.
  it('pressing Space on the IP token opens the slide-over (keyboard a11y)', async () => {
    const openEntity = vi.fn()
    renderWithPanel([ACTOR_CRITICAL], vi.fn(), openEntity)

    screen.getByTestId('clickable-ip').focus()
    await userEvent.keyboard(' ')

    expect(openEntity).toHaveBeenCalledOnce()
    expect(openEntity).toHaveBeenCalledWith({ kind: 'ip', value: ACTOR_CRITICAL.source_ip })
  })

  // EARS ubiquitous: "Drill down" button SHALL NOT be present.
  it('does NOT render a "Drill down" button (issue #204)', () => {
    render(<TriageBanner pendingActors={[ACTOR_CRITICAL]} onAction={vi.fn()} />)

    // testid used in the old implementation
    expect(screen.queryByTestId('triage-chip-investigate')).toBeNull()
    // text-based check for belt-and-suspenders
    expect(screen.queryByRole('button', { name: /drill down/i })).toBeNull()
  })

  // EARS: clicking IP does NOT call onAction (ClickableIp bypasses the seam directly).
  it('clicking IP does not call onAction (ClickableIp opens panel directly)', async () => {
    const onAction: OnAction = vi.fn()
    renderWithPanel([ACTOR_CRITICAL], onAction)

    await userEvent.click(screen.getByTestId('clickable-ip'))

    expect(onAction).not.toHaveBeenCalled()
  })

  // ---------------------------------------------------------------------------
  // Dismiss behavior (unchanged)
  // ---------------------------------------------------------------------------

  // Event-driven: dismiss button calls onAction with 'dismiss'
  it('calls onAction(actor, "dismiss") when dismiss button is clicked', async () => {
    const onAction: OnAction = vi.fn()
    render(<TriageBanner pendingActors={[ACTOR_CRITICAL]} onAction={onAction} />)

    await userEvent.click(screen.getByTestId('triage-chip-dismiss'))

    expect(onAction).toHaveBeenCalledTimes(1)
    expect(onAction).toHaveBeenCalledWith(ACTOR_CRITICAL, 'dismiss')
  })

  // Action seam: component does NOT contain per-verb side-effect logic
  it('dismiss button calls only onAction — no other side effects inside component', async () => {
    const onAction = vi.fn() as MockedFunction<OnAction>
    render(<TriageBanner pendingActors={[ACTOR_CRITICAL]} onAction={onAction} />)

    await userEvent.click(screen.getByTestId('triage-chip-dismiss'))

    expect(onAction).toHaveBeenCalledTimes(1)
    expect(onAction.mock.calls[0][1]).toBe('dismiss')
  })

  // Dismiss button has accessible aria-label
  it('dismiss button has aria-label with IP', () => {
    render(<TriageBanner pendingActors={[ACTOR_CRITICAL]} onAction={vi.fn()} />)
    expect(screen.getByTestId('triage-chip-dismiss')).toHaveAttribute(
      'aria-label',
      `Dismiss ${ACTOR_CRITICAL.source_ip}`,
    )
  })

  // ---------------------------------------------------------------------------
  // A11y: IP token
  // ---------------------------------------------------------------------------

  // IP token is focusable (it is a <button>)
  it('IP token is keyboard-focusable (rendered as a button)', () => {
    render(<TriageBanner pendingActors={[ACTOR_CRITICAL]} onAction={vi.fn()} />)
    const ipBtn = screen.getByTestId('clickable-ip')
    expect(ipBtn.tagName).toBe('BUTTON')
  })

  // IP token has aria-label "Investigate <ip>"
  it('IP token has aria-label "Investigate <ip>" (a11y, issue #204)', () => {
    render(<TriageBanner pendingActors={[ACTOR_CRITICAL]} onAction={vi.fn()} />)
    expect(screen.getByTestId('clickable-ip')).toHaveAttribute(
      'aria-label',
      `Investigate ${ACTOR_CRITICAL.source_ip}`,
    )
  })

  // ---------------------------------------------------------------------------
  // Security: XSS
  // ---------------------------------------------------------------------------

  // Security: IP rendered as text node, not HTML
  it('renders IP as a text node (no innerHTML injection)', () => {
    const xssActor: ThreatScore = {
      ...ACTOR_CRITICAL,
      source_ip: '<script>alert("xss")</script>',
    }
    render(<TriageBanner pendingActors={[xssActor]} onAction={vi.fn()} />)

    // The literal string must appear as text
    expect(screen.getByText('<script>alert("xss")</script>')).toBeInTheDocument()
    // No live script elements should have been created
    document.querySelectorAll('script').forEach((el) => {
      expect(el.textContent).not.toContain('xss')
    })
  })
})

// ---------------------------------------------------------------------------
// ADR-0058 D2 (issue #649) — Escalation axis: justification + disposition label
// ---------------------------------------------------------------------------

/** Tier 1 escalation verdict fixture (allowed-through, highest urgency). */
const ESCALATION_TIER1: EscalationVerdict = {
  tier: 1,
  disposition: 'allowed_through',
  justification: '[RULE] SQLi signature matched on an ALLOWED request — possible success',
  block_status: 'allowed',
}

/** Tier 2 escalation verdict fixture (IDS alert-only, block status unknown). */
const ESCALATION_TIER2: EscalationVerdict = {
  tier: 2,
  disposition: 'block_status_unknown',
  justification: '[RULE] Suricata ALERT fired — terminating disposition not asserted',
  block_status: 'unknown',
}

/** Tier-1 escalated actor with LOW numeric score (tests score-bypass banner-worthiness). */
const ACTOR_ESCALATED_TIER1: ThreatScore = {
  ...ACTOR_CRITICAL,
  source_ip: '192.0.2.10',
  threat_level: 'LOW',
  score: 30,
  escalation: ESCALATION_TIER1,
}

/** Tier-2 escalated actor. */
const ACTOR_ESCALATED_TIER2: ThreatScore = {
  ...ACTOR_HIGH,
  source_ip: '192.0.2.11',
  threat_level: 'MEDIUM',
  score: 40,
  escalation: ESCALATION_TIER2,
}

/** Actor with no escalation verdict (existing behavior, no regression). */
const ACTOR_NO_ESCALATION: ThreatScore = {
  ...ACTOR_CRITICAL,
  source_ip: '192.0.2.20',
  escalation: null,
}

describe('TriageBanner — ADR-0058 D2 escalation axis (issue #649)', () => {
  // EARS: WHERE banner renders an escalated actor → justification line present inside popover
  it('shows justification line inside popover when actor has an escalation verdict', async () => {
    render(<TriageBanner pendingActors={[ACTOR_ESCALATED_TIER1]} onAction={vi.fn()} />)

    expect(screen.getByTestId('triage-banner-active')).toBeInTheDocument()
    // Justification is NOT on the chip face — open the popover first
    expect(screen.queryByTestId('triage-chip-justification')).toBeNull()
    await userEvent.click(screen.getByTestId('triage-chip-disposition'))
    const justEl = screen.getByTestId('triage-chip-justification')
    expect(justEl).toBeInTheDocument()
    // Text content matches the fixture justification exactly
    expect(justEl).toHaveTextContent(ESCALATION_TIER1.justification)
  })

  // EARS: WHERE banner renders an escalated actor → disposition label always visible (it is the trigger)
  it('shows disposition label "Got through — possible breach" for tier-1 actor', () => {
    render(<TriageBanner pendingActors={[ACTOR_ESCALATED_TIER1]} onAction={vi.fn()} />)

    const dispEl = screen.getByTestId('triage-chip-disposition')
    expect(dispEl).toHaveTextContent('Got through — possible breach')
  })

  it('shows disposition label "Flagged — needs review" for tier-2 actor', () => {
    render(<TriageBanner pendingActors={[ACTOR_ESCALATED_TIER2]} onAction={vi.fn()} />)

    const dispEl = screen.getByTestId('triage-chip-disposition')
    expect(dispEl).toHaveTextContent('Flagged — needs review')
  })

  // EARS: WHERE banner renders an escalated actor → block-status label present inside popover
  it('shows block-status label "Got through" for tier-1 actor inside popover (block_status=allowed)', async () => {
    render(<TriageBanner pendingActors={[ACTOR_ESCALATED_TIER1]} onAction={vi.fn()} />)

    // Block-status is inside the popover — open it first
    expect(screen.queryByTestId('triage-chip-block-status')).toBeNull()
    await userEvent.click(screen.getByTestId('triage-chip-disposition'))
    const bsEl = screen.getByTestId('triage-chip-block-status')
    expect(bsEl).toHaveTextContent('Got through')
  })

  it('shows block-status label "Unconfirmed" for tier-2 actor inside popover (block_status=unknown)', async () => {
    render(<TriageBanner pendingActors={[ACTOR_ESCALATED_TIER2]} onAction={vi.fn()} />)

    // Block-status is inside the popover — open it first
    expect(screen.queryByTestId('triage-chip-block-status')).toBeNull()
    await userEvent.click(screen.getByTestId('triage-chip-disposition'))
    const bsEl = screen.getByTestId('triage-chip-block-status')
    expect(bsEl).toHaveTextContent('Unconfirmed')
  })

  // EARS: tier badge displayed when escalation is present
  it('shows tier badge on escalated actor chip', () => {
    render(<TriageBanner pendingActors={[ACTOR_ESCALATED_TIER1]} onAction={vi.fn()} />)

    const tierBadge = screen.getByTestId('triage-chip-tier')
    expect(tierBadge).toBeInTheDocument()
    expect(tierBadge).toHaveTextContent('T1')
  })

  it('shows T2 tier badge for tier-2 actor', () => {
    render(<TriageBanner pendingActors={[ACTOR_ESCALATED_TIER2]} onAction={vi.fn()} />)

    const tierBadge = screen.getByTestId('triage-chip-tier')
    expect(tierBadge).toHaveTextContent('T2')
  })

  // No escalation verdict → no justification / disposition / tier rendered (no regression)
  it('does NOT render justification, disposition trigger, or tier badge when actor has no escalation', () => {
    render(<TriageBanner pendingActors={[ACTOR_NO_ESCALATION]} onAction={vi.fn()} />)

    // None of these are in the DOM when there is no escalation verdict
    expect(screen.queryByTestId('triage-chip-justification')).toBeNull()
    expect(screen.queryByTestId('triage-chip-disposition')).toBeNull()
    expect(screen.queryByTestId('triage-chip-block-status')).toBeNull()
    expect(screen.queryByTestId('triage-chip-tier')).toBeNull()
  })

  // Security (ADR-0029 D3): justification rendered as text node, not markup
  it('renders justification as plain text — no script injection (ADR-0029 D3)', async () => {
    const xssEsc: EscalationVerdict = {
      ...ESCALATION_TIER1,
      justification: '<script>alert("xss-in-justification")</script>',
    }
    const xssActor: ThreatScore = {
      ...ACTOR_ESCALATED_TIER1,
      escalation: xssEsc,
    }
    render(<TriageBanner pendingActors={[xssActor]} onAction={vi.fn()} />)

    // Open the popover to reveal the justification
    await userEvent.click(screen.getByTestId('triage-chip-disposition'))

    // The raw string must appear as visible text
    expect(
      screen.getByText('<script>alert("xss-in-justification")</script>'),
    ).toBeInTheDocument()
    // No live script element with this content should exist
    document.querySelectorAll('script').forEach((el) => {
      expect(el.textContent).not.toContain('xss-in-justification')
    })
  })

  // WHILE queue is empty → 4-tier legend present
  it('shows escalation legend with 4 tier rows when queue is empty', () => {
    render(<TriageBanner pendingActors={[]} onAction={vi.fn()} />)

    expect(screen.getByTestId('escalation-legend')).toBeInTheDocument()
    expect(screen.getByTestId('legend-tier-1')).toBeInTheDocument()
    expect(screen.getByTestId('legend-tier-2')).toBeInTheDocument()
    expect(screen.getByTestId('legend-tier-3')).toBeInTheDocument()
    expect(screen.getByTestId('legend-tier-4')).toBeInTheDocument()
  })

  // Legend text content: tier 1 label
  it('legend tier-1 shows "Got through — possible breach"', () => {
    render(<TriageBanner pendingActors={[]} onAction={vi.fn()} />)

    const tier1 = screen.getByTestId('legend-tier-1')
    expect(tier1).toHaveTextContent('Got through — possible breach')
  })

  // Legend text content: tier 2 label
  it('legend tier-2 shows "Flagged — needs review"', () => {
    render(<TriageBanner pendingActors={[]} onAction={vi.fn()} />)

    const tier2 = screen.getByTestId('legend-tier-2')
    expect(tier2).toHaveTextContent('Flagged — needs review')
  })

  // Legend block-status badges
  it('legend tier-1 block-status badge shows "Got through"', () => {
    render(<TriageBanner pendingActors={[]} onAction={vi.fn()} />)

    expect(screen.getByTestId('legend-block-status-1')).toHaveTextContent('Got through')
  })

  it('legend tier-2 block-status badge shows "Unconfirmed"', () => {
    render(<TriageBanner pendingActors={[]} onAction={vi.fn()} />)

    expect(screen.getByTestId('legend-block-status-2')).toHaveTextContent('Unconfirmed')
  })

  // Issue #6: the legend documents the two-axis "zero tuning" model as a feature
  it('legend shows a "zero tuning required" note explaining the two-axis model', () => {
    render(<TriageBanner pendingActors={[]} onAction={vi.fn()} />)

    const note = screen.getByTestId('legend-zero-tuning-note')
    expect(note).toHaveTextContent('no threshold to tune')
  })

  // Legend NOT shown when actors are pending (calm state only)
  it('does NOT show the escalation legend when the banner is active', () => {
    render(<TriageBanner pendingActors={[ACTOR_ESCALATED_TIER1]} onAction={vi.fn()} />)

    expect(screen.queryByTestId('escalation-legend')).toBeNull()
  })

  // No inner scrollbar — the banner/legend must not set overflow:scroll/auto (house rule)
  it('active banner container has no overflow:scroll/auto (no inner scrollbar)', () => {
    render(<TriageBanner pendingActors={[ACTOR_ESCALATED_TIER1]} onAction={vi.fn()} />)

    const banner = screen.getByTestId('triage-banner-active')
    const style = banner.getAttribute('style') ?? ''
    expect(style).not.toMatch(/overflow\s*:\s*(scroll|auto)/)
  })

  it('calm banner container (with legend) has no overflow:scroll/auto (no inner scrollbar)', () => {
    render(<TriageBanner pendingActors={[]} onAction={vi.fn()} />)

    const banner = screen.getByTestId('triage-banner-calm')
    const style = banner.getAttribute('style') ?? ''
    expect(style).not.toMatch(/overflow\s*:\s*(scroll|auto)/)
  })

  // Dismiss still works when escalation is present (no regression)
  it('dismiss button still calls onAction when escalation is present', async () => {
    const onAction: OnAction = vi.fn()
    render(<TriageBanner pendingActors={[ACTOR_ESCALATED_TIER1]} onAction={onAction} />)

    await userEvent.click(screen.getByTestId('triage-chip-dismiss'))
    expect(onAction).toHaveBeenCalledWith(ACTOR_ESCALATED_TIER1, 'dismiss')
  })

  // Mixed actors: escalated + non-escalated in same banner
  it('renders chips for both escalated and non-escalated actors together', async () => {
    render(
      <TriageBanner
        pendingActors={[ACTOR_ESCALATED_TIER1, ACTOR_NO_ESCALATION]}
        onAction={vi.fn()}
      />,
    )

    const chips = screen.getAllByTestId('triage-actor-chip')
    expect(chips).toHaveLength(2)
    // Justification is NOT on the chip face before the popover is opened
    expect(screen.queryByTestId('triage-chip-justification')).toBeNull()
    // Only the escalated chip has a popover trigger (disposition label)
    expect(screen.getAllByTestId('triage-chip-disposition')).toHaveLength(1)
    // Open the popover → justification becomes visible
    await userEvent.click(screen.getByTestId('triage-chip-disposition'))
    expect(screen.getAllByTestId('triage-chip-justification')).toHaveLength(1)
  })

  // ---------------------------------------------------------------------------
  // Issue #708: single-row chip + disposition popover
  // ---------------------------------------------------------------------------

  // EARS: chip is a single row (flexDirection row) — no column stacking
  it('chip renders on a single row (flexDirection: row, no column stacking)', () => {
    render(<TriageBanner pendingActors={[ACTOR_ESCALATED_TIER1]} onAction={vi.fn()} />)

    const chip = screen.getByTestId('triage-actor-chip')
    // The chip must NOT use column layout
    expect(chip).not.toHaveStyle({ flexDirection: 'column' })
  })

  // EARS: justification and block-status are NOT on the chip face before popover open
  it('does NOT render justification or block-status on the chip face (issue #708)', () => {
    render(<TriageBanner pendingActors={[ACTOR_ESCALATED_TIER1]} onAction={vi.fn()} />)

    expect(screen.queryByTestId('triage-chip-justification')).toBeNull()
    expect(screen.queryByTestId('triage-chip-block-status')).toBeNull()
  })

  // EARS: clicking the disposition label opens the popover with block-status and justification
  it('clicking the disposition trigger opens the popover with block-status + justification (issue #708)', async () => {
    render(<TriageBanner pendingActors={[ACTOR_ESCALATED_TIER1]} onAction={vi.fn()} />)

    // Disposition trigger is always visible
    const trigger = screen.getByTestId('triage-chip-disposition')
    expect(trigger).toBeInTheDocument()
    // Popover content not yet in DOM
    expect(screen.queryByTestId('triage-chip-justification')).toBeNull()
    expect(screen.queryByTestId('triage-chip-block-status')).toBeNull()

    // Click opens popover
    await userEvent.click(trigger)

    // Block-status framing now visible
    const bsEl = screen.getByTestId('triage-chip-block-status')
    expect(bsEl).toBeInTheDocument()
    expect(bsEl).toHaveTextContent('Got through — possible breach')
    expect(bsEl).toHaveTextContent('Got through')

    // Full justification now visible
    const justEl = screen.getByTestId('triage-chip-justification')
    expect(justEl).toBeInTheDocument()
    expect(justEl).toHaveTextContent(ESCALATION_TIER1.justification)
  })

  // EARS: dismiss button shows ✕ icon (not the word "Dismiss")
  it('dismiss button shows ✕ icon, not the word "Dismiss" (issue #708)', () => {
    render(<TriageBanner pendingActors={[ACTOR_ESCALATED_TIER1]} onAction={vi.fn()} />)

    const btn = screen.getByTestId('triage-chip-dismiss')
    expect(btn).toHaveTextContent('✕')
    expect(btn).not.toHaveTextContent('Dismiss')
  })

  // EARS: no-verdict chip renders IP + Dismiss only — no tier, no popover trigger
  it('no-verdict chip renders IP + Dismiss only (no tier badge, no popover trigger) (issue #708)', () => {
    render(<TriageBanner pendingActors={[ACTOR_NO_ESCALATION]} onAction={vi.fn()} />)

    // IP is present
    expect(screen.getByTestId('clickable-ip')).toBeInTheDocument()
    // Dismiss is present
    expect(screen.getByTestId('triage-chip-dismiss')).toBeInTheDocument()
    // No tier badge, no disposition trigger, no block-status, no justification
    expect(screen.queryByTestId('triage-chip-tier')).toBeNull()
    expect(screen.queryByTestId('triage-chip-disposition')).toBeNull()
    expect(screen.queryByTestId('triage-chip-block-status')).toBeNull()
    expect(screen.queryByTestId('triage-chip-justification')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// ADR-0058 Amendment 1 (issue #726) — partial block_status + disposition_counts
// ---------------------------------------------------------------------------

/** Partial escalation verdict fixture with disposition_counts (the common mixed-actor case). */
const ESCALATION_PARTIAL_WITH_COUNTS: EscalationVerdict = {
  tier: 2,
  disposition: 'block_status_unknown',
  justification: '[RULE] Mixed disposition — actor has both blocked and alert-only events',
  block_status: 'partial',
  disposition_counts: {
    blocked: 9,
    alert_unknown: 298,
    allowed: 0,
  },
}

/** Partial escalation verdict WITHOUT disposition_counts — tests graceful degradation. */
const ESCALATION_PARTIAL_NO_COUNTS: EscalationVerdict = {
  tier: 2,
  disposition: 'block_status_unknown',
  justification: '[RULE] Mixed disposition — older backend without counts',
  block_status: 'partial',
  // disposition_counts intentionally absent
}

/** Actor with partial block_status and counts. */
const ACTOR_PARTIAL_WITH_COUNTS: ThreatScore = {
  ...ACTOR_HIGH,
  source_ip: '192.0.2.50',
  escalation: ESCALATION_PARTIAL_WITH_COUNTS,
}

/** Actor with partial block_status but no counts (older API response). */
const ACTOR_PARTIAL_NO_COUNTS: ThreatScore = {
  ...ACTOR_HIGH,
  source_ip: '192.0.2.51',
  escalation: ESCALATION_PARTIAL_NO_COUNTS,
}

describe('TriageBanner — ADR-0058 Amendment 1 partial block_status (issue #726)', () => {
  // EARS-1: WHERE block_status === "partial", label derives from disposition_counts
  it('EARS-1: block-status label shows "N blocked · M unconfirmed" from disposition_counts', async () => {
    render(<TriageBanner pendingActors={[ACTOR_PARTIAL_WITH_COUNTS]} onAction={vi.fn()} />)

    // Open the popover to reveal the block-status element
    await userEvent.click(screen.getByTestId('triage-chip-disposition'))

    const bsEl = screen.getByTestId('triage-chip-block-status')
    expect(bsEl).toHaveTextContent('9 blocked · 298 unconfirmed')
  })

  // EARS-1: label must NOT show the raw key "partial"
  it('EARS-1: block-status label does NOT show the raw key "partial" when counts are present', async () => {
    render(<TriageBanner pendingActors={[ACTOR_PARTIAL_WITH_COUNTS]} onAction={vi.fn()} />)

    await userEvent.click(screen.getByTestId('triage-chip-disposition'))

    const bsEl = screen.getByTestId('triage-chip-block-status')
    expect(bsEl).not.toHaveTextContent('partial')
  })

  // EARS-2: popover shows the per-class count breakdown when partial
  it('EARS-2: popover shows per-class count breakdown (triage-chip-disposition-counts)', async () => {
    render(<TriageBanner pendingActors={[ACTOR_PARTIAL_WITH_COUNTS]} onAction={vi.fn()} />)

    // Counts breakdown is inside the popover — not visible before opening
    expect(screen.queryByTestId('triage-chip-disposition-counts')).toBeNull()

    await userEvent.click(screen.getByTestId('triage-chip-disposition'))

    const countsEl = screen.getByTestId('triage-chip-disposition-counts')
    expect(countsEl).toBeInTheDocument()
    // Shows all three classes as text nodes
    expect(countsEl).toHaveTextContent('9')
    expect(countsEl).toHaveTextContent('blocked')
    expect(countsEl).toHaveTextContent('298')
    expect(countsEl).toHaveTextContent('unconfirmed')
    expect(countsEl).toHaveTextContent('0')
    expect(countsEl).toHaveTextContent('got through')
  })

  // EARS-2: counts are text nodes only (ADR-0029 D3) — no dangerouslySetInnerHTML
  it('EARS-2: disposition counts rendered as text nodes (ADR-0029 D3)', async () => {
    render(<TriageBanner pendingActors={[ACTOR_PARTIAL_WITH_COUNTS]} onAction={vi.fn()} />)

    await userEvent.click(screen.getByTestId('triage-chip-disposition'))

    const countsEl = screen.getByTestId('triage-chip-disposition-counts')
    // Must be a text node, not an innerHTML injection
    expect(countsEl.innerHTML).not.toContain('<script')
    expect(countsEl.innerHTML).not.toContain('dangerouslySetInnerHTML')
  })

  // EARS-3: legend shows 4 tier rows + one explanatory partial note (no 5th tier row)
  it('EARS-3: calm legend has 4 tier rows + one partial explanatory note', () => {
    render(<TriageBanner pendingActors={[]} onAction={vi.fn()} />)

    // Still exactly 4 tier rows
    expect(screen.getByTestId('legend-tier-1')).toBeInTheDocument()
    expect(screen.getByTestId('legend-tier-2')).toBeInTheDocument()
    expect(screen.getByTestId('legend-tier-3')).toBeInTheDocument()
    expect(screen.getByTestId('legend-tier-4')).toBeInTheDocument()
    // No 5th tier row
    expect(screen.queryByTestId('legend-tier-5')).toBeNull()

    // Explanatory note about partial actors is present
    const partialNote = screen.getByTestId('legend-partial-note')
    expect(partialNote).toBeInTheDocument()
  })

  // EARS-3: legend partial note contains the required text (no inner scrollbar)
  it('EARS-3: partial note contains "partial" and "queued by its loudest events"', () => {
    render(<TriageBanner pendingActors={[]} onAction={vi.fn()} />)

    const partialNote = screen.getByTestId('legend-partial-note')
    expect(partialNote).toHaveTextContent('partial')
    expect(partialNote).toHaveTextContent('queued by its loudest events')
  })

  // EARS-3: legend has no inner scrollbar (house rule)
  it('EARS-3: legend container has no overflow:scroll/auto (house rule)', () => {
    render(<TriageBanner pendingActors={[]} onAction={vi.fn()} />)

    const legend = screen.getByTestId('escalation-legend')
    const style = legend.getAttribute('style') ?? ''
    expect(style).not.toMatch(/overflow\s*:\s*(scroll|auto)/)
  })

  // EARS-4: text node only — no dangerouslySetInnerHTML for labels (ADR-0029 D3)
  it('EARS-4: block-status label is a text node (ADR-0029 D3)', async () => {
    render(<TriageBanner pendingActors={[ACTOR_PARTIAL_WITH_COUNTS]} onAction={vi.fn()} />)

    await userEvent.click(screen.getByTestId('triage-chip-disposition'))

    const bsEl = screen.getByTestId('triage-chip-block-status')
    expect(bsEl.innerHTML).not.toContain('<script')
  })

  // EARS-5 (graceful degradation): counts absent → label falls back to "Partial" (not raw key, not error)
  it('EARS-5 graceful degradation: "Partial" label when disposition_counts absent', async () => {
    render(<TriageBanner pendingActors={[ACTOR_PARTIAL_NO_COUNTS]} onAction={vi.fn()} />)

    await userEvent.click(screen.getByTestId('triage-chip-disposition'))

    const bsEl = screen.getByTestId('triage-chip-block-status')
    // Graceful: shows "Partial" (human-readable), not the raw key "partial"
    expect(bsEl).toHaveTextContent('Partial')
  })

  // EARS-5 (graceful degradation): no counts breakdown rendered when disposition_counts absent
  it('EARS-5 graceful degradation: no counts breakdown when disposition_counts absent', async () => {
    render(<TriageBanner pendingActors={[ACTOR_PARTIAL_NO_COUNTS]} onAction={vi.fn()} />)

    await userEvent.click(screen.getByTestId('triage-chip-disposition'))

    // The per-class breakdown element must not appear
    expect(screen.queryByTestId('triage-chip-disposition-counts')).toBeNull()
  })

  // EARS-5 (no regression): single-class "blocked" actor renders exactly as before
  it('EARS-5 no regression: "blocked" actor renders "Blocked" (no change to pre-amendment label)', async () => {
    const blockedEsc: EscalationVerdict = {
      tier: 3,
      disposition: 'blocked_persistent',
      justification: '[RULE] Blocked persistent attacker',
      block_status: 'blocked',
    }
    const blockedActor: ThreatScore = { ...ACTOR_HIGH, source_ip: '192.0.2.60', escalation: blockedEsc }
    render(<TriageBanner pendingActors={[blockedActor]} onAction={vi.fn()} />)

    await userEvent.click(screen.getByTestId('triage-chip-disposition'))

    const bsEl = screen.getByTestId('triage-chip-block-status')
    expect(bsEl).toHaveTextContent('Blocked')
    // No counts breakdown for single-class
    expect(screen.queryByTestId('triage-chip-disposition-counts')).toBeNull()
  })

  // EARS-5 (no regression): single-class "unknown" status renders without a counts breakdown
  // (issue #6 updates the label text itself to "Unconfirmed" — see escalationCopy.ts)
  it('EARS-5 no regression: "unknown" actor renders "Unconfirmed", no counts breakdown', async () => {
    const unknownEsc: EscalationVerdict = {
      tier: 2,
      disposition: 'block_status_unknown',
      justification: '[RULE] Suricata ALERT — terminating disposition not asserted',
      block_status: 'unknown',
    }
    const unknownActor: ThreatScore = { ...ACTOR_HIGH, source_ip: '192.0.2.61', escalation: unknownEsc }
    render(<TriageBanner pendingActors={[unknownActor]} onAction={vi.fn()} />)

    await userEvent.click(screen.getByTestId('triage-chip-disposition'))

    const bsEl = screen.getByTestId('triage-chip-block-status')
    expect(bsEl).toHaveTextContent('Unconfirmed')
    expect(screen.queryByTestId('triage-chip-disposition-counts')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Issue #728 — top-N / view-all / tier-group headers
// ---------------------------------------------------------------------------

/** Build N distinct actors with a given escalation tier for #728 tests. */
function makeActors(
  count: number,
  tier: number,
  disposition: string,
  baseScore = 80,
): ThreatScore[] {
  return Array.from({ length: count }, (_, i) => ({
    ...ACTOR_CRITICAL,
    source_ip: `10.${tier}.0.${i + 1}`,
    score: baseScore - i, // descending score so first is loudest
    escalation: {
      tier,
      disposition,
      justification: `[RULE] test actor ${i + 1}`,
      block_status: 'blocked' as const,
    },
  }))
}

describe('TriageBanner — #728 top-N + view-all + tier headers', () => {
  // EARS-1: WHILE count <= TOP_ACTORS_DEFAULT → all chips shown, no expander
  it('shows all chips when count is at or below TOP_ACTORS_DEFAULT (no expander)', () => {
    const actors = makeActors(TOP_ACTORS_DEFAULT, 3, 'blocked_persistent')
    render(<TriageBanner pendingActors={actors} onAction={vi.fn()} />)

    expect(screen.getAllByTestId('triage-actor-chip')).toHaveLength(TOP_ACTORS_DEFAULT)
    expect(screen.queryByTestId('triage-view-all')).toBeNull()
  })

  // EARS-1: WHILE count > TOP_ACTORS_DEFAULT → only top-N shown by default
  it('shows only top-N chips by default when count > TOP_ACTORS_DEFAULT', () => {
    const actors = makeActors(TOP_ACTORS_DEFAULT + 5, 3, 'blocked_persistent')
    render(<TriageBanner pendingActors={actors} onAction={vi.fn()} />)

    expect(screen.getAllByTestId('triage-actor-chip')).toHaveLength(TOP_ACTORS_DEFAULT)
  })

  // EARS-1: "view all N" control is present when truncated
  it('shows "view all N actors" expander when more than TOP_N actors are pending', () => {
    const total = TOP_ACTORS_DEFAULT + 10
    const actors = makeActors(total, 3, 'blocked_persistent')
    render(<TriageBanner pendingActors={actors} onAction={vi.fn()} />)

    const expander = screen.getByTestId('triage-view-all')
    expect(expander).toBeInTheDocument()
    // Should mention the total count
    expect(expander).toHaveTextContent(String(total))
  })

  // EARS-3: WHEN "view all" is activated → all actors visible, no inner scrollbar
  it('EARS-3: clicking "view all" reveals all remaining actors', async () => {
    const total = TOP_ACTORS_DEFAULT + 5
    const actors = makeActors(total, 3, 'blocked_persistent')
    render(<TriageBanner pendingActors={actors} onAction={vi.fn()} />)

    // Before: only TOP_N chips visible
    expect(screen.getAllByTestId('triage-actor-chip')).toHaveLength(TOP_ACTORS_DEFAULT)

    // Click "view all"
    await userEvent.click(screen.getByTestId('triage-view-all'))

    // After: all chips visible
    expect(screen.getAllByTestId('triage-actor-chip')).toHaveLength(total)
  })

  // EARS-3: no inner scrollbar after view-all expands
  it('EARS-3: active banner has no overflow:scroll/auto after expansion (house rule)', async () => {
    const total = TOP_ACTORS_DEFAULT + 5
    const actors = makeActors(total, 3, 'blocked_persistent')
    render(<TriageBanner pendingActors={actors} onAction={vi.fn()} />)

    await userEvent.click(screen.getByTestId('triage-view-all'))

    const banner = screen.getByTestId('triage-banner-active')
    const style = banner.getAttribute('style') ?? ''
    expect(style).not.toMatch(/overflow\s*:\s*(scroll|auto)/)
  })

  // EARS-4: top-N is the loudest slice — the first N actors in the existing sort order
  it('EARS-4: top-N is the loudest slice — first chips are highest-score actors', () => {
    // Build actors with descending scores so first is loudest
    const actors = Array.from({ length: TOP_ACTORS_DEFAULT + 3 }, (_, i) => ({
      ...ACTOR_CRITICAL,
      source_ip: `10.3.0.${i + 1}`,
      score: 100 - i, // descending
      escalation: null,
    }))
    render(<TriageBanner pendingActors={actors} onAction={vi.fn()} />)

    // Top-N chips shown → the first IP (highest score) must be present
    const chips = screen.getAllByTestId('triage-actor-chip')
    expect(chips).toHaveLength(TOP_ACTORS_DEFAULT)
    // The highest-score actor (10.3.0.1) is in the visible set
    expect(screen.getByText('10.3.0.1')).toBeInTheDocument()
    // The last actor (beyond top-N) is hidden
    expect(screen.queryByText(`10.3.0.${TOP_ACTORS_DEFAULT + 1}`)).toBeNull()
  })

  // EARS-2: actors grouped under tier-group headers when spanning multiple tiers
  it('EARS-2: groups actors under tier-group headers when actors span multiple tiers', () => {
    const tier2Actors = makeActors(3, 2, 'block_status_unknown', 90)
    const tier3Actors = makeActors(3, 3, 'blocked_persistent', 70)
    // Pre-sorted: tier 2 first (louder), then tier 3
    const actors = [...tier2Actors, ...tier3Actors]

    render(<TriageBanner pendingActors={actors} onAction={vi.fn()} />)

    const headers = screen.getAllByTestId('triage-tier-header')
    expect(headers.length).toBeGreaterThanOrEqual(2)

    // The tier-2 header should contain "Tier 2" and "Flagged"
    const tier2Header = headers.find((h) => h.textContent?.includes('Tier 2'))
    expect(tier2Header).toBeInTheDocument()
    expect(tier2Header).toHaveTextContent('Flagged')

    // The tier-3 header should contain "Tier 3" and "Blocked, repeated"
    const tier3Header = headers.find((h) => h.textContent?.includes('Tier 3'))
    expect(tier3Header).toBeInTheDocument()
    expect(tier3Header).toHaveTextContent('Blocked, repeated')
  })

  // EARS-2: tier header shows actor count for that tier
  it('EARS-2: tier-group header shows actor count for the tier', () => {
    const tier2Actors = makeActors(4, 2, 'block_status_unknown', 90)
    const tier3Actors = makeActors(2, 3, 'blocked_persistent', 70)
    const actors = [...tier2Actors, ...tier3Actors]

    render(<TriageBanner pendingActors={actors} onAction={vi.fn()} />)

    const headers = screen.getAllByTestId('triage-tier-header')
    const tier2Header = headers.find((h) => h.textContent?.includes('Tier 2'))!
    // Shows "(4)" for tier 2
    expect(tier2Header).toHaveTextContent('(4)')
  })

  // EARS-2: single-tier scenario — tier header shown for the group
  it('EARS-2: shows tier-group header even with a single tier', () => {
    const actors = makeActors(3, 1, 'allowed_through', 90)
    render(<TriageBanner pendingActors={actors} onAction={vi.fn()} />)

    const headers = screen.getAllByTestId('triage-tier-header')
    expect(headers.length).toBeGreaterThanOrEqual(1)
    expect(headers[0]).toHaveTextContent('Tier 1')
    expect(headers[0]).toHaveTextContent('Got through')
  })

  // Tier groups + view-all work together correctly
  it('tier groups + view-all: shows correct counts after expansion', async () => {
    const tier2Actors = makeActors(TOP_ACTORS_DEFAULT, 2, 'block_status_unknown', 90)
    const tier3Actors = makeActors(5, 3, 'blocked_persistent', 70)
    const actors = [...tier2Actors, ...tier3Actors]

    render(<TriageBanner pendingActors={actors} onAction={vi.fn()} />)

    // Before expansion: only TOP_N chips
    expect(screen.getAllByTestId('triage-actor-chip')).toHaveLength(TOP_ACTORS_DEFAULT)

    // Expand
    await userEvent.click(screen.getByTestId('triage-view-all'))

    // After expansion: all chips visible
    expect(screen.getAllByTestId('triage-actor-chip')).toHaveLength(actors.length)
  })

  // Expander is not shown when count is exactly TOP_ACTORS_DEFAULT
  it('expander absent when count equals TOP_ACTORS_DEFAULT exactly', () => {
    const actors = makeActors(TOP_ACTORS_DEFAULT, 3, 'blocked_persistent')
    render(<TriageBanner pendingActors={actors} onAction={vi.fn()} />)

    expect(screen.queryByTestId('triage-view-all')).toBeNull()
  })

  // Dismiss still works inside a tier group (no regression)
  it('dismiss button inside tier-group calls onAction correctly (no regression)', async () => {
    const onAction: OnAction = vi.fn()
    const actors = makeActors(2, 2, 'block_status_unknown', 90)
    render(<TriageBanner pendingActors={actors} onAction={onAction} />)

    // Click the first dismiss button
    const dismissBtns = screen.getAllByTestId('triage-chip-dismiss')
    await userEvent.click(dismissBtns[0])

    expect(onAction).toHaveBeenCalledTimes(1)
    expect(onAction).toHaveBeenCalledWith(actors[0], 'dismiss')
  })

  // No inner scrollbar introduced by tier groups container (house rule)
  it('tier-group container has no overflow:scroll/auto (house rule)', () => {
    const actors = makeActors(3, 2, 'block_status_unknown', 90)
    render(<TriageBanner pendingActors={actors} onAction={vi.fn()} />)

    const groups = screen.getAllByTestId('triage-tier-group')
    for (const group of groups) {
      const style = group.getAttribute('style') ?? ''
      expect(style).not.toMatch(/overflow\s*:\s*(scroll|auto)/)
    }
  })
})

// ---------------------------------------------------------------------------
// Observed-stratum aggregate record line (issue #43, ADR-0067 D2/D5)
//
// EARS criteria under test:
//   - WHEN observedRecord is null/absent → no aggregate line renders, in
//     either the calm or active state.
//   - WHEN observedRecord is present → the banner renders ONE line built from
//     its engine integers (never re-derived, never attacker-controlled text),
//     in BOTH the calm and active states.
//   - The line's link navigates to Network Logs (/logs).
//   - The tier legend gains one "Observed" row (bounded, no inner scrollbar).
// ---------------------------------------------------------------------------

describe('TriageBanner — observed-stratum aggregate record line (issue #43)', () => {
  const RECORD: ObservedRecordSummary = { eventCount: 42, sourceCount: 3 }

  it('does NOT render the aggregate line when observedRecord is absent (calm state)', () => {
    render(<TriageBanner pendingActors={[]} onAction={vi.fn()} />)
    expect(screen.queryByTestId('triage-observed-record')).toBeNull()
  })

  it('does NOT render the aggregate line when observedRecord is null (calm state)', () => {
    render(<TriageBanner pendingActors={[]} onAction={vi.fn()} observedRecord={null} />)
    expect(screen.queryByTestId('triage-observed-record')).toBeNull()
  })

  it('does NOT render the aggregate line when observedRecord is absent (active state)', () => {
    render(<TriageBanner pendingActors={[ACTOR_ESCALATED_TIER1]} onAction={vi.fn()} />)
    expect(screen.queryByTestId('triage-observed-record')).toBeNull()
  })

  it('renders the aggregate line in the calm state when observedRecord is present', () => {
    render(<TriageBanner pendingActors={[]} onAction={vi.fn()} observedRecord={RECORD} />)

    const line = screen.getByTestId('triage-observed-record')
    expect(line).toHaveTextContent('42 detections on the record from 3 sources')
  })

  it('renders the aggregate line in the active state when observedRecord is present', () => {
    render(
      <TriageBanner
        pendingActors={[ACTOR_ESCALATED_TIER1]}
        onAction={vi.fn()}
        observedRecord={RECORD}
      />,
    )

    const line = screen.getByTestId('triage-observed-record')
    expect(line).toHaveTextContent('42 detections on the record from 3 sources')
  })

  it('singularizes "detection" and "source" when counts are 1', () => {
    render(
      <TriageBanner
        pendingActors={[]}
        onAction={vi.fn()}
        observedRecord={{ eventCount: 1, sourceCount: 1 }}
      />,
    )

    const line = screen.getByTestId('triage-observed-record')
    expect(line).toHaveTextContent('1 detection on the record from 1 source')
    expect(line).not.toHaveTextContent('1 detections')
    expect(line).not.toHaveTextContent('1 sources')
  })

  it('clicking the Network Logs link navigates to /logs', async () => {
    mockNavigate.mockClear()
    render(<TriageBanner pendingActors={[]} onAction={vi.fn()} observedRecord={RECORD} />)

    await userEvent.click(screen.getByTestId('triage-observed-record-link'))

    expect(mockNavigate).toHaveBeenCalledOnce()
    expect(mockNavigate).toHaveBeenCalledWith('/logs')
  })

  it('renders the record line as text nodes only (ADR-0029 D3 — no injection surface)', () => {
    render(<TriageBanner pendingActors={[]} onAction={vi.fn()} observedRecord={RECORD} />)

    expect(document.querySelectorAll('script').length).toBe(0)
  })

  it('calm banner container (with observed line + legend) has no overflow:scroll/auto', () => {
    render(<TriageBanner pendingActors={[]} onAction={vi.fn()} observedRecord={RECORD} />)

    const banner = screen.getByTestId('triage-banner-calm')
    const style = banner.getAttribute('style') ?? ''
    expect(style).not.toMatch(/overflow\s*:\s*(scroll|auto)/)
  })

  // Legend gains an "Observed" row (ADR-0067 D2) — bounded block, no 5th tier number
  it('legend shows an "Observed" row alongside the 4 tier rows', () => {
    render(<TriageBanner pendingActors={[]} onAction={vi.fn()} />)

    const observedRow = screen.getByTestId('legend-tier-observed')
    expect(observedRow).toHaveTextContent('On the record — no escalation claim')
    // The 4 numbered tiers are still present, unchanged
    expect(screen.getByTestId('legend-tier-1')).toBeInTheDocument()
    expect(screen.getByTestId('legend-tier-4')).toBeInTheDocument()
  })

  it('legend Observed row has no inner scrollbar (house rule)', () => {
    render(<TriageBanner pendingActors={[]} onAction={vi.fn()} />)

    const observedRow = screen.getByTestId('legend-tier-observed')
    const style = observedRow.getAttribute('style') ?? ''
    expect(style).not.toMatch(/overflow\s*:\s*(scroll|auto)/)
  })
})
