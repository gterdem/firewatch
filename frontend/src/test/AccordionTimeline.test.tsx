/**
 * Tests for AccordionTimeline + SectionChips (issue #270).
 *
 * EARS criteria covered:
 *
 * AccordionTimeline:
 *   - WHEN events ≤ threshold, all events render as notable rows (no cluster).
 *   - WHEN events > threshold, routine events collapse into cluster rows.
 *   - WHEN a cluster row is activated (click), IT SHALL expand in-place.
 *   - Collapsing SHALL restore the summary row.
 *   - Notable events SHALL always be rendered (visible without clicking).
 *   - THE panel body SHALL NOT gain an inner fixed-height scrollbar (no overflow:auto on accordion).
 *   - Bucket labels go through lib/time seam (contain "–" separator).
 *   - "+N routine events" expander shows the correct count.
 *   - Correlated events render with data-correlated="true".
 *
 * SectionChips:
 *   - WHEN rendered, chips (Score · AI · Timeline · Logs) appear.
 *   - WHEN a chip is activated, scrollIntoView is called on the target element.
 *   - Keyboard: chips are buttons (Tab-focusable, Enter/Space activates).
 *
 * #337 time-format (EARS):
 *   - Ubiquitous: every timestamp in the AccordionTimeline SHALL render via TimeText/lib/time.ts.
 *     No raw ISO strings visible at rest.
 *   - WHEN the user hovers a time value, the title attribute SHALL hold the absolute UTC string.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, within, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { AccordionTimeline } from '../components/entity/ip/timeline/AccordionTimeline'
import { SectionChips } from '../components/entity/SectionChips'
import type { IpTimelineEventItem } from '../api/types'
import { IP_EVENTS_SINGLE_SOURCE_FIXTURE, IP_EVENTS_CORRELATED_FIXTURE } from './readFixtures'

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

function makeEvent(overrides: Partial<IpTimelineEventItem> & { time: string }): IpTimelineEventItem {
  return {
    source: overrides.source ?? 'suricata',
    time: overrides.time,
    label: overrides.label ?? null,
    payload: overrides.payload ?? null,
    correlated: overrides.correlated ?? false,
    action: overrides.action ?? 'ALERT',
    severity: overrides.severity ?? null,
    category: overrides.category ?? null,
  }
}

/** Build N routine (non-notable, non-correlated, same-rule) events spread across hours. */
function buildRoutineEvents(count: number): IpTimelineEventItem[] {
  const events: IpTimelineEventItem[] = []
  for (let i = 0; i < count; i++) {
    const hour = 8 + Math.floor(i / 4)
    const min = (i % 4) * 10
    events.push(makeEvent({
      time: `2026-06-04T${String(hour).padStart(2, '0')}:${String(min).padStart(2, '0')}:00Z`,
      label: 'rule-1',
    }))
  }
  return events
}

// ---------------------------------------------------------------------------
// AccordionTimeline — small set (all notable)
// ---------------------------------------------------------------------------

describe('AccordionTimeline — small set (≤ threshold)', () => {
  it('renders all events as notable rows when count ≤ threshold', () => {
    render(
      <AccordionTimeline
        events={IP_EVENTS_SINGLE_SOURCE_FIXTURE.events}
        notableThreshold={10}
      />,
    )
    const timeline = screen.getByTestId('accordion-timeline')
    // 2 events in fixture, both become notable
    const events = within(timeline).getAllByTestId(/^timeline-event-/)
    expect(events).toHaveLength(2)
  })

  it('does NOT render the cluster expander for small sets', () => {
    render(
      <AccordionTimeline
        events={IP_EVENTS_SINGLE_SOURCE_FIXTURE.events}
        notableThreshold={10}
      />,
    )
    expect(screen.queryByTestId('timeline-routine-expander')).not.toBeInTheDocument()
  })

  it('marks first event with data-notable="true"', () => {
    render(
      <AccordionTimeline events={IP_EVENTS_SINGLE_SOURCE_FIXTURE.events} notableThreshold={10} />,
    )
    const firstEvent = screen.getByTestId('timeline-event-0')
    expect(firstEvent).toHaveAttribute('data-notable', 'true')
  })
})

// ---------------------------------------------------------------------------
// AccordionTimeline — large set (cluster rows appear)
// ---------------------------------------------------------------------------

describe('AccordionTimeline — large set (> threshold)', () => {
  it('renders the +N routine events expander when there are clusters', () => {
    const events = buildRoutineEvents(15) // 15 > 10 default threshold
    render(<AccordionTimeline events={events} notableThreshold={10} />)
    expect(screen.getByTestId('timeline-routine-expander')).toBeInTheDocument()
  })

  it('expander label shows the routine event count', () => {
    const events = buildRoutineEvents(15)
    render(<AccordionTimeline events={events} notableThreshold={10} />)
    const expander = screen.getByTestId('timeline-routine-expander')
    // Should say "+N routine events" where N is the cluster count
    expect(expander.textContent).toMatch(/\+\d+ routine events/)
  })

  it('cluster rows are NOT visible before expander is clicked', () => {
    const events = buildRoutineEvents(15)
    render(<AccordionTimeline events={events} notableThreshold={10} />)
    // Cluster toggle buttons should not be visible (clusters hidden)
    expect(screen.queryAllByTestId(/^timeline-cluster-toggle-/).length).toBe(0)
  })

  it('clicking the expander reveals cluster rows', async () => {
    const events = buildRoutineEvents(15)
    render(<AccordionTimeline events={events} notableThreshold={10} />)
    await userEvent.click(screen.getByTestId('timeline-routine-expander'))
    const clusterToggles = screen.getAllByTestId(/^timeline-cluster-toggle-/)
    expect(clusterToggles.length).toBeGreaterThan(0)
  })

  it('clicking the expander again hides cluster rows (toggle)', async () => {
    const events = buildRoutineEvents(15)
    render(<AccordionTimeline events={events} notableThreshold={10} />)
    const expander = screen.getByTestId('timeline-routine-expander')
    await userEvent.click(expander)
    await userEvent.click(expander)
    expect(screen.queryAllByTestId(/^timeline-cluster-toggle-/).length).toBe(0)
  })

  it('notable rows remain visible when clusters are collapsed', () => {
    const events = buildRoutineEvents(15)
    render(<AccordionTimeline events={events} notableThreshold={10} />)
    // First and last events are always notable
    expect(screen.getByTestId('timeline-event-0')).toBeInTheDocument()
    expect(screen.getByTestId(`timeline-event-${events.length - 1}`)).toBeInTheDocument()
  })

  it('accordion container has no fixed height / overflow:auto (no 3rd scrollbar)', () => {
    const events = buildRoutineEvents(15)
    const { container } = render(
      <AccordionTimeline events={events} notableThreshold={10} />,
    )
    const accordion = container.querySelector('[data-testid="accordion-timeline"]')
    expect(accordion).not.toBeNull()
    const style = window.getComputedStyle(accordion!)
    // No overflow:auto or overflow:scroll on the accordion itself
    expect(style.overflowY).not.toBe('auto')
    expect(style.overflowY).not.toBe('scroll')
    expect(style.maxHeight).not.toMatch(/\d/)
  })
})

// ---------------------------------------------------------------------------
// ClusterRow — expand / collapse individual events
// ---------------------------------------------------------------------------

describe('AccordionTimeline — ClusterRow expand/collapse', () => {
  it('clicking a cluster toggle expands its events in-place', async () => {
    const events = buildRoutineEvents(15)
    render(<AccordionTimeline events={events} notableThreshold={10} />)
    // First expand the routine expander
    await userEvent.click(screen.getByTestId('timeline-routine-expander'))
    // Then click a cluster toggle
    const clusterToggle = screen.getAllByTestId(/^timeline-cluster-toggle-/)[0]
    const rowIndex = clusterToggle.getAttribute('data-testid')?.replace('timeline-cluster-toggle-', '')
    await userEvent.click(clusterToggle)
    expect(screen.getByTestId(`timeline-cluster-events-${rowIndex}`)).toBeInTheDocument()
  })

  it('clicking a cluster toggle again collapses its events', async () => {
    const events = buildRoutineEvents(15)
    render(<AccordionTimeline events={events} notableThreshold={10} />)
    await userEvent.click(screen.getByTestId('timeline-routine-expander'))
    const clusterToggle = screen.getAllByTestId(/^timeline-cluster-toggle-/)[0]
    const rowIndex = clusterToggle.getAttribute('data-testid')?.replace('timeline-cluster-toggle-', '')
    await userEvent.click(clusterToggle) // expand
    await userEvent.click(clusterToggle) // collapse
    expect(screen.queryByTestId(`timeline-cluster-events-${rowIndex}`)).not.toBeInTheDocument()
  })

  it('cluster toggle has aria-expanded=false initially', async () => {
    const events = buildRoutineEvents(15)
    render(<AccordionTimeline events={events} notableThreshold={10} />)
    await userEvent.click(screen.getByTestId('timeline-routine-expander'))
    const toggle = screen.getAllByTestId(/^timeline-cluster-toggle-/)[0]
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
  })

  it('cluster toggle has aria-expanded=true after expand', async () => {
    const events = buildRoutineEvents(15)
    render(<AccordionTimeline events={events} notableThreshold={10} />)
    await userEvent.click(screen.getByTestId('timeline-routine-expander'))
    const toggle = screen.getAllByTestId(/^timeline-cluster-toggle-/)[0]
    await userEvent.click(toggle)
    expect(toggle).toHaveAttribute('aria-expanded', 'true')
  })

  it('cluster label contains "–" separator (lib/time formatted)', async () => {
    const events = buildRoutineEvents(15)
    render(<AccordionTimeline events={events} notableThreshold={10} />)
    await userEvent.click(screen.getByTestId('timeline-routine-expander'))
    const toggle = screen.getAllByTestId(/^timeline-cluster-toggle-/)[0]
    expect(toggle.textContent).toContain('–')
  })

  it('cluster row shows event count', async () => {
    const events = buildRoutineEvents(15)
    render(<AccordionTimeline events={events} notableThreshold={10} />)
    await userEvent.click(screen.getByTestId('timeline-routine-expander'))
    const countEls = screen.getAllByTestId(/^cluster-count-/)
    expect(countEls.length).toBeGreaterThan(0)
    // Each count element should have a positive number
    for (const el of countEls) {
      const n = parseInt(el.textContent ?? '', 10)
      expect(n).toBeGreaterThan(0)
    }
  })
})

// ---------------------------------------------------------------------------
// AccordionTimeline — correlated events
// ---------------------------------------------------------------------------

describe('AccordionTimeline — correlated events', () => {
  it('renders correlated entries with data-correlated="true"', () => {
    render(
      <AccordionTimeline
        events={IP_EVENTS_CORRELATED_FIXTURE.events}
        notableThreshold={10}
      />,
    )
    const correlatedEvents = screen.getAllByTestId(/^timeline-event-/).filter(
      (el) => el.getAttribute('data-correlated') === 'true',
    )
    expect(correlatedEvents.length).toBe(IP_EVENTS_CORRELATED_FIXTURE.events.filter((e) => e.correlated).length)
  })

  it('correlated events always render as notable (not hidden in clusters)', () => {
    // Build 15 events where some are correlated — correlated ones must always be visible
    const events: IpTimelineEventItem[] = buildRoutineEvents(15)
    // Inject correlated events at positions 5 and 10
    events[5] = { ...events[5], correlated: true }
    events[10] = { ...events[10], correlated: true }

    render(<AccordionTimeline events={events} notableThreshold={10} />)
    // Even without clicking the expander, the correlated events (at their natural index)
    // should be visible as notable rows
    const notableCorrelated = screen.getAllByTestId(/^timeline-event-/).filter(
      (el) => el.getAttribute('data-correlated') === 'true' && el.getAttribute('data-notable') === 'true',
    )
    expect(notableCorrelated.length).toBeGreaterThan(0)
  })
})

// ---------------------------------------------------------------------------
// SectionChips — render and keyboard
// ---------------------------------------------------------------------------

describe('SectionChips', () => {
  it('renders all provided chips', () => {
    render(
      <SectionChips
        chips={[
          { label: 'Score', targetId: 'ip-section-score' },
          { label: 'AI', targetId: 'ip-section-ai' },
          { label: 'Timeline', targetId: 'ip-section-timeline' },
          { label: 'Logs', targetId: 'ip-section-logs' },
        ]}
      />,
    )
    expect(screen.getByTestId('section-chips')).toBeInTheDocument()
    expect(screen.getByTestId('section-chip-ip-section-score')).toHaveTextContent('Score')
    expect(screen.getByTestId('section-chip-ip-section-ai')).toHaveTextContent('AI')
    expect(screen.getByTestId('section-chip-ip-section-timeline')).toHaveTextContent('Timeline')
    expect(screen.getByTestId('section-chip-ip-section-logs')).toHaveTextContent('Logs')
  })

  it('renders nothing when chips array is empty', () => {
    const { container } = render(<SectionChips chips={[]} />)
    expect(container.firstChild).toBeNull()
  })

  it('chips are button elements (keyboard-operable)', () => {
    render(
      <SectionChips
        chips={[{ label: 'Score', targetId: 'ip-section-score' }]}
      />,
    )
    const chip = screen.getByTestId('section-chip-ip-section-score')
    expect(chip.tagName).toBe('BUTTON')
  })

  it('chip has aria-label "Jump to X section"', () => {
    render(
      <SectionChips
        chips={[{ label: 'Timeline', targetId: 'ip-section-timeline' }]}
      />,
    )
    const chip = screen.getByTestId('section-chip-ip-section-timeline')
    expect(chip).toHaveAttribute('aria-label', 'Jump to Timeline section')
  })

  it('clicking a chip calls scrollIntoView on the target element', async () => {
    // Create the target element in the DOM
    const target = document.createElement('div')
    target.id = 'ip-section-timeline'
    const scrollIntoView = vi.fn()
    target.scrollIntoView = scrollIntoView
    document.body.appendChild(target)

    render(
      <SectionChips
        chips={[{ label: 'Timeline', targetId: 'ip-section-timeline' }]}
      />,
    )
    await userEvent.click(screen.getByTestId('section-chip-ip-section-timeline'))
    expect(scrollIntoView).toHaveBeenCalledWith({ behavior: 'smooth', block: 'start' })

    document.body.removeChild(target)
  })

  it('keyboard Enter activates the chip (scrollIntoView called)', async () => {
    const target = document.createElement('div')
    target.id = 'ip-section-score'
    const scrollIntoView = vi.fn()
    target.scrollIntoView = scrollIntoView
    document.body.appendChild(target)

    render(
      <SectionChips
        chips={[{ label: 'Score', targetId: 'ip-section-score' }]}
      />,
    )
    const chip = screen.getByTestId('section-chip-ip-section-score')
    chip.focus()
    await userEvent.keyboard('{Enter}')
    expect(scrollIntoView).toHaveBeenCalled()

    document.body.removeChild(target)
  })
})

// ---------------------------------------------------------------------------
// AccordionTimeline — no-op when target has no element (chip graceful)
// ---------------------------------------------------------------------------

describe('SectionChips — clicking chip with no target is graceful', () => {
  it('does not throw when target element does not exist', async () => {
    render(
      <SectionChips
        chips={[{ label: 'Missing', targetId: 'nonexistent-section' }]}
      />,
    )
    // Should not throw
    await expect(
      userEvent.click(screen.getByTestId('section-chip-nonexistent-section')),
    ).resolves.not.toThrow()
  })
})

// ---------------------------------------------------------------------------
// IpPanel integration: section chips and accordion appear
// ---------------------------------------------------------------------------

import IpPanel from '../components/entity/ip/IpPanel'
import {
  THREATS_FIXTURE,
  IP_EVENTS_SINGLE_SOURCE_FIXTURE as SINGLE_EVENTS,
} from './readFixtures'

const { mockFetchThreatScore2, mockFetchDetailedAnalysis2, mockFetchRules2, mockFetchIpEvents2 } =
  vi.hoisted(() => ({
    mockFetchThreatScore2: vi.fn(),
    mockFetchDetailedAnalysis2: vi.fn(),
    mockFetchRules2: vi.fn(),
    mockFetchIpEvents2: vi.fn(),
  }))

vi.mock('../api/logs', () => ({
  fetchThreatScore: mockFetchThreatScore2,
  fetchDetailedAnalysis: mockFetchDetailedAnalysis2,
  fetchRules: mockFetchRules2,
  fetchIpEvents: mockFetchIpEvents2,
}))

vi.mock('../api/client', () => ({
  fetchSourceTypes: vi.fn().mockResolvedValue([]),
  fetchThreats: vi.fn().mockResolvedValue([]),
  // Issue #268: useDeepAnalysis calls fetchHealth; default to AI offline so it resolves instantly.
  fetchHealth: vi.fn().mockResolvedValue({
    status: 'ok', ollama_connected: false, ollama_model: null, db_ok: true,
  }),
  // MI-7: useEvidenceChain calls fetchEvidenceChain; never-resolving so it does not affect tests.
  fetchEvidenceChain: vi.fn().mockReturnValue(new Promise(() => {})),
  ApiError: class ApiError extends Error {
    status: number
    constructor(status: number, message: unknown) {
      super(String(message ?? status))
      this.status = status
    }
  },
}))

beforeEach(() => {
  vi.clearAllMocks()
  mockFetchIpEvents2.mockResolvedValue(null)
})

describe('IpPanel — #270 integration', () => {
  it('renders SectionChips with Score/AI/Timeline/Logs at panel top', async () => {
    mockFetchThreatScore2.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis2.mockReturnValue(new Promise(() => {}))
    mockFetchRules2.mockReturnValue(new Promise(() => {}))

    render(<IpPanel ip="192.0.2.1" />)

    await waitFor(() => expect(screen.getByTestId('section-chips')).toBeInTheDocument())
    expect(screen.getByTestId('section-chip-ip-section-score')).toBeInTheDocument()
    expect(screen.getByTestId('section-chip-ip-section-ai')).toBeInTheDocument()
    expect(screen.getByTestId('section-chip-ip-section-timeline')).toBeInTheDocument()
    expect(screen.getByTestId('section-chip-ip-section-logs')).toBeInTheDocument()
  })

  it('renders AccordionTimeline (not flat EventTimeline) for the event timeline', async () => {
    mockFetchThreatScore2.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis2.mockReturnValue(new Promise(() => {}))
    mockFetchRules2.mockReturnValue(new Promise(() => {}))
    mockFetchIpEvents2.mockResolvedValue(SINGLE_EVENTS)

    render(<IpPanel ip="192.0.2.1" />)

    await waitFor(() => expect(screen.getByTestId('accordion-timeline')).toBeInTheDocument())
    // The flat EventTimeline container class should not appear as a root timeline
    // (AccordionTimeline uses data-testid="accordion-timeline", not "fw-evtl")
    expect(document.querySelector('.fw-evtl')).toBeNull()
  })

  it('section id="ip-section-score" present in DOM', async () => {
    mockFetchThreatScore2.mockResolvedValue(THREATS_FIXTURE[0])
    mockFetchDetailedAnalysis2.mockReturnValue(new Promise(() => {}))
    mockFetchRules2.mockReturnValue(new Promise(() => {}))

    render(<IpPanel ip="192.0.2.1" />)

    await waitFor(() => expect(screen.getByTestId('modal-score-section')).toBeInTheDocument())
    expect(document.getElementById('ip-section-score')).not.toBeNull()
  })
})

// ---------------------------------------------------------------------------
// #337 — slide-over timeline time format: relative primary, absolute on hover
// ---------------------------------------------------------------------------

describe('AccordionTimeline #337 — time-format via TimeText/lib/time seam', () => {
  /**
   * Notable rows (always-expanded entries) MUST NOT show raw ISO strings.
   * The time span must use TimeText style="relative" which renders relativeTime()
   * as the visible text and the UTC string in the title attribute.
   * Fixture: IP_EVENTS_SINGLE_SOURCE_FIXTURE has events at '2026-06-04T08:00:00Z'
   * and '2026-06-04T09:00:00Z' — RFC-5737 safe (not real IPs; time strings are not IPs).
   */
  it('#337: notable row time does NOT render the raw ISO source string', () => {
    const rawIso = '2026-06-04T08:00:00Z'
    const event: IpTimelineEventItem = {
      source: 'suricata',
      time: rawIso,
      label: 'ET SCAN',
      payload: null,
      correlated: false,
      action: 'ALERT',
      severity: 'medium',
      category: 'Scan',
    }
    render(<AccordionTimeline events={[event]} notableThreshold={10} />)
    const timeEl = screen.getByTestId('timeline-time-0')
    // Visible text must NOT be the raw ISO — must be relative ("Xd ago", "Xh ago", etc.)
    expect(timeEl.textContent).not.toBe(rawIso)
    expect(timeEl.textContent).not.toMatch(/^\d{4}-\d{2}-\d{2}T/)
  })

  it('#337: notable row time span carries title with absolute UTC string (for hover)', () => {
    const event: IpTimelineEventItem = {
      source: 'suricata',
      time: '2026-06-04T08:00:00Z',
      label: null,
      payload: null,
      correlated: false,
      action: 'ALERT',
      severity: null,
      category: null,
    }
    render(<AccordionTimeline events={[event]} notableThreshold={10} />)
    const timeEl = screen.getByTestId('timeline-time-0')
    // title attribute holds the absolute UTC value (formatUtc output contains "UTC")
    expect(timeEl).toHaveAttribute('title')
    expect(timeEl.getAttribute('title')).toContain('UTC')
  })

  it('#337: cluster expanded-event time does NOT render the raw ISO string', async () => {
    // Build enough events to force clustering (> notableThreshold), then expand
    const events: IpTimelineEventItem[] = buildRoutineEvents(15)
    render(<AccordionTimeline events={events} notableThreshold={3} />)
    // Expand routine events
    await userEvent.click(screen.getByTestId('timeline-routine-expander'))
    // Expand the first cluster
    const toggles = screen.getAllByTestId(/^timeline-cluster-toggle-/)
    await userEvent.click(toggles[0])
    // Get any timeline-time span inside the expanded cluster events
    const timeEls = screen.getAllByTestId(/^timeline-time-/)
    expect(timeEls.length).toBeGreaterThan(0)
    for (const el of timeEls) {
      // Must NOT be a raw ISO string at rest
      expect(el.textContent).not.toMatch(/^\d{4}-\d{2}-\d{2}T/)
      // Must have a title with UTC
      expect(el.getAttribute('title')).toContain('UTC')
    }
  })
})
