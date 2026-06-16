/**
 * Unit tests for ScoreBreakdownPopover + ScoreBadge popover integration (issue #210).
 *
 * EARS acceptance criteria mapped to tests:
 *
 *   EARS 1 — WHEN the analyst activates a ScoreBadge with breakdown data, a popover
 *             SHALL list the top contributing factors with their points.
 *             → "renders top contributors on open", "shows label and points for each row"
 *
 *   EARS 2 — WHEN no breakdown is available (older cached responses), the badge SHALL
 *             degrade gracefully (no popover affordance, no error).
 *             → "no trigger when scoreBreakdown is absent"
 *             → "no trigger when scoreBreakdown is empty array"
 *
 *   EARS 3 — WHEN the AI boost contributed, the popover SHALL tag that line with the AI
 *             provenance chip; WHEN AI had no say, the popover SHALL say so ([no AI]).
 *             → "AI chip on ai_boost row"
 *             → "[no AI] line when no ai_boost factor"
 *
 *   EARS 4 — Ubiquitous: the popover SHALL be keyboard-operable and SHALL render all
 *             labels as text nodes only.
 *             → "trigger has aria-label, opens on click"
 *             → "Esc closes the popover"
 *             → "trigger aria-expanded reflects open state"
 *             → "labels rendered as text nodes, no innerHTML injection"
 *
 *   Additional coverage:
 *   - Top 3 shown, "+N more" overflow line for 4+ contributors.
 *   - Cap item shown separately with signed points.
 *   - Existing ScoreBadge usages without scoreBreakdown prop are unaffected.
 *   - onBreakdownClick legacy prop still works independently.
 *   - Popover closes when mouse leaves the badge wrapper.
 *   - ScoreBreakdownPopover exported from the DS barrel.
 */

import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import { ScoreBadge, ScoreBreakdownPopover } from '../components/ds'
import type { ScoreBreakdownItem } from '../api/types'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const RULE_ONLY_BREAKDOWN: ScoreBreakdownItem[] = [
  { factor: 'brute_force', label: 'Brute force', points: 30 },
  { factor: 'port_scan', label: 'Port scan', points: 25 },
]

const AI_BREAKDOWN: ScoreBreakdownItem[] = [
  { factor: 'brute_force', label: 'Brute force', points: 30 },
  { factor: 'sql_injection', label: 'SQL injection', points: 40 },
  { factor: 'ai_boost', label: 'AI boost', points: 20 },
]

const CAPPED_BREAKDOWN: ScoreBreakdownItem[] = [
  { factor: 'brute_force', label: 'Brute force', points: 30 },
  { factor: 'sql_injection', label: 'SQL injection', points: 40 },
  { factor: 'xss', label: 'XSS', points: 35 },
  { factor: 'ai_boost', label: 'AI boost', points: 20 },
  { factor: 'cap', label: 'Capped at 100', points: -25 },
]

const MANY_CONTRIBUTORS_BREAKDOWN: ScoreBreakdownItem[] = [
  { factor: 'brute_force', label: 'Brute force', points: 30 },
  { factor: 'port_scan', label: 'Port scan', points: 25 },
  { factor: 'sql_injection', label: 'SQL injection', points: 20 },
  { factor: 'xss', label: 'XSS', points: 15 },
  { factor: 'lfi', label: 'LFI', points: 10 },
]

// ---------------------------------------------------------------------------
// ScoreBreakdownPopover — standalone component tests
// ---------------------------------------------------------------------------

describe('ScoreBreakdownPopover — renders nothing when closed', () => {
  it('renders nothing when open=false', () => {
    render(
      <ScoreBreakdownPopover
        items={RULE_ONLY_BREAKDOWN}
        open={false}
        onClose={() => {}}
      />,
    )
    expect(screen.queryByTestId('score-breakdown-popover')).not.toBeInTheDocument()
  })

  it('renders nothing when items is empty even if open=true', () => {
    render(
      <ScoreBreakdownPopover
        items={[]}
        open={true}
        onClose={() => {}}
      />,
    )
    expect(screen.queryByTestId('score-breakdown-popover')).not.toBeInTheDocument()
  })
})

describe('ScoreBreakdownPopover — renders when open with items (EARS 1)', () => {
  it('renders the popover element when open=true and items present', () => {
    render(
      <ScoreBreakdownPopover
        items={RULE_ONLY_BREAKDOWN}
        open={true}
        onClose={() => {}}
      />,
    )
    expect(screen.getByTestId('score-breakdown-popover')).toBeInTheDocument()
  })

  it('shows "Score contributors" header', () => {
    render(
      <ScoreBreakdownPopover
        items={RULE_ONLY_BREAKDOWN}
        open={true}
        onClose={() => {}}
      />,
    )
    expect(screen.getByText(/score contributors/i)).toBeInTheDocument()
  })

  it('renders breakdown-row for each visible contributor (EARS 1)', () => {
    render(
      <ScoreBreakdownPopover
        items={RULE_ONLY_BREAKDOWN}
        open={true}
        onClose={() => {}}
      />,
    )
    const rows = screen.getAllByTestId('breakdown-row')
    // Both items are within TOP_N (3)
    expect(rows).toHaveLength(2)
  })

  it('shows label text for each contributor as a text node (EARS 1 + EARS 4)', () => {
    render(
      <ScoreBreakdownPopover
        items={RULE_ONLY_BREAKDOWN}
        open={true}
        onClose={() => {}}
      />,
    )
    expect(screen.getByText('Brute force')).toBeInTheDocument()
    expect(screen.getByText('Port scan')).toBeInTheDocument()
  })

  it('shows "+N" signed points for each contributor (EARS 1)', () => {
    render(
      <ScoreBreakdownPopover
        items={RULE_ONLY_BREAKDOWN}
        open={true}
        onClose={() => {}}
      />,
    )
    expect(screen.getByText('+30')).toBeInTheDocument()
    expect(screen.getByText('+25')).toBeInTheDocument()
  })
})

describe('ScoreBreakdownPopover — overflow ("+N more") line', () => {
  it('shows no overflow line when contributors <= TOP_N (3)', () => {
    render(
      <ScoreBreakdownPopover
        items={AI_BREAKDOWN}
        open={true}
        onClose={() => {}}
      />,
    )
    expect(screen.queryByTestId('breakdown-overflow')).not.toBeInTheDocument()
  })

  it('shows overflow line when contributors > TOP_N', () => {
    render(
      <ScoreBreakdownPopover
        items={MANY_CONTRIBUTORS_BREAKDOWN}
        open={true}
        onClose={() => {}}
      />,
    )
    expect(screen.getByTestId('breakdown-overflow')).toBeInTheDocument()
    // 5 contributors, cap excluded, TOP_N=3 → overflow = 2
    expect(screen.getByTestId('breakdown-overflow').textContent).toContain('+2')
  })

  it('overflow text says "more factor" for 1 overflow item', () => {
    // 4 contributors (no cap) → overflow = 1
    const fourItems: ScoreBreakdownItem[] = [
      ...RULE_ONLY_BREAKDOWN,
      { factor: 'xss', label: 'XSS', points: 35 },
      { factor: 'lfi', label: 'LFI', points: 10 },
    ]
    render(
      <ScoreBreakdownPopover
        items={fourItems}
        open={true}
        onClose={() => {}}
      />,
    )
    const overflow = screen.getByTestId('breakdown-overflow')
    expect(overflow.textContent).toContain('+1')
    expect(overflow.textContent).toContain('factor')
  })

  it('shows exactly TOP_N (3) rows even with 5 contributors', () => {
    render(
      <ScoreBreakdownPopover
        items={MANY_CONTRIBUTORS_BREAKDOWN}
        open={true}
        onClose={() => {}}
      />,
    )
    const rows = screen.getAllByTestId('breakdown-row')
    expect(rows).toHaveLength(3)
  })
})

describe('ScoreBreakdownPopover — AI provenance chip (EARS 3)', () => {
  it('shows AI chip on the ai_boost row (EARS 3)', () => {
    render(
      <ScoreBreakdownPopover
        items={AI_BREAKDOWN}
        open={true}
        onClose={() => {}}
      />,
    )
    // ProvenanceChip renders with text "AI" for derivation="ai"
    expect(screen.getByText('AI')).toBeInTheDocument()
  })

  it('does NOT show [no AI] line when ai_boost factor is present (EARS 3)', () => {
    render(
      <ScoreBreakdownPopover
        items={AI_BREAKDOWN}
        open={true}
        onClose={() => {}}
      />,
    )
    expect(screen.queryByTestId('breakdown-no-ai')).not.toBeInTheDocument()
  })

  it('shows [no AI] line when no ai_boost factor present (EARS 3)', () => {
    render(
      <ScoreBreakdownPopover
        items={RULE_ONLY_BREAKDOWN}
        open={true}
        onClose={() => {}}
      />,
    )
    expect(screen.getByTestId('breakdown-no-ai')).toBeInTheDocument()
    expect(screen.getByTestId('breakdown-no-ai').textContent).toContain('[no AI]')
  })
})

describe('ScoreBreakdownPopover — cap item', () => {
  it('shows cap item as a separate "breakdown-cap" row', () => {
    render(
      <ScoreBreakdownPopover
        items={CAPPED_BREAKDOWN}
        open={true}
        onClose={() => {}}
      />,
    )
    expect(screen.getByTestId('breakdown-cap')).toBeInTheDocument()
  })

  it('cap item shows "Capped at 100" label text', () => {
    render(
      <ScoreBreakdownPopover
        items={CAPPED_BREAKDOWN}
        open={true}
        onClose={() => {}}
      />,
    )
    expect(screen.getByTestId('breakdown-cap').textContent).toContain('Capped at 100')
  })

  it('cap item shows negative signed points', () => {
    render(
      <ScoreBreakdownPopover
        items={CAPPED_BREAKDOWN}
        open={true}
        onClose={() => {}}
      />,
    )
    // The cap is -25 in the fixture
    expect(screen.getByTestId('breakdown-cap').textContent).toContain('-25')
  })

  it('cap item is NOT included in the TOP_N rows', () => {
    // CAPPED_BREAKDOWN has 4 non-cap contributors + 1 cap
    render(
      <ScoreBreakdownPopover
        items={CAPPED_BREAKDOWN}
        open={true}
        onClose={() => {}}
      />,
    )
    // Only TOP_N (3) breakdown-row items should appear
    const rows = screen.getAllByTestId('breakdown-row')
    expect(rows).toHaveLength(3)
  })

  it('shows no cap section when no cap item in breakdown', () => {
    render(
      <ScoreBreakdownPopover
        items={RULE_ONLY_BREAKDOWN}
        open={true}
        onClose={() => {}}
      />,
    )
    expect(screen.queryByTestId('breakdown-cap')).not.toBeInTheDocument()
  })
})

describe('ScoreBreakdownPopover — keyboard / Esc close (EARS 4)', () => {
  it('does NOT register its own Esc handler — Esc is owned by useDismissableDisclosure (issue #356)', () => {
    // ScoreBreakdownPopover no longer has a duplicate capture-phase Esc listener.
    // Esc dismiss + focus-return is handled exclusively by useDismissableDisclosure
    // in ScoreBadge. The onClose prop is NOT called directly by the popover on Esc.
    const onClose = vi.fn()
    render(
      <ScoreBreakdownPopover
        items={RULE_ONLY_BREAKDOWN}
        open={true}
        onClose={onClose}
      />,
    )
    fireEvent.keyDown(document, { key: 'Escape' })
    // The standalone popover does NOT call onClose on Esc — hook owns this
    expect(onClose).not.toHaveBeenCalled()
  })

  it('does NOT call onClose for non-Esc keys', () => {
    const onClose = vi.fn()
    render(
      <ScoreBreakdownPopover
        items={RULE_ONLY_BREAKDOWN}
        open={true}
        onClose={onClose}
      />,
    )
    fireEvent.keyDown(document, { key: 'Enter' })
    fireEvent.keyDown(document, { key: 'Tab' })
    expect(onClose).not.toHaveBeenCalled()
  })

  it('does NOT have role="tooltip" — popover is click-opened, not hover-opened (issue #356)', () => {
    render(
      <ScoreBreakdownPopover
        items={RULE_ONLY_BREAKDOWN}
        open={true}
        onClose={() => {}}
      />,
    )
    // Tooltip semantics are wrong for click-opened disclosures (ARIA spec).
    // role="tooltip" was removed in issue #356.
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument()
    // The popover is still in the DOM (via data-testid)
    expect(screen.getByTestId('score-breakdown-popover')).toBeInTheDocument()
  })

  it('has aria-live="polite" for screen reader announcements on open', () => {
    render(
      <ScoreBreakdownPopover
        items={RULE_ONLY_BREAKDOWN}
        open={true}
        onClose={() => {}}
      />,
    )
    const popover = screen.getByTestId('score-breakdown-popover')
    expect(popover.getAttribute('aria-live')).toBe('polite')
  })

  it('accepts and renders with an id (for aria-controls linkage)', () => {
    render(
      <ScoreBreakdownPopover
        items={RULE_ONLY_BREAKDOWN}
        open={true}
        onClose={() => {}}
        id="test-popover"
      />,
    )
    expect(screen.getByTestId('score-breakdown-popover').id).toBe('test-popover')
  })
})

describe('ScoreBreakdownPopover — XSS safety (EARS 4 / ADR-0029 D3)', () => {
  it('renders label as text node — does not inject HTML', () => {
    const xssItems: ScoreBreakdownItem[] = [
      { factor: 'evil', label: '<img src=x onerror=alert(1)>', points: 30 },
    ]
    const { container } = render(
      <ScoreBreakdownPopover
        items={xssItems}
        open={true}
        onClose={() => {}}
      />,
    )
    // The injected string should NOT produce an actual img element in the DOM
    expect(container.querySelector('img[src="x"]')).toBeNull()
    // The text content should contain the raw string (React escapes it)
    expect(screen.getByTestId('score-breakdown-popover').textContent).toContain(
      '<img src=x onerror=alert(1)>',
    )
  })
})

// ---------------------------------------------------------------------------
// ScoreBadge — popover integration tests
// ---------------------------------------------------------------------------

describe('ScoreBadge — no breakdown trigger when scoreBreakdown is absent (EARS 2)', () => {
  it('renders no breakdown trigger when scoreBreakdown is undefined (backward compat)', () => {
    render(<ScoreBadge score={100} threatLevel="CRITICAL" />)
    expect(screen.queryByRole('button', { name: /show score breakdown/i })).not.toBeInTheDocument()
  })

  it('renders no breakdown trigger when scoreBreakdown is empty array (EARS 2)', () => {
    render(<ScoreBadge score={100} threatLevel="CRITICAL" scoreBreakdown={[]} />)
    expect(screen.queryByRole('button', { name: /show score breakdown/i })).not.toBeInTheDocument()
  })

  it('still renders score and band without breakdown (backward compat)', () => {
    render(<ScoreBadge score={100} threatLevel="CRITICAL" />)
    expect(screen.getByRole('img').textContent).toContain('100')
    expect(screen.getByRole('img').textContent).toContain('CRITICAL')
  })
})

describe('ScoreBadge — breakdown trigger shown with non-empty scoreBreakdown', () => {
  it('renders breakdown trigger when scoreBreakdown has items', () => {
    render(
      <ScoreBadge
        score={95}
        threatLevel="CRITICAL"
        scoreBreakdown={RULE_ONLY_BREAKDOWN}
      />,
    )
    expect(screen.getByRole('button', { name: /show score breakdown/i })).toBeInTheDocument()
  })

  it('trigger has aria-expanded=false initially', () => {
    render(
      <ScoreBadge
        score={95}
        threatLevel="CRITICAL"
        scoreBreakdown={RULE_ONLY_BREAKDOWN}
      />,
    )
    const trigger = screen.getByRole('button', { name: /show score breakdown/i })
    expect(trigger.getAttribute('aria-expanded')).toBe('false')
  })

  it('popover is not shown before trigger click (EARS 1)', () => {
    render(
      <ScoreBadge
        score={95}
        threatLevel="CRITICAL"
        scoreBreakdown={RULE_ONLY_BREAKDOWN}
      />,
    )
    expect(screen.queryByTestId('score-breakdown-popover')).not.toBeInTheDocument()
  })
})

describe('ScoreBadge — popover opens on trigger click (EARS 1)', () => {
  it('shows popover after clicking the trigger', () => {
    render(
      <ScoreBadge
        score={95}
        threatLevel="CRITICAL"
        scoreBreakdown={RULE_ONLY_BREAKDOWN}
      />,
    )
    const trigger = screen.getByRole('button', { name: /show score breakdown/i })
    fireEvent.click(trigger)
    expect(screen.getByTestId('score-breakdown-popover')).toBeInTheDocument()
  })

  it('trigger aria-expanded becomes true after click', () => {
    render(
      <ScoreBadge
        score={95}
        threatLevel="CRITICAL"
        scoreBreakdown={RULE_ONLY_BREAKDOWN}
      />,
    )
    const trigger = screen.getByRole('button', { name: /show score breakdown/i })
    fireEvent.click(trigger)
    expect(trigger.getAttribute('aria-expanded')).toBe('true')
  })

  it('popover shows top contributors (EARS 1)', () => {
    render(
      <ScoreBadge
        score={55}
        threatLevel="HIGH"
        scoreBreakdown={RULE_ONLY_BREAKDOWN}
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: /show score breakdown/i }))
    expect(screen.getByText('Brute force')).toBeInTheDocument()
    expect(screen.getByText('Port scan')).toBeInTheDocument()
    expect(screen.getByText('+30')).toBeInTheDocument()
    expect(screen.getByText('+25')).toBeInTheDocument()
  })

  it('second click on trigger toggles popover closed', () => {
    render(
      <ScoreBadge
        score={95}
        threatLevel="CRITICAL"
        scoreBreakdown={RULE_ONLY_BREAKDOWN}
      />,
    )
    const trigger = screen.getByRole('button', { name: /show score breakdown/i })
    fireEvent.click(trigger)
    expect(screen.getByTestId('score-breakdown-popover')).toBeInTheDocument()
    fireEvent.click(trigger)
    expect(screen.queryByTestId('score-breakdown-popover')).not.toBeInTheDocument()
  })
})

describe('ScoreBadge — keyboard close of popover (EARS 4)', () => {
  it('Esc closes the open popover (handled by useDismissableDisclosure in ScoreBadge)', () => {
    render(
      <ScoreBadge
        score={95}
        threatLevel="CRITICAL"
        scoreBreakdown={RULE_ONLY_BREAKDOWN}
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: /show score breakdown/i }))
    expect(screen.getByTestId('score-breakdown-popover')).toBeInTheDocument()
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.queryByTestId('score-breakdown-popover')).not.toBeInTheDocument()
  })
})

describe('ScoreBadge — AI provenance in popover (EARS 3)', () => {
  it('shows AI chip in popover when ai_boost is in breakdown (EARS 3)', () => {
    render(
      <ScoreBadge
        score={90}
        threatLevel="CRITICAL"
        scoreBreakdown={AI_BREAKDOWN}
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: /show score breakdown/i }))
    expect(screen.getByText('AI')).toBeInTheDocument()
  })

  it('shows [no AI] line in popover when no ai_boost (EARS 3)', () => {
    render(
      <ScoreBadge
        score={55}
        threatLevel="HIGH"
        scoreBreakdown={RULE_ONLY_BREAKDOWN}
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: /show score breakdown/i }))
    expect(screen.getByTestId('breakdown-no-ai')).toBeInTheDocument()
  })
})

describe('ScoreBadge — mouse-leave does NOT close popover (issue #356 instant-close fix)', () => {
  it('mouse-leave from the badge wrapper does NOT close the popover', () => {
    // The popover is portaled above the badge. The pointer naturally crosses the
    // badge boundary when travelling to the popover — closing on mouseleave would
    // cause instant-close before the user can read the breakdown (issue #356).
    render(
      <ScoreBadge
        score={95}
        threatLevel="CRITICAL"
        scoreBreakdown={RULE_ONLY_BREAKDOWN}
        data-testid="badge"
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: /show score breakdown/i }))
    expect(screen.getByTestId('score-breakdown-popover')).toBeInTheDocument()
    fireEvent.mouseLeave(screen.getByTestId('badge'))
    // Popover MUST remain open
    expect(screen.getByTestId('score-breakdown-popover')).toBeInTheDocument()
  })
})

describe('ScoreBadge — legacy onBreakdownClick backward compatibility', () => {
  it('renders "?" trigger when only onBreakdownClick is provided (no scoreBreakdown)', () => {
    const handler = vi.fn()
    render(
      <ScoreBadge score={100} threatLevel="CRITICAL" onBreakdownClick={handler} />,
    )
    expect(screen.getByRole('button', { name: 'Why this score?' })).toBeInTheDocument()
  })

  it('fires onBreakdownClick when only that prop is provided', () => {
    const handler = vi.fn()
    render(
      <ScoreBadge score={100} threatLevel="CRITICAL" onBreakdownClick={handler} />,
    )
    fireEvent.click(screen.getByRole('button', { name: 'Why this score?' }))
    expect(handler).toHaveBeenCalledOnce()
  })

  it('does NOT open the popover with legacy onBreakdownClick (no scoreBreakdown data)', () => {
    const handler = vi.fn()
    render(
      <ScoreBadge score={100} threatLevel="CRITICAL" onBreakdownClick={handler} />,
    )
    fireEvent.click(screen.getByRole('button', { name: 'Why this score?' }))
    // No popover is shown because scoreBreakdown is absent
    expect(screen.queryByTestId('score-breakdown-popover')).not.toBeInTheDocument()
  })

  it('fires onBreakdownClick when BOTH scoreBreakdown and onBreakdownClick provided', () => {
    const handler = vi.fn()
    render(
      <ScoreBadge
        score={100}
        threatLevel="CRITICAL"
        scoreBreakdown={RULE_ONLY_BREAKDOWN}
        onBreakdownClick={handler}
      />,
    )
    fireEvent.click(screen.getByRole('button', { name: /show score breakdown/i }))
    expect(handler).toHaveBeenCalledOnce()
    // AND popover is shown because scoreBreakdown is present
    expect(screen.getByTestId('score-breakdown-popover')).toBeInTheDocument()
  })
})

describe('ScoreBadge — existing call sites unaffected (EARS 2 / backward compat)', () => {
  it('score and band still render with no breakdown props (regression guard)', () => {
    render(<ScoreBadge score={72} threatLevel="HIGH" data-testid="badge" />)
    const badge = screen.getByTestId('badge')
    expect(badge.textContent).toContain('72')
    expect(badge.textContent).toContain('HIGH')
    expect(badge.textContent).toContain('Risk')
  })

  it('fw-score-badge class still present (class-based selector regression guard)', () => {
    const { container } = render(<ScoreBadge score={72} threatLevel="HIGH" />)
    expect(container.querySelector('.fw-score-badge')).not.toBeNull()
  })

  it('data-band still set correctly with no breakdown', () => {
    render(<ScoreBadge score={100} threatLevel="CRITICAL" data-testid="badge" />)
    expect(screen.getByTestId('badge').getAttribute('data-band')).toBe('CRITICAL')
  })

  it('aria-label still describes score and band with no breakdown', () => {
    render(<ScoreBadge score={100} threatLevel="CRITICAL" data-testid="badge" />)
    const label = screen.getByTestId('badge').getAttribute('aria-label') ?? ''
    expect(label).toContain('100')
    expect(label).toContain('CRITICAL')
  })
})

// ---------------------------------------------------------------------------
// DS barrel export check
// ---------------------------------------------------------------------------

describe('DS barrel — ScoreBreakdownPopover exported', () => {
  it('ScoreBreakdownPopover is a function (exported from ds barrel)', () => {
    expect(typeof ScoreBreakdownPopover).toBe('function')
  })
})
