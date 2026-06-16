/**
 * Tests for RuleCellTooltip — peek-then-pin grammar (#253 + #283 follow-up).
 *
 * EARS criteria covered:
 *
 * Peek (hover/focus):
 *   WHEN a Signature cell is hovered or focused, the system SHALL show the
 *   cell-anchored RuleCellTooltip (peek — instant, hoverable per #246).
 *   Peek shows: sid, category, source rows.
 *
 * Pin (click/Enter):
 *   WHEN the cell is clicked or Enter is pressed, the popover SHALL pin
 *   (persists for text copy and for clicking the action hint).
 *   Pin adds: description text, category chip, ADR-0034 hint.
 *
 * Esc:
 *   WHEN Esc is pressed, dismissal SHALL be innermost-first (#226 layered-Esc:
 *   popover → slide-over), with focus restored to the cell.
 *   WHEN pinned, first Esc clears pin; second Esc closes peek if still focused.
 *
 * Content:
 *   The tooltip content SHALL carry: description text, category chip,
 *   ADR-0034 action hint — all text nodes only (ADR-0029 D3).
 *
 * Logs page table wired:
 *   WHEN a Signature cell in LogsTable is hovered/focused, RuleCellTooltip
 *   SHALL be rendered (not the old center-modal RulePopup).
 *
 * Genericity:
 *   No source-name branching in the component — fictional type_key is used.
 *
 * SECURITY (ADR-0029 D3): all attacker-controlled values rendered as text nodes.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { RuleCellTooltip } from '../components/logs/RuleCellTooltip'
import { findActionHint } from '../lib/actionHints'
import {
  DEMO_IDS_SOURCE_ENTRY,
  NO_ACTIONS_SOURCE_ENTRY,
} from './fixtures'
import type { RuleDescription } from '../api/types'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const RULES: RuleDescription[] = [
  {
    rule_id: '2001219',
    name: 'ET SCAN Potential VNC Scan',
    description: 'Detects potential VNC scanning activity.',
    category: 'Port Scan',
  },
]

const EMPTY_RULES: RuleDescription[] = []

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.clearAllMocks()
})

afterEach(() => {
  vi.useRealTimers()
})

// ---------------------------------------------------------------------------
// 1. Peek: hover opens tooltip
// ---------------------------------------------------------------------------

describe('RuleCellTooltip — peek on hover/focus', () => {
  it('shows tooltip on mouseenter (peek)', async () => {
    render(
      <RuleCellTooltip
        ruleName="ET SCAN Potential VNC Scan"
        ruleId="2001219"
        category="Port Scan"
        sourceType="suricata"
        rules={RULES}
      />,
    )
    const trigger = screen.getByTestId('rule-cell-tooltip-trigger')
    expect(screen.queryByTestId('cell-tooltip-content')).not.toBeInTheDocument()

    fireEvent.mouseEnter(trigger)

    await waitFor(() => {
      expect(screen.getByTestId('cell-tooltip-content')).toBeInTheDocument()
    })
    // Peek rows visible
    expect(screen.getByTestId('rule-cell-tooltip-content')).toBeInTheDocument()
  })

  it('shows tooltip on keyboard focus (peek)', async () => {
    render(
      <RuleCellTooltip
        ruleName="ET SCAN"
        ruleId="2001219"
        category="Scan"
        sourceType="suricata"
        rules={RULES}
      />,
    )
    const trigger = screen.getByTestId('rule-cell-tooltip-trigger')
    fireEvent.focus(trigger)
    await waitFor(() => {
      expect(screen.getByTestId('cell-tooltip-content')).toBeInTheDocument()
    })
  })

  it('peek shows sid row', async () => {
    render(
      <RuleCellTooltip ruleId="2001219" rules={RULES} />,
    )
    const trigger = screen.getByTestId('rule-cell-tooltip-trigger')
    fireEvent.mouseEnter(trigger)
    await waitFor(() => {
      expect(screen.getByTestId('rule-cell-tooltip-content')).toBeInTheDocument()
    })
    expect(screen.getByTestId('rule-cell-tooltip-content').textContent).toContain('2001219')
  })

  it('peek shows category row when provided', async () => {
    render(
      <RuleCellTooltip ruleId="2001219" category="Port Scan" rules={RULES} />,
    )
    fireEvent.mouseEnter(screen.getByTestId('rule-cell-tooltip-trigger'))
    await waitFor(() => {
      expect(screen.getByTestId('rule-cell-tooltip-content').textContent).toContain('Port Scan')
    })
  })

  it('peek shows source row when provided', async () => {
    render(
      <RuleCellTooltip ruleId="2001219" sourceType="suricata" rules={RULES} />,
    )
    fireEvent.mouseEnter(screen.getByTestId('rule-cell-tooltip-trigger'))
    await waitFor(() => {
      expect(screen.getByTestId('rule-cell-tooltip-content').textContent).toContain('suricata')
    })
  })

  it('peek does NOT show pin-detail (description) until pinned', async () => {
    render(
      <RuleCellTooltip
        ruleId="2001219"
        category="Port Scan"
        rules={RULES}
      />,
    )
    fireEvent.mouseEnter(screen.getByTestId('rule-cell-tooltip-trigger'))
    await waitFor(() => {
      expect(screen.getByTestId('rule-cell-tooltip-content')).toBeInTheDocument()
    })
    // Description section should NOT be shown in peek mode
    expect(screen.queryByTestId('rule-cell-pin-detail')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// 2. Click opens CellDetailPopover (#329 upgrade — full value on demand)
// ---------------------------------------------------------------------------

describe('RuleCellTooltip — click opens CellDetailPopover', () => {
  it('click on display-name span opens the CellDetailPopover', async () => {
    const user = userEvent.setup()
    render(
      <RuleCellTooltip
        ruleId="2001219"
        category="Port Scan"
        rules={RULES}
      />,
    )
    // CellDetailPopover is not visible before click
    expect(screen.queryByTestId('rule-cell-detail-popover')).not.toBeInTheDocument()

    const displayName = screen.getByTestId('rule-cell-display-name')
    await user.click(displayName)

    // After click: CellDetailPopover appears
    await waitFor(() => {
      expect(screen.getByTestId('rule-cell-detail-popover')).toBeInTheDocument()
    })
  })

  it('CellDetailPopover shows the full rule name as first content block', async () => {
    const user = userEvent.setup()
    render(
      <RuleCellTooltip
        ruleName="ET SCAN Potential VNC Scan"
        ruleId="2001219"
        category="Port Scan"
        rules={RULES}
      />,
    )
    await user.click(screen.getByTestId('rule-cell-display-name'))

    await waitFor(() => {
      expect(screen.getByTestId('cell-detail-full-value')).toBeInTheDocument()
    })
    expect(screen.getByTestId('cell-detail-full-value').textContent).toContain(
      'ET SCAN Potential VNC Scan',
    )
  })

  it('CellDetailPopover shows SID metadata row when ruleId present', async () => {
    const user = userEvent.setup()
    render(
      <RuleCellTooltip
        ruleId="2001219"
        category="Port Scan"
        rules={RULES}
      />,
    )
    await user.click(screen.getByTestId('rule-cell-display-name'))

    await waitFor(() => {
      expect(screen.getByTestId('cell-detail-meta-sid')).toBeInTheDocument()
    })
    expect(screen.getByTestId('cell-detail-meta-sid').textContent).toContain('2001219')
  })

  it('CellDetailPopover shows description as metadata row when resolved from rules', async () => {
    const user = userEvent.setup()
    render(
      <RuleCellTooltip
        ruleId="2001219"
        rules={RULES}
      />,
    )
    await user.click(screen.getByTestId('rule-cell-display-name'))

    await waitFor(() => {
      expect(screen.getByTestId('cell-detail-meta-desc')).toBeInTheDocument()
    })
    expect(screen.getByTestId('cell-detail-meta-desc').textContent).toContain(
      'Detects potential VNC scanning activity.',
    )
  })

  it('second click on display-name closes the CellDetailPopover (toggle)', async () => {
    const user = userEvent.setup()
    render(
      <RuleCellTooltip
        ruleId="2001219"
        rules={RULES}
      />,
    )
    const displayName = screen.getByTestId('rule-cell-display-name')
    // First click: open
    await user.click(displayName)
    await waitFor(() => {
      expect(screen.getByTestId('rule-cell-detail-popover')).toBeInTheDocument()
    })
    // Second click: close
    await user.click(displayName)
    await waitFor(() => {
      expect(screen.queryByTestId('rule-cell-detail-popover')).not.toBeInTheDocument()
    })
  })

  it('CellDetailPopover shows Copy action button', async () => {
    const user = userEvent.setup()
    render(
      <RuleCellTooltip
        ruleId="2001219"
        rules={RULES}
      />,
    )
    await user.click(screen.getByTestId('rule-cell-display-name'))

    await waitFor(() => {
      expect(screen.getByTestId('cell-detail-copy')).toBeInTheDocument()
    })
  })

  it('CellDetailPopover is absent before click (no popover noise)', () => {
    render(
      <RuleCellTooltip
        ruleId="2001219"
        rules={RULES}
      />,
    )
    expect(screen.queryByTestId('rule-cell-detail-popover')).not.toBeInTheDocument()
  })

  it('CellDetailPopover persists past blur (useDismissableDisclosure: click-opened)', async () => {
    const user = userEvent.setup()
    render(
      <RuleCellTooltip
        ruleId="2001219"
        rules={RULES}
      />,
    )
    await user.click(screen.getByTestId('rule-cell-display-name'))
    await waitFor(() => {
      expect(screen.getByTestId('rule-cell-detail-popover')).toBeInTheDocument()
    })

    // Blur the trigger — popover stays open (outside-click, not blur, closes it)
    fireEvent.blur(screen.getByTestId('rule-cell-tooltip-trigger'))
    expect(screen.getByTestId('rule-cell-detail-popover')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// 3. Esc: layered dismiss — innermost first (#226)
// ---------------------------------------------------------------------------

describe('RuleCellTooltip — Esc layered dismiss', () => {
  it('Esc while peeking closes the peek without propagating to outer handler', async () => {
    const user = userEvent.setup()
    const outerHandler = vi.fn()
    document.addEventListener('keydown', outerHandler)

    try {
      render(<RuleCellTooltip ruleId="2001219" rules={RULES} />)
      const trigger = screen.getByTestId('rule-cell-tooltip-trigger')

      fireEvent.focus(trigger)
      await waitFor(() => {
        expect(screen.getByTestId('cell-tooltip-content')).toBeInTheDocument()
      })

      await user.keyboard('{Escape}')
      // Tooltip dismissed
      expect(screen.queryByTestId('cell-tooltip-content')).not.toBeInTheDocument()
      // Outer slide-over handler not called
      expect(outerHandler).not.toHaveBeenCalled()
    } finally {
      document.removeEventListener('keydown', outerHandler)
    }
  })

  it('Esc while CellDetailPopover is open closes it', async () => {
    const user = userEvent.setup()
    render(<RuleCellTooltip ruleId="2001219" rules={RULES} />)

    await user.click(screen.getByTestId('rule-cell-display-name'))
    await waitFor(() => {
      expect(screen.getByTestId('rule-cell-detail-popover')).toBeInTheDocument()
    })

    await user.keyboard('{Escape}')
    // CellDetailPopover dismissed by useDismissableDisclosure
    await waitFor(() => {
      expect(screen.queryByTestId('rule-cell-detail-popover')).not.toBeInTheDocument()
    }, { timeout: 3000 })
  })

  it('Esc while CellDetailPopover open does NOT propagate to outer handler', async () => {
    const user = userEvent.setup()
    const outerHandler = vi.fn()
    document.addEventListener('keydown', outerHandler)

    try {
      render(<RuleCellTooltip ruleId="2001219" rules={RULES} />)
      await user.click(screen.getByTestId('rule-cell-display-name'))

      await waitFor(() => {
        expect(screen.getByTestId('rule-cell-detail-popover')).toBeInTheDocument()
      })

      await user.keyboard('{Escape}')
      // Outer handler must NOT be called on this Esc (innermost-first, layered-Esc #226)
      expect(outerHandler).not.toHaveBeenCalled()
    } finally {
      document.removeEventListener('keydown', outerHandler)
    }
  })
})

// ---------------------------------------------------------------------------
// 4. ADR-0034 hint in pin mode
// ---------------------------------------------------------------------------

describe('RuleCellTooltip — ADR-0034 hint when popover open', () => {
  it('shows hint section when popover open, rule_name missing + source declares action', async () => {
    const user = userEvent.setup()
    const hint = findActionHint([DEMO_IDS_SOURCE_ENTRY], 'demo_ids', null)
    expect(hint).not.toBeNull()

    render(
      <RuleCellTooltip
        ruleId="1234567"
        rules={EMPTY_RULES}
        hint={hint}
      />,
    )
    await user.click(screen.getByTestId('rule-cell-display-name'))

    await waitFor(() => {
      expect(screen.getByTestId('rule-cell-hint')).toBeInTheDocument()
    })
    expect(screen.getByTestId('rule-cell-hint-source').textContent).toContain('Demo IDS')
    expect(screen.getByTestId('rule-cell-hint-confirm').textContent).toContain('40–60 MB')
  })

  it('does NOT show hint when hovering (hint only shown on click-open)', async () => {
    const hint = findActionHint([DEMO_IDS_SOURCE_ENTRY], 'demo_ids', null)

    render(
      <RuleCellTooltip
        ruleId="1234567"
        rules={EMPTY_RULES}
        hint={hint}
      />,
    )
    // Before click: no hint
    expect(screen.queryByTestId('rule-cell-hint')).not.toBeInTheDocument()
    // Hover opens CellTooltip peek (not the CellDetailPopover)
    fireEvent.mouseEnter(screen.getByTestId('rule-cell-tooltip-trigger'))
    await waitFor(() => {
      expect(screen.getByTestId('cell-tooltip-content')).toBeInTheDocument()
    })
    // Hint still not shown — it only appears when the CellDetailPopover is open
    expect(screen.queryByTestId('rule-cell-hint')).not.toBeInTheDocument()
  })

  it('does NOT show hint when source declares no rule_descriptions action', async () => {
    const user = userEvent.setup()
    const hint = findActionHint([NO_ACTIONS_SOURCE_ENTRY], 'syslog_plain', null)
    expect(hint).toBeNull()

    render(
      <RuleCellTooltip
        ruleId="SIG001"
        rules={EMPTY_RULES}
        hint={null}
      />,
    )
    await user.click(screen.getByTestId('rule-cell-display-name'))

    // No hint section (popover is open but showHint=false)
    expect(screen.queryByTestId('rule-cell-hint')).not.toBeInTheDocument()
  })

  it('does NOT show hint when rule is already resolved (rule_name present)', async () => {
    const user = userEvent.setup()
    const hint = findActionHint([DEMO_IDS_SOURCE_ENTRY], 'demo_ids', 'ET SCAN Nmap')
    expect(hint).toBeNull()

    render(
      <RuleCellTooltip
        ruleName="ET SCAN Nmap"
        ruleId="1234567"
        rules={RULES}
        hint={null}
      />,
    )
    await user.click(screen.getByTestId('rule-cell-display-name'))

    expect(screen.queryByTestId('rule-cell-hint')).not.toBeInTheDocument()
  })

  it('shows hint without confirm section when action has confirm=null', async () => {
    const user = userEvent.setup()
    const sourceNullConfirm = {
      type_key: 'silent_ids',
      display_name: 'Silent IDS',
      version: '1.0.0',
      flavor: 'pull' as const,
      config_schema: { type: 'object', properties: {} },
      actions: [
        {
          id: 'load_rules',
          label: 'Load rules',
          description: 'Loads rules.',
          long_running: false,
          confirm: null,
          provides: ['rule_descriptions'],
        },
      ],
    }
    const hint = findActionHint([sourceNullConfirm], 'silent_ids', null)
    expect(hint).not.toBeNull()
    expect(hint!.confirmProse).toBeNull()

    render(
      <RuleCellTooltip
        ruleId="X100"
        rules={EMPTY_RULES}
        hint={hint}
      />,
    )
    await user.click(screen.getByTestId('rule-cell-display-name'))

    await waitFor(() => {
      expect(screen.getByTestId('rule-cell-hint')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('rule-cell-hint-confirm')).not.toBeInTheDocument()
  })

  it('genericity: hint works for a fictional "quantum_ids" type_key — no hardcoded source names', async () => {
    const user = userEvent.setup()
    const quantumSource = {
      type_key: 'quantum_ids',
      display_name: 'Quantum IDS',
      version: '1.0.0',
      flavor: 'pull' as const,
      config_schema: { type: 'object', properties: {} },
      actions: [
        {
          id: 'fetch_catalog',
          label: 'Fetch catalog',
          description: 'Fetch the rule catalog.',
          long_running: true,
          confirm: 'Download ~20 MB?',
          provides: ['rule_descriptions'],
        },
      ],
    }
    const hint = findActionHint([quantumSource], 'quantum_ids', null)
    expect(hint).not.toBeNull()

    render(
      <RuleCellTooltip
        ruleId="QID-1"
        rules={EMPTY_RULES}
        hint={hint}
      />,
    )
    await user.click(screen.getByTestId('rule-cell-display-name'))

    await waitFor(() => {
      expect(screen.getByTestId('rule-cell-hint')).toBeInTheDocument()
    })
    expect(screen.getByTestId('rule-cell-hint-source').textContent).toContain('Quantum IDS')
  })
})

// ---------------------------------------------------------------------------
// 5. Display name rendering
// ---------------------------------------------------------------------------

describe('RuleCellTooltip — display name', () => {
  it('prefers rule_name as display name', () => {
    render(<RuleCellTooltip ruleName="ET SCAN VNC" ruleId="2001219" rules={RULES} />)
    expect(screen.getByTestId('rule-cell-display-name').textContent).toBe('ET SCAN VNC')
  })

  it('falls back to ruleId when rule_name is absent', () => {
    render(<RuleCellTooltip ruleId="2001219" rules={RULES} />)
    expect(screen.getByTestId('rule-cell-display-name').textContent).toBe('2001219')
  })

  it('falls back to em-dash when both absent', () => {
    render(<RuleCellTooltip rules={RULES} />)
    expect(screen.getByTestId('rule-cell-display-name').textContent).toBe('—')
  })
})

// ---------------------------------------------------------------------------
// 6. SECURITY: attacker-controlled values rendered as text nodes
// ---------------------------------------------------------------------------

describe('RuleCellTooltip — SECURITY: text nodes only', () => {
  it('XSS in description renders as inert text in CellDetailPopover', async () => {
    const user = userEvent.setup()
    const xssRules: RuleDescription[] = [
      {
        rule_id: '9999',
        name: 'XSS Rule',
        description: '<script>alert("xss")</script>',
        category: 'injection',
      },
    ]
    render(<RuleCellTooltip ruleId="9999" rules={xssRules} />)
    await user.click(screen.getByTestId('rule-cell-display-name'))

    await waitFor(() => {
      expect(screen.getByTestId('rule-cell-detail-popover')).toBeInTheDocument()
    })
    // The description is in the metadata section as a text node
    const descEl = screen.getByTestId('cell-detail-meta-desc')
    // The script tag must appear as literal text, not executed
    expect(descEl.textContent).toContain('<script>alert("xss")</script>')
    // No live script element
    document.querySelectorAll('script').forEach((el) => {
      expect(el.textContent).not.toContain('xss')
    })
  })

  it('XSS in ruleName renders as inert text in full-value section', async () => {
    const user = userEvent.setup()
    render(<RuleCellTooltip ruleName='<img src=x onerror=alert(1)>' ruleId="9998" rules={[]} />)
    await user.click(screen.getByTestId('rule-cell-display-name'))

    await waitFor(() => {
      expect(screen.getByTestId('cell-detail-full-value')).toBeInTheDocument()
    })
    // The img tag must appear as literal text, not executed
    expect(screen.getByTestId('cell-detail-full-value').textContent).toContain('<img src=x')
    // No onerror attribute on any img element from our payload
    expect(document.querySelectorAll('img[onerror]').length).toBe(0)
  })
})
