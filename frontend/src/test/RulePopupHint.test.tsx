/**
 * ADR-0034 hint integration tests — migrated from RulePopup to RuleCellTooltip (#283).
 *
 * EARS criteria covered (previously in RulePopupHint.test.tsx, now exercising RuleCellTooltip):
 *   - When rule_name is missing AND source declares rule_descriptions action, hint
 *     section is shown in the CellDetailPopover with display_name, action label, confirm prose.
 *   - When source declares no rule_descriptions action, no hint shown.
 *   - No type_key branches in RuleCellTooltip — uses fictional fixture.
 *   - Existing category + description behavior unchanged when hint is null.
 *
 * Note: RulePopup was deleted (#283). These tests are the semantic equivalents
 * of the old RulePopupHint tests, now exercising RuleCellTooltip click → CellDetailPopover.
 * Post-#329: pin mode is now CellDetailPopover; click trigger is `rule-cell-display-name`.
 */

import { describe, it, expect } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { RuleCellTooltip } from '../components/logs/RuleCellTooltip'
import { findActionHint } from '../lib/actionHints'
import {
  DEMO_IDS_SOURCE_ENTRY,
  NO_ACTIONS_SOURCE_ENTRY,
} from './fixtures'
import type { RuleDescription } from '../api/types'

const EMPTY_RULES: RuleDescription[] = []

describe('RuleCellTooltip with ADR-0034 hint (migrated from RulePopupHint)', () => {
  // EARS event-driven: rule has no name + source has rule_descriptions action → hint shown in pin mode.
  it('shows hint section in pin mode when rule_name is missing and source declares rule_descriptions action', async () => {
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
    // Confirm prose (size warning) should be shown in parens
    expect(screen.getByTestId('rule-cell-hint-confirm').textContent).toContain('40–60 MB')
  })

  // EARS event-driven: source with no rule_descriptions action → no hint section.
  it('does not show hint when source declares no rule_descriptions action', async () => {
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

    // Popover opens, but no hint section (no action hint for this source)
    await waitFor(() => {
      expect(screen.getByTestId('rule-cell-detail-popover')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('rule-cell-hint')).not.toBeInTheDocument()
  })

  // Standard: existing description behavior unchanged when hint is null.
  it('renders description when hint is null (standard path)', async () => {
    const user = userEvent.setup()
    const rules: RuleDescription[] = [
      {
        rule_id: '9999',
        name: 'SQL Injection Attempt',
        description: 'Detects SQL injection patterns.',
        category: 'sqli',
      },
    ]

    render(
      <RuleCellTooltip
        ruleId="9999"
        rules={rules}
        hint={null}
      />,
    )
    await user.click(screen.getByTestId('rule-cell-display-name'))

    await waitFor(() => {
      expect(screen.getByTestId('rule-cell-detail-popover')).toBeInTheDocument()
    })
    expect(screen.getByTestId('cell-detail-meta-desc').textContent).toContain(
      'Detects SQL injection patterns.',
    )
    expect(screen.queryByTestId('rule-cell-hint')).not.toBeInTheDocument()
  })

  // EARS ubiquitous: hint works for any fictional type_key (genericity).
  it('shows hint for a fictional "quantum_ids" type_key — no hardcoded source names', async () => {
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

  // Hint NOT shown when rule is already resolved (rule_name present).
  it('does not show hint when rule is fully resolved (has a name)', async () => {
    const user = userEvent.setup()
    const rules: RuleDescription[] = [
      {
        rule_id: '1234567',
        name: 'ET SCAN Nmap',
        description: 'Nmap scan detection.',
        category: 'scan',
      },
    ]

    // If rule_name is present, findActionHint returns null — caller passes null hint.
    const hint = findActionHint([DEMO_IDS_SOURCE_ENTRY], 'demo_ids', 'ET SCAN Nmap')
    expect(hint).toBeNull()

    render(
      <RuleCellTooltip
        ruleName="ET SCAN Nmap"
        ruleId="1234567"
        rules={rules}
        hint={null}
      />,
    )
    await user.click(screen.getByTestId('rule-cell-display-name'))

    await waitFor(() => {
      expect(screen.getByTestId('rule-cell-detail-popover')).toBeInTheDocument()
    })
    expect(screen.queryByTestId('rule-cell-hint')).not.toBeInTheDocument()
    // Description is shown in metadata when it differs from the FALLBACK_DESC
    expect(screen.getByTestId('cell-detail-meta-desc').textContent).toContain('Nmap scan detection.')
  })

  // Confirm prose absent: hint shown without the parens/confirm section.
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
    // The confirm section should NOT be present when confirmProse is null
    expect(screen.queryByTestId('rule-cell-hint-confirm')).not.toBeInTheDocument()
  })
})
