/**
 * Tests for src/components/AiStatusChip.tsx
 *
 * EARS criteria covered (issue #97; three-state rework issue #41 / ADR-0066):
 *   - Single shared component: same data-testid on both Dashboard and AI Analysis headers.
 *   - active      → canonical copy "AI active", soc-ok token classes (green).
 *   - disabled    → canonical copy "AI off · rules-only", muted/neutral classes
 *                    (NOT soc-enforced/red, NOT soc-watch/amber).
 *   - unreachable → canonical copy "AI unreachable · rules-only", soc-watch/amber
 *                    classes (attention-worthy, NOT soc-enforced/red, NOT muted-only).
 *   - unavailable (Layer 2 threat-derived fallback) → same amber treatment as
 *     'unreachable' — both fault words map to the same attention bucket.
 *   - null → chip hidden (no flash during load).
 *   - Any other/unknown status (e.g. 'skipped', 'no_input', 'error') degrades to
 *     the neutral treatment — never assumed to be a fault.
 */

import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import AiStatusChip from '../components/AiStatusChip'
import { AI_STATUS_COPY } from '../components/aiStatusCopy'

describe('AiStatusChip — canonical copy table', () => {
  it('exports the canonical active copy string', () => {
    expect(AI_STATUS_COPY.active).toBe('AI active')
  })

  it('exports the canonical disabled (off-by-choice) copy string', () => {
    expect(AI_STATUS_COPY.disabled).toBe('AI off · rules-only')
  })

  it('exports the canonical unreachable (fault) copy string', () => {
    expect(AI_STATUS_COPY.unreachable).toBe('AI unreachable · rules-only')
  })

  it('disabled and unreachable copy strings are distinct (no collapsed "offline" bucket)', () => {
    expect(AI_STATUS_COPY.disabled).not.toBe(AI_STATUS_COPY.unreachable)
  })
})

describe('AiStatusChip — render states', () => {
  it('renders nothing when status is null', () => {
    const { container } = render(<AiStatusChip status={null} />)
    expect(container.firstChild).toBeNull()
    expect(screen.queryByTestId('ai-status-chip')).not.toBeInTheDocument()
  })

  it('renders "AI active" chip when status is active', () => {
    render(<AiStatusChip status="active" />)
    const chip = screen.getByTestId('ai-status-chip')
    expect(chip).toBeInTheDocument()
    expect(chip).toHaveTextContent('AI active')
    expect(chip).toHaveAttribute('aria-label', 'AI active')
  })

  it('uses soc-ok token classes for active state', () => {
    render(<AiStatusChip status="active" />)
    const chip = screen.getByTestId('ai-status-chip')
    expect(chip.className).toContain('soc-ok')
  })

  // -------------------------------------------------------------------------
  // disabled — off BY CHOICE — neutral, never alarming
  // -------------------------------------------------------------------------

  it('renders "AI off · rules-only" chip when status is disabled', () => {
    render(<AiStatusChip status="disabled" />)
    const chip = screen.getByTestId('ai-status-chip')
    expect(chip).toBeInTheDocument()
    expect(chip).toHaveTextContent('AI off · rules-only')
    expect(chip).toHaveAttribute('aria-label', 'AI off · rules-only')
  })

  it('disabled state uses muted/neutral token, NOT soc-enforced, NOT soc-watch/amber', () => {
    render(<AiStatusChip status="disabled" />)
    const chip = screen.getByTestId('ai-status-chip')
    expect(chip.className).not.toContain('soc-enforced')
    expect(chip.className).not.toContain('destructive')
    expect(chip.className).not.toContain('soc-watch')
    expect(chip.className).toContain('muted')
  })

  // -------------------------------------------------------------------------
  // unreachable / unavailable — FAULT — attention-worthy amber, not critical
  // -------------------------------------------------------------------------

  it('renders "AI unreachable · rules-only" chip when status is unreachable (Layer 1 /health.ai fault word)', () => {
    render(<AiStatusChip status="unreachable" />)
    const chip = screen.getByTestId('ai-status-chip')
    expect(chip).toBeInTheDocument()
    expect(chip).toHaveTextContent('AI unreachable · rules-only')
    expect(chip).toHaveAttribute('aria-label', 'AI unreachable · rules-only')
  })

  it('renders the same "AI unreachable · rules-only" chip when status is unavailable (Layer 2 fallback fault word)', () => {
    render(<AiStatusChip status="unavailable" />)
    const chip = screen.getByTestId('ai-status-chip')
    expect(chip).toBeInTheDocument()
    expect(chip).toHaveTextContent('AI unreachable · rules-only')
  })

  it('unreachable state uses soc-watch/amber attention tokens, NOT soc-enforced/red, NOT plain muted', () => {
    render(<AiStatusChip status="unreachable" />)
    const chip = screen.getByTestId('ai-status-chip')
    expect(chip.className).toContain('soc-watch')
    expect(chip.className).not.toContain('soc-enforced')
    expect(chip.className).not.toContain('destructive')
  })

  it('disabled and unreachable render visually distinct chips (the bug ADR-0066 fixes)', () => {
    const { unmount } = render(<AiStatusChip status="disabled" />)
    const disabledText = screen.getByTestId('ai-status-chip').textContent
    const disabledClass = screen.getByTestId('ai-status-chip').className
    unmount()

    render(<AiStatusChip status="unreachable" />)
    const unreachableText = screen.getByTestId('ai-status-chip').textContent
    const unreachableClass = screen.getByTestId('ai-status-chip').className

    expect(disabledText).not.toBe(unreachableText)
    expect(disabledClass).not.toBe(unreachableClass)
  })

  // -------------------------------------------------------------------------
  // Unknown/other values — degrade to neutral, never assumed to be a fault
  // -------------------------------------------------------------------------

  it('unknown status values fall through to the muted neutral treatment, not amber', () => {
    render(<AiStatusChip status="error" />)
    const chip = screen.getByTestId('ai-status-chip')
    expect(chip).toBeInTheDocument()
    expect(chip).toHaveTextContent('AI off · rules-only')
    expect(chip.className).not.toContain('soc-enforced')
    expect(chip.className).not.toContain('soc-watch')
    expect(chip.className).toContain('muted')
  })

  it('"skipped" (per-analysis-only annotation) degrades to the neutral treatment, never drives an alarming chip', () => {
    render(<AiStatusChip status="skipped" />)
    const chip = screen.getByTestId('ai-status-chip')
    expect(chip).toHaveTextContent('AI off · rules-only')
    expect(chip.className).not.toContain('soc-watch')
  })

  it('"no_input" (per-analysis-only annotation) degrades to the neutral treatment, never drives an alarming chip', () => {
    render(<AiStatusChip status="no_input" />)
    const chip = screen.getByTestId('ai-status-chip')
    expect(chip).toHaveTextContent('AI off · rules-only')
    expect(chip.className).not.toContain('soc-watch')
  })
})
