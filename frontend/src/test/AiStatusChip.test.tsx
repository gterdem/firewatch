/**
 * Tests for src/components/AiStatusChip.tsx
 *
 * EARS criteria covered (issue #97):
 *   - Single shared component: same data-testid on both Dashboard and AI Analysis headers.
 *   - active  → canonical copy "AI active", soc-ok token classes (green).
 *   - disabled → canonical copy "AI offline · rules-only", muted/neutral classes (NOT soc-enforced/red).
 *   - unavailable → canonical copy "AI offline · rules-only", muted/neutral classes (NOT soc-enforced/red).
 *   - null → chip hidden (no flash during load).
 *   - Disabled state MUST NOT carry any soc-enforced or red class.
 */

import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import AiStatusChip from '../components/AiStatusChip'
import { AI_STATUS_COPY } from '../components/aiStatusCopy'

describe('AiStatusChip — canonical copy table', () => {
  it('exports the canonical active copy string', () => {
    expect(AI_STATUS_COPY.active).toBe('AI active')
  })

  it('exports the canonical offline copy string', () => {
    expect(AI_STATUS_COPY.offline).toBe('AI offline · rules-only')
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

  it('renders "AI offline · rules-only" chip when status is disabled', () => {
    render(<AiStatusChip status="disabled" />)
    const chip = screen.getByTestId('ai-status-chip')
    expect(chip).toBeInTheDocument()
    expect(chip).toHaveTextContent('AI offline · rules-only')
    expect(chip).toHaveAttribute('aria-label', 'AI offline · rules-only')
  })

  it('renders "AI offline · rules-only" chip when status is unavailable', () => {
    render(<AiStatusChip status="unavailable" />)
    const chip = screen.getByTestId('ai-status-chip')
    expect(chip).toBeInTheDocument()
    expect(chip).toHaveTextContent('AI offline · rules-only')
    expect(chip).toHaveAttribute('aria-label', 'AI offline · rules-only')
  })

  it('disabled state uses muted/neutral token, NOT soc-enforced or red', () => {
    render(<AiStatusChip status="disabled" />)
    const chip = screen.getByTestId('ai-status-chip')
    // Must NOT carry alarming token classes
    expect(chip.className).not.toContain('soc-enforced')
    expect(chip.className).not.toContain('destructive')
    // Must carry muted/neutral tokens
    expect(chip.className).toContain('muted')
  })

  it('unavailable state uses muted/neutral token, NOT soc-enforced or red', () => {
    render(<AiStatusChip status="unavailable" />)
    const chip = screen.getByTestId('ai-status-chip')
    expect(chip.className).not.toContain('soc-enforced')
    expect(chip.className).not.toContain('destructive')
    expect(chip.className).toContain('muted')
  })

  it('unknown status values fall through to the muted offline treatment', () => {
    render(<AiStatusChip status="error" />)
    const chip = screen.getByTestId('ai-status-chip')
    expect(chip).toBeInTheDocument()
    expect(chip).toHaveTextContent('AI offline · rules-only')
    expect(chip.className).not.toContain('soc-enforced')
    expect(chip.className).toContain('muted')
  })

  // Canonical copy must be identical for both disabled and unavailable (one string per state)
  it('disabled and unavailable share the exact same copy string', () => {
    const { unmount } = render(<AiStatusChip status="disabled" />)
    const disabledText = screen.getByTestId('ai-status-chip').textContent
    unmount()

    render(<AiStatusChip status="unavailable" />)
    const unavailableText = screen.getByTestId('ai-status-chip').textContent
    expect(disabledText).toBe(unavailableText)
  })
})
