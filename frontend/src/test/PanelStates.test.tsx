/**
 * Tests for src/components/states/{EmptyState,LoadingState,ErrorState} and panelState helper.
 *
 * EARS acceptance criteria (issue #98, updated F2 #108):
 *   - EmptyState SHALL render headline and sub-line text (calm zero-state).
 *   - EmptyState SHALL expose icon, headline (title), and sub-line (children) slots.
 *   - EmptyState headline MUST NOT carry any critical/error token — empty is calm.
 *   - LoadingState SHALL render a spinner + label with muted-foreground styling.
 *   - ErrorState SHALL render with soc-critical-fg token class (critical read).
 *   - ErrorState SHALL carry role="alert" for screen-reader announcement.
 *   - resolvePanelState SHALL prioritise loading > error > empty > ready.
 *
 * F2 #108 note: EmptyState now uses the DS recipe (inline --fw-* styles, not
 * muted-foreground Tailwind class). The EARS calm/non-alarming intent is
 * preserved — the assertion is updated from className check to semantic check
 * (no soc-critical / no destructive class on the element).
 */

import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import EmptyState from '../components/states/EmptyState'
import LoadingState from '../components/states/LoadingState'
import ErrorState from '../components/states/ErrorState'
import { resolvePanelState } from '../components/states/panelState'

// ---------------------------------------------------------------------------
// EmptyState
// ---------------------------------------------------------------------------

describe('EmptyState — calm zero-state (issue #98, F2 #108)', () => {
  it('renders headline text', () => {
    render(<EmptyState headline="No geolocated events yet" />)
    expect(screen.getByTestId('empty-state-headline')).toHaveTextContent(
      'No geolocated events yet',
    )
  })

  it('headline element does NOT carry any critical/error token — empty is calm', () => {
    render(<EmptyState headline="No data" />)
    const headline = screen.getByTestId('empty-state-headline')
    // Must NOT carry any alarming token classes — empty is calm, not broken
    expect(headline.className).not.toContain('soc-critical')
    expect(headline.className).not.toContain('destructive')
  })

  it('renders sub-line when provided', () => {
    render(
      <EmptyState
        headline="No events"
        subLine="Events will appear once the source starts reporting."
      />,
    )
    expect(screen.getByTestId('empty-state-subline')).toHaveTextContent(
      'Events will appear once the source starts reporting.',
    )
  })

  it('does not render sub-line when omitted', () => {
    render(<EmptyState headline="No events" />)
    expect(screen.queryByTestId('empty-state-subline')).not.toBeInTheDocument()
  })

  it('renders icon slot when provided', () => {
    render(
      <EmptyState
        headline="No events"
        icon={<span data-testid="custom-icon">icon</span>}
      />,
    )
    expect(screen.getByTestId('empty-state-icon')).toBeInTheDocument()
    expect(screen.getByTestId('custom-icon')).toBeInTheDocument()
  })

  it('does not render icon container when no icon is provided', () => {
    render(<EmptyState headline="No events" />)
    expect(screen.queryByTestId('empty-state-icon')).not.toBeInTheDocument()
  })

  it('icon container does NOT carry any alarming token classes (icon is calm-toned)', () => {
    render(
      <EmptyState
        headline="No events"
        icon={<span>icon</span>}
      />,
    )
    const iconContainer = screen.getByTestId('empty-state-icon')
    // DS uses inline opacity:0.6 — not muted-foreground class. Check calm (no alarm).
    expect(iconContainer.className).not.toContain('soc-critical')
    expect(iconContainer.className).not.toContain('destructive')
  })

  it('outer wrapper has role="status" for accessibility', () => {
    render(<EmptyState headline="No data" />)
    expect(screen.getByRole('status')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// LoadingState
// ---------------------------------------------------------------------------

describe('LoadingState — muted/pending styling (issue #98)', () => {
  it('renders default label "Loading…"', () => {
    render(<LoadingState />)
    expect(screen.getByTestId('loading-state-label')).toHaveTextContent('Loading…')
  })

  it('renders custom label when provided', () => {
    render(<LoadingState label="Loading analytics…" />)
    expect(screen.getByTestId('loading-state-label')).toHaveTextContent('Loading analytics…')
  })

  it('label carries muted-foreground token class (not alarming)', () => {
    render(<LoadingState />)
    const label = screen.getByTestId('loading-state-label')
    expect(label.className).toContain('muted-foreground')
    expect(label.className).not.toContain('soc-critical')
  })

  it('renders an animated spinner element', () => {
    render(<LoadingState />)
    expect(screen.getByTestId('loading-state-spinner')).toBeInTheDocument()
  })

  it('outer wrapper has role="status" for accessibility', () => {
    render(<LoadingState />)
    expect(screen.getByRole('status')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// ErrorState
// ---------------------------------------------------------------------------

describe('ErrorState — critical-styled error indicator (issue #98)', () => {
  it('renders headline text', () => {
    render(<ErrorState headline="Analytics unavailable (503)" />)
    expect(screen.getByTestId('error-state-headline')).toHaveTextContent(
      'Analytics unavailable (503)',
    )
  })

  it('headline carries soc-critical-fg token class (critical read)', () => {
    render(<ErrorState headline="Failed to load" />)
    const headline = screen.getByTestId('error-state-headline')
    expect(headline.className).toContain('soc-critical-fg')
    // Must NOT be muted (error is alarming, not calm)
    expect(headline.className).not.toContain('muted-foreground')
  })

  it('icon container carries soc-critical-fg class', () => {
    render(<ErrorState headline="Error" />)
    const iconContainer = screen.getByTestId('error-state-icon')
    expect(iconContainer.className).toContain('soc-critical-fg')
  })

  it('renders sub-line when provided', () => {
    render(
      <ErrorState
        headline="Error"
        subLine="The service could not be reached. Please retry."
      />,
    )
    expect(screen.getByTestId('error-state-subline')).toHaveTextContent(
      'The service could not be reached. Please retry.',
    )
  })

  it('does not render sub-line when omitted', () => {
    render(<ErrorState headline="Error" />)
    expect(screen.queryByTestId('error-state-subline')).not.toBeInTheDocument()
  })

  it('has role="alert" for immediate screen-reader announcement', () => {
    render(<ErrorState headline="Critical error" />)
    expect(screen.getByRole('alert')).toBeInTheDocument()
  })

  it('renders custom icon when provided', () => {
    render(
      <ErrorState
        headline="Error"
        icon={<span data-testid="custom-error-icon">!</span>}
      />,
    )
    expect(screen.getByTestId('custom-error-icon')).toBeInTheDocument()
  })

  it('renders default warning emoji when no icon prop is given', () => {
    render(<ErrorState headline="Error" />)
    // Default icon is the ⚠️ emoji glyph (F5 #111 DS iconography — no SVG stroke icons)
    const iconContainer = screen.getByTestId('error-state-icon')
    expect(iconContainer.textContent).toContain('⚠️')
    // No inline SVG should be present — emoji replaces the stroke icon
    expect(iconContainer.querySelector('svg')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// resolvePanelState helper
// ---------------------------------------------------------------------------

describe('resolvePanelState — priority ordering (issue #98)', () => {
  it('loading=true always returns "loading"', () => {
    expect(resolvePanelState({ loading: true, error: null, isEmpty: false })).toBe('loading')
    expect(resolvePanelState({ loading: true, error: 'boom', isEmpty: true })).toBe('loading')
  })

  it('loading=false + error → returns "error"', () => {
    expect(resolvePanelState({ loading: false, error: 'Service unavailable', isEmpty: false })).toBe(
      'error',
    )
    expect(resolvePanelState({ loading: false, error: '503', isEmpty: true })).toBe('error')
  })

  it('loading=false + no error + isEmpty=true → returns "empty"', () => {
    expect(resolvePanelState({ loading: false, error: null, isEmpty: true })).toBe('empty')
  })

  it('loading=false + no error + isEmpty=false → returns "ready"', () => {
    expect(resolvePanelState({ loading: false, error: null, isEmpty: false })).toBe('ready')
  })
})
