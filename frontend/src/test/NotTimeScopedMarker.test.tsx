/**
 * Tests for components/dashboard/NotTimeScopedMarker.tsx (issue #249).
 *
 * EARS acceptance criteria covered:
 *
 * A. Graceful-degrade visibility:
 *    - When active=true, the marker renders (visible "not time-scoped" indicator).
 *    - When active=false, the marker renders nothing (zero footprint on default layout).
 *
 * B. Content:
 *    - Marker text contains "not time-scoped".
 *    - Marker has a descriptive title attribute explaining the limitation.
 */

import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import NotTimeScopedMarker from '../components/dashboard/NotTimeScopedMarker'

// ---------------------------------------------------------------------------
// A. Graceful-degrade visibility
// ---------------------------------------------------------------------------

describe('NotTimeScopedMarker — visibility', () => {
  it('renders when active=true (brush range is active)', () => {
    render(<NotTimeScopedMarker active={true} />)
    expect(screen.getByTestId('not-time-scoped-marker')).toBeInTheDocument()
  })

  it('renders nothing when active=false (no brush range)', () => {
    render(<NotTimeScopedMarker active={false} />)
    expect(screen.queryByTestId('not-time-scoped-marker')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// B. Content
// ---------------------------------------------------------------------------

describe('NotTimeScopedMarker — content', () => {
  it('marker text contains "not time-scoped"', () => {
    render(<NotTimeScopedMarker active={true} />)
    const marker = screen.getByTestId('not-time-scoped-marker')
    expect(marker.textContent).toContain('not time-scoped')
  })

  it('marker has a title attribute explaining the limitation', () => {
    render(<NotTimeScopedMarker active={true} />)
    const marker = screen.getByTestId('not-time-scoped-marker')
    const title = marker.getAttribute('title') ?? ''
    expect(title.length).toBeGreaterThan(0)
    // Should mention filtering limitation
    expect(title.toLowerCase()).toMatch(/time.range|filter/i)
  })
})
