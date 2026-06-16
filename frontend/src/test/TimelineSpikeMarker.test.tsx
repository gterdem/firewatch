/**
 * Tests for TimelineSpikeMarker component (issue #248).
 *
 * EARS acceptance criteria covered:
 *
 * A. WHEN a marker is hovered or focused, the statistical magnitude SHALL be shown
 *    per the CellTooltip (#246) primitive.
 *    - Hovering the trigger reveals the spike-hover-content testid.
 *    - The stat line contains the ratio and event count.
 *
 * B. WHILE no LLM reason exists for a spike, the marker and its hover SHALL contain
 *    no AI-attributed wording or provenance chip (ADR-0035).
 *    - When llmReason is undefined, data-testid="spike-llm-reason" is absent.
 *    - No text containing "AI", "ai", "model", "LLM" appears in the marker.
 *
 * C. The glyph renders with aria-label="Spike detected" (WCAG 1.4.1).
 *
 * D. When llmReason IS provided (seam test), it renders in data-testid="spike-llm-reason".
 *    (This confirms the seam is wired correctly; actual content from #213 is gated.)
 *
 * E. Hover stat text format: "Nx vs window median · N events".
 */

import { describe, it, expect } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { TimelineSpikeMarker } from '../components/dashboard/TimelineSpikeMarker'
import type { SpikeMark } from '../lib/spikes'

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const MARK_BASIC: SpikeMark = {
  bucketIndex: 7,
  ratio: 4.2,
  value: 312,
  windowMedian: 74,
}

const MARK_RATIO_ZERO: SpikeMark = {
  bucketIndex: 3,
  ratio: 0,    // zero-median edge case
  value: 200,
  windowMedian: 0,
}

// ---------------------------------------------------------------------------
// A. Hover reveals statistical magnitude
// ---------------------------------------------------------------------------

describe('TimelineSpikeMarker — hover reveals statistical magnitude', () => {
  it('renders the spike marker trigger', () => {
    render(<TimelineSpikeMarker mark={MARK_BASIC} />)
    expect(screen.getByTestId('spike-marker-trigger')).toBeInTheDocument()
  })

  it('hovering the trigger reveals the spike hover content', async () => {
    render(<TimelineSpikeMarker mark={MARK_BASIC} />)
    fireEvent.mouseEnter(screen.getByTestId('spike-marker-trigger'))
    await waitFor(() => {
      expect(screen.getByTestId('spike-hover-content')).toBeInTheDocument()
    })
  })

  it('hover content contains the stat line testid', async () => {
    render(<TimelineSpikeMarker mark={MARK_BASIC} />)
    fireEvent.mouseEnter(screen.getByTestId('spike-marker-trigger'))
    await waitFor(() => {
      expect(screen.getByTestId('spike-stat-line')).toBeInTheDocument()
    })
  })

  it('stat line contains the ratio text (e.g. "4.2x")', async () => {
    render(<TimelineSpikeMarker mark={MARK_BASIC} />)
    fireEvent.mouseEnter(screen.getByTestId('spike-marker-trigger'))
    await waitFor(() => {
      expect(screen.getByTestId('spike-stat-line').textContent).toContain('4.2x')
    })
  })

  it('stat line contains the event count', async () => {
    render(<TimelineSpikeMarker mark={MARK_BASIC} />)
    fireEvent.mouseEnter(screen.getByTestId('spike-marker-trigger'))
    await waitFor(() => {
      const text = screen.getByTestId('spike-stat-line').textContent ?? ''
      expect(text).toContain('312')
    })
  })

  it('stat line contains "vs window median" text', async () => {
    render(<TimelineSpikeMarker mark={MARK_BASIC} />)
    fireEvent.mouseEnter(screen.getByTestId('spike-marker-trigger'))
    await waitFor(() => {
      expect(screen.getByTestId('spike-stat-line').textContent).toContain('vs window median')
    })
  })

  it('stat line contains "events" label', async () => {
    render(<TimelineSpikeMarker mark={MARK_BASIC} />)
    fireEvent.mouseEnter(screen.getByTestId('spike-marker-trigger'))
    await waitFor(() => {
      expect(screen.getByTestId('spike-stat-line').textContent).toContain('events')
    })
  })

  it('when ratio is 0 (zero-median), stat shows "elevated" instead of a ratio', async () => {
    render(<TimelineSpikeMarker mark={MARK_RATIO_ZERO} />)
    fireEvent.mouseEnter(screen.getByTestId('spike-marker-trigger'))
    await waitFor(() => {
      expect(screen.getByTestId('spike-stat-line').textContent).toContain('elevated')
    })
  })
})

// ---------------------------------------------------------------------------
// B. No AI-attributed wording (ADR-0035)
// ---------------------------------------------------------------------------

describe('TimelineSpikeMarker — no AI wording without llmReason (ADR-0035)', () => {
  it('spike-llm-reason testid is NOT rendered when llmReason is undefined', async () => {
    render(<TimelineSpikeMarker mark={MARK_BASIC} />)
    fireEvent.mouseEnter(screen.getByTestId('spike-marker-trigger'))
    // Allow tooltip to render if it will.
    await new Promise((r) => setTimeout(r, 50))
    expect(screen.queryByTestId('spike-llm-reason')).not.toBeInTheDocument()
  })

  it('hover content text does not contain "AI" when llmReason is absent', async () => {
    render(<TimelineSpikeMarker mark={MARK_BASIC} />)
    fireEvent.mouseEnter(screen.getByTestId('spike-marker-trigger'))
    await waitFor(() => {
      expect(screen.getByTestId('spike-hover-content')).toBeInTheDocument()
    })
    const text = screen.getByTestId('spike-hover-content').textContent ?? ''
    expect(text).not.toMatch(/\bAI\b/i)
    expect(text).not.toMatch(/\bmodel\b/i)
    expect(text).not.toMatch(/\bLLM\b/i)
  })

  it('glyph element text does not contain any AI wording', () => {
    render(<TimelineSpikeMarker mark={MARK_BASIC} />)
    const glyph = screen.getByTestId('spike-marker-glyph')
    expect(glyph.textContent).not.toMatch(/AI|model|LLM/i)
  })
})

// ---------------------------------------------------------------------------
// C. Accessibility — aria-label on glyph (WCAG 1.4.1)
// ---------------------------------------------------------------------------

describe('TimelineSpikeMarker — accessibility', () => {
  it('glyph has aria-label="Spike detected"', () => {
    render(<TimelineSpikeMarker mark={MARK_BASIC} />)
    const glyph = screen.getByTestId('spike-marker-glyph')
    expect(glyph.getAttribute('aria-label')).toBe('Spike detected')
  })

  it('glyph is present in the DOM', () => {
    render(<TimelineSpikeMarker mark={MARK_BASIC} />)
    expect(screen.getByTestId('spike-marker-glyph')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// D. LLM-reason seam — renders when provided (structural test only, #213 gated)
// ---------------------------------------------------------------------------

describe('TimelineSpikeMarker — llmReason seam', () => {
  it('renders spike-llm-reason when llmReason prop is provided', async () => {
    render(
      <TimelineSpikeMarker
        mark={MARK_BASIC}
        llmReason="likely SQLi sweep from 3 IPs"
      />
    )
    fireEvent.mouseEnter(screen.getByTestId('spike-marker-trigger'))
    await waitFor(() => {
      expect(screen.getByTestId('spike-llm-reason')).toBeInTheDocument()
    })
  })

  it('spike-llm-reason contains the provided reason text', async () => {
    render(
      <TimelineSpikeMarker
        mark={MARK_BASIC}
        llmReason="likely SQLi sweep from 3 IPs"
      />
    )
    fireEvent.mouseEnter(screen.getByTestId('spike-marker-trigger'))
    await waitFor(() => {
      expect(screen.getByTestId('spike-llm-reason').textContent).toContain('likely SQLi sweep')
    })
  })

  it('llmReason text is rendered as a text node (not innerHTML)', async () => {
    render(
      <TimelineSpikeMarker
        mark={MARK_BASIC}
        llmReason="<b>injection attempt</b>"
      />
    )
    fireEvent.mouseEnter(screen.getByTestId('spike-marker-trigger'))
    await waitFor(() => {
      expect(screen.getByTestId('spike-llm-reason')).toBeInTheDocument()
    })
    // The raw string should appear as text, not rendered as bold HTML.
    const el = screen.getByTestId('spike-llm-reason')
    expect(el.innerHTML).not.toContain('<b>')
    expect(el.textContent).toContain('<b>injection attempt</b>')
  })
})
