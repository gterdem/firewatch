/**
 * Tests for src/components/logs/CursorPager.tsx
 *
 * EARS criteria covered:
 *   - Event-driven: "Next" button calls onNext with next_cursor from the envelope
 *     (ADR-0029 D2 — cursor echo, never offset math).
 *   - Event-driven: "First" button calls onFirst to reset cursor.
 *   - State-driven: Next disabled when has_more=false or nextCursor=null.
 *   - State-driven: First disabled when currentCursor is undefined/null (already on first page).
 *   - State-driven: total_matching and pageSize rendered as text.
 */

import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import CursorPager from '../components/logs/CursorPager'

describe('CursorPager — cursor pagination (ADR-0029 D2)', () => {
  it('renders total_matching count', () => {
    render(
      <CursorPager
        nextCursor="cursor-abc"
        has_more={true}
        total_matching={1287}
        pageSize={50}
        onNext={vi.fn()}
        onFirst={vi.fn()}
      />,
    )
    expect(screen.getByTestId('pager-count')).toHaveTextContent('1,287')
  })

  it('calls onNext with next_cursor when Next is clicked (cursor echo)', () => {
    const onNext = vi.fn()
    render(
      <CursorPager
        nextCursor="2026-06-04T10:01:00|2"
        has_more={true}
        total_matching={1287}
        pageSize={50}
        onNext={onNext}
        onFirst={vi.fn()}
      />,
    )
    fireEvent.click(screen.getByTestId('pager-next'))
    expect(onNext).toHaveBeenCalledTimes(1)
    // CRITICAL: must echo the server-provided cursor verbatim — not compute an offset.
    expect(onNext).toHaveBeenCalledWith('2026-06-04T10:01:00|2')
  })

  it('disables Next when has_more=false', () => {
    render(
      <CursorPager
        nextCursor={null}
        has_more={false}
        total_matching={50}
        pageSize={50}
        onNext={vi.fn()}
        onFirst={vi.fn()}
      />,
    )
    expect(screen.getByTestId('pager-next')).toBeDisabled()
  })

  it('disables Next when nextCursor=null even if has_more=true', () => {
    render(
      <CursorPager
        nextCursor={null}
        has_more={true}
        total_matching={100}
        pageSize={50}
        onNext={vi.fn()}
        onFirst={vi.fn()}
      />,
    )
    expect(screen.getByTestId('pager-next')).toBeDisabled()
  })

  it('calls onFirst when First is clicked', () => {
    const onFirst = vi.fn()
    render(
      <CursorPager
        currentCursor="some-cursor"
        nextCursor="next-cursor"
        has_more={true}
        total_matching={1287}
        pageSize={50}
        onNext={vi.fn()}
        onFirst={onFirst}
      />,
    )
    fireEvent.click(screen.getByTestId('pager-first'))
    expect(onFirst).toHaveBeenCalledTimes(1)
  })

  it('disables First when currentCursor is undefined (already on first page)', () => {
    render(
      <CursorPager
        currentCursor={undefined}
        nextCursor="next-cursor"
        has_more={true}
        total_matching={200}
        pageSize={50}
        onNext={vi.fn()}
        onFirst={vi.fn()}
      />,
    )
    expect(screen.getByTestId('pager-first')).toBeDisabled()
  })
})
