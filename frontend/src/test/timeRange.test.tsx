/**
 * Tests for frontend/src/app/timeRange.tsx (issue #249).
 *
 * EARS acceptance criteria covered:
 *
 * A. Context / hook basics:
 *    - useTimeRange throws when called outside provider.
 *    - useTimeRange returns null activeRange by default (no brush active).
 *    - setRange makes activeRange non-null with correct start/end.
 *    - clearRange resets activeRange to null.
 *
 * B. Provider isolation:
 *    - Two independent providers do not share state.
 */

import { describe, it, expect } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { type ReactNode } from 'react'
import { TimeRangeProvider, useTimeRange } from '../app/timeRange'

// ---------------------------------------------------------------------------
// Wrapper helper
// ---------------------------------------------------------------------------

function wrapper({ children }: { children: ReactNode }) {
  return <TimeRangeProvider>{children}</TimeRangeProvider>
}

// ---------------------------------------------------------------------------
// A. Context / hook basics
// ---------------------------------------------------------------------------

describe('useTimeRange — basic behaviour', () => {
  it('throws when called outside TimeRangeProvider', () => {
    // Vitest + react testing library suppress the console.error from the throw
    expect(() => renderHook(() => useTimeRange())).toThrow(
      'useTimeRange must be used inside <TimeRangeProvider>',
    )
  })

  it('returns null activeRange by default', () => {
    const { result } = renderHook(() => useTimeRange(), { wrapper })
    expect(result.current.activeRange).toBeNull()
  })

  it('setRange sets activeRange with correct start and end', () => {
    const { result } = renderHook(() => useTimeRange(), { wrapper })

    act(() => {
      result.current.setRange({
        start: '2026-06-11T02:00:00.000Z',
        end: '2026-06-11T04:00:00.000Z',
      })
    })

    expect(result.current.activeRange).not.toBeNull()
    expect(result.current.activeRange?.start).toBe('2026-06-11T02:00:00.000Z')
    expect(result.current.activeRange?.end).toBe('2026-06-11T04:00:00.000Z')
  })

  it('clearRange resets activeRange to null', () => {
    const { result } = renderHook(() => useTimeRange(), { wrapper })

    act(() => {
      result.current.setRange({
        start: '2026-06-11T02:00:00.000Z',
        end: '2026-06-11T04:00:00.000Z',
      })
    })
    expect(result.current.activeRange).not.toBeNull()

    act(() => {
      result.current.clearRange()
    })
    expect(result.current.activeRange).toBeNull()
  })

  it('setRange can be called multiple times to update the range', () => {
    const { result } = renderHook(() => useTimeRange(), { wrapper })

    act(() => {
      result.current.setRange({
        start: '2026-06-11T02:00:00.000Z',
        end: '2026-06-11T03:00:00.000Z',
      })
    })
    act(() => {
      result.current.setRange({
        start: '2026-06-11T05:00:00.000Z',
        end: '2026-06-11T07:00:00.000Z',
      })
    })

    expect(result.current.activeRange?.start).toBe('2026-06-11T05:00:00.000Z')
    expect(result.current.activeRange?.end).toBe('2026-06-11T07:00:00.000Z')
  })
})

// ---------------------------------------------------------------------------
// B. Provider isolation
// ---------------------------------------------------------------------------

describe('TimeRangeProvider — isolation', () => {
  it('two independent providers have separate state', () => {
    // Each renderHook call gets its own wrapper instance
    const { result: r1 } = renderHook(() => useTimeRange(), { wrapper })
    const { result: r2 } = renderHook(() => useTimeRange(), { wrapper })

    act(() => {
      r1.current.setRange({
        start: '2026-06-11T01:00:00.000Z',
        end: '2026-06-11T02:00:00.000Z',
      })
    })

    // r2 is a different provider instance — it must still be null
    expect(r2.current.activeRange).toBeNull()
    expect(r1.current.activeRange?.start).toBe('2026-06-11T01:00:00.000Z')
  })
})
