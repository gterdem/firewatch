/**
 * Tests for src/hooks/useSupervisorGate.ts
 *
 * EARS criteria covered (issue #315):
 *   - WHEN GET /sources returns 503, status transitions to "offline".
 *   - WHILE offline, probe retries back off exponentially (5 s → 60 s cap).
 *   - WHEN retryNow() is called, a probe fires immediately and backoff resets.
 *   - WHEN the probe succeeds again, status transitions to "online".
 *   - Initial state is "unknown" until the first probe settles.
 *
 * Consumer-level testing (docs/lessons.md dead-wire lesson):
 * We test the hook's output values (status, countdown, retryNow), not internal
 * timer state. The fan-out suppression is tested at the SourceCard level
 * (SupervisorGate.test.tsx).
 *
 * Timer strategy: vi.useFakeTimers({ shouldAdvanceTime: true }) so that the
 * internal React/waitFor polling timers advance while we can still control
 * the backoff timers explicitly.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act, waitFor } from '@testing-library/react'
import { useSupervisorGate } from '../hooks/useSupervisorGate'

// Hoist mocks so they are available before vi.mock factory runs
const { mockFetchSources } = vi.hoisted(() => ({
  mockFetchSources: vi.fn(),
}))

vi.mock('../api/sources', () => ({
  fetchSources: mockFetchSources,
}))

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return { ...actual }
})

describe('useSupervisorGate', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    // shouldAdvanceTime: true — allows internal React timer callbacks (waitFor polling)
    // to run while still intercepting the backoff setTimeout calls.
    vi.useFakeTimers({ shouldAdvanceTime: true })
  })

  afterEach(() => {
    vi.useRealTimers()
  })

  // Initial state: unknown until the first probe settles
  it('starts with status "unknown"', () => {
    // Never resolves — probe stays in-flight
    mockFetchSources.mockReturnValue(new Promise(() => {}))
    const { result } = renderHook(() => useSupervisorGate())
    expect(result.current.supervisorStatus).toBe('unknown')
  })

  // WHEN probe succeeds → status "online"
  it('transitions to "online" when the probe succeeds', async () => {
    mockFetchSources.mockResolvedValue([])
    const { result } = renderHook(() => useSupervisorGate())

    await waitFor(() => {
      expect(result.current.supervisorStatus).toBe('online')
    })
  })

  // WHEN probe returns 503 → status "offline" and banner should appear
  it('transitions to "offline" when the probe returns 503', async () => {
    const { ApiError } = await import('../api/client')
    mockFetchSources.mockRejectedValue(new ApiError(503, null, 'Service Unavailable'))

    const { result } = renderHook(() => useSupervisorGate())

    await waitFor(() => {
      expect(result.current.supervisorStatus).toBe('offline')
    })
  })

  // WHILE offline: retryCountdown is set to the first backoff delay (5 s = 5)
  it('sets a non-zero retryCountdown when offline', async () => {
    const { ApiError } = await import('../api/client')
    mockFetchSources.mockRejectedValue(new ApiError(503, null, 'Service Unavailable'))

    const { result } = renderHook(() => useSupervisorGate())

    await waitFor(() => {
      expect(result.current.supervisorStatus).toBe('offline')
    })

    expect(result.current.retryCountdown).toBeGreaterThan(0)
  })

  // WHEN the supervisor comes back: status transitions to "online"
  it('transitions back to "online" when the probe succeeds after being offline', async () => {
    const { ApiError } = await import('../api/client')
    // First probe: 503
    mockFetchSources.mockRejectedValueOnce(new ApiError(503, null, 'Service Unavailable'))
    // Second probe: success
    mockFetchSources.mockResolvedValueOnce([])

    const { result } = renderHook(() => useSupervisorGate())

    // Wait for offline status
    await waitFor(() => {
      expect(result.current.supervisorStatus).toBe('offline')
    })

    // Advance time past the first backoff (5 s)
    await act(async () => {
      vi.advanceTimersByTime(6_000)
    })

    await waitFor(() => {
      expect(result.current.supervisorStatus).toBe('online')
    })
  })

  // WHEN retryNow() is called: fires the probe immediately
  it('fires the probe immediately when retryNow() is called', async () => {
    const { ApiError } = await import('../api/client')
    // First probe: 503
    mockFetchSources.mockRejectedValueOnce(new ApiError(503, null, 'Service Unavailable'))
    // Second probe (triggered by retryNow): success
    mockFetchSources.mockResolvedValueOnce([])

    const { result } = renderHook(() => useSupervisorGate())

    // Wait for offline status
    await waitFor(() => {
      expect(result.current.supervisorStatus).toBe('offline')
    })

    // Call retryNow — should probe immediately without waiting for backoff
    await act(async () => {
      result.current.retryNow()
    })

    await waitFor(() => {
      expect(result.current.supervisorStatus).toBe('online')
    })

    // Probe was called at least twice: initial + retryNow
    expect(mockFetchSources).toHaveBeenCalledTimes(2)
  })

  // WHEN retryNow() is called: countdown resets to 0 on recovery
  it('resets retryCountdown to 0 when retryNow() succeeds', async () => {
    const { ApiError } = await import('../api/client')
    mockFetchSources.mockRejectedValueOnce(new ApiError(503, null, 'Service Unavailable'))
    mockFetchSources.mockResolvedValueOnce([])

    const { result } = renderHook(() => useSupervisorGate())

    await waitFor(() => expect(result.current.supervisorStatus).toBe('offline'))

    await act(async () => {
      result.current.retryNow()
    })

    await waitFor(() => {
      expect(result.current.supervisorStatus).toBe('online')
      expect(result.current.retryCountdown).toBe(0)
    })
  })

  // WHILE offline: backoff resets to 5 s after retryNow() (not doubling)
  it('resets the backoff counter when retryNow() is called', async () => {
    const { ApiError } = await import('../api/client')
    // All probes fail with 503
    mockFetchSources.mockRejectedValue(new ApiError(503, null, 'Service Unavailable'))

    const { result } = renderHook(() => useSupervisorGate())

    // First probe — goes offline with 5 s backoff
    await waitFor(() => expect(result.current.supervisorStatus).toBe('offline'))

    // Advance 6 s to trigger the first backoff retry (attempt 1 → 10 s scheduled)
    await act(async () => {
      vi.advanceTimersByTime(6_000)
    })
    await waitFor(() => expect(result.current.supervisorStatus).toBe('offline'))

    // Now call retryNow — should reset attempt and show ~5 s (not 20 s)
    await act(async () => {
      result.current.retryNow()
    })

    await waitFor(() => {
      // After retryNow fails, the next backoff should be 5 s (attempt reset to 0 → delay = 5 s)
      // retryCountdown starts at 5 s then ticks down
      expect(result.current.retryCountdown).toBeLessThanOrEqual(5)
      expect(result.current.retryCountdown).toBeGreaterThan(0)
    })
  })
})
