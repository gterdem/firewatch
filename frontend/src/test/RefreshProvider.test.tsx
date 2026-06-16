/**
 * Tests for the ADR-0064 refresh provider: RefreshProvider + useRefreshSignal +
 * useStatsHeartbeat.
 *
 * EARS acceptance criteria covered (1:1):
 *
 * [AC-1] WHEN the net new-event delta between two consecutive polls is > 0,
 *        THE provider SHALL increment `dataVersion` by exactly 1.
 *
 * [AC-2] WHEN the net delta is 0 (or negative), THE provider SHALL NOT
 *        change `dataVersion`.  (Empty poll cycles → zero downstream refetches.)
 *
 * [AC-3] THE provider SHALL expose `grewSources` (the source_types that grew
 *        this cycle) as a ReadonlySet<string>.
 *
 * [AC-4] THE provider SHALL expose `lastDeltaCount` equal to the net new-event
 *        count on the last positive-delta cycle.
 *
 * [AC-5] `useRefreshSignal()` SHALL be callable from inside a RefreshProvider
 *        and SHALL return the current signal.
 *
 * [AC-6] `useRefreshSignal()` SHALL throw when called outside a RefreshProvider.
 *
 * [AC-7] `useHeaderRefresh()` SHALL return the existing UseHeaderRefreshResult
 *        shape unchanged (backward-compatible thin reader).
 *
 * [AC-8] IF GET /stats fails, THE provider SHALL preserve the last good signal
 *        and set isLive=false (503-safe).
 *
 * Security: test IPs use RFC-5737 TEST-NET-3 (203.0.113.x); never real IPs.
 * ADR-0019: React + TS + Vitest.
 * ADR-0064 D1–D3.
 */

// ADR-0064 D4: setup.ts provides a global stub for RefreshContext so that route
// tests that don't wrap components in <RefreshProvider> don't throw.  This file
// tests the REAL RefreshContext implementation, so we need to unmock it first.
import { vi } from 'vitest'
vi.unmock('../app/refresh/RefreshContext')

import { describe, it, expect, beforeEach } from 'vitest'
import { render, screen, act, waitFor } from '@testing-library/react'
import type { StatsResponse } from '../api/types'
import { RefreshProvider, useRefreshSignal } from '../app/refresh/RefreshContext'
import { useHeaderRefresh, HEALTH_POLL_MS } from '../hooks/useHeaderRefresh'

// ---------------------------------------------------------------------------
// Module mock — fetchStats must be hoisted before any import of the mocked
// module so the mock instance is the same one used by useStatsHeartbeat.
// ---------------------------------------------------------------------------

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    fetchStats: vi.fn(),
  }
})

const { fetchStats: mockFetchStats } = await import('../api/client')

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeStats(suricataCount: number, azureCount = 0): StatsResponse {
  return {
    total_logs: suricataCount + azureCount,
    total_ips: 5,
    blocked_percentage: 10,
    last_updated: new Date().toISOString(),
    freshness_minutes: 5,
    source_health: [
      {
        source_type: 'suricata',
        source_id: 'suricata',
        display_name: 'Suricata IDS/IPS',
        flavor: 'pull',
        health: 'ok',
        supervisor_state: 'running',
        last_event_at: new Date().toISOString(),
        event_count: suricataCount,
        last_error: null,
      },
      ...(azureCount > 0
        ? [
            {
              source_type: 'azure_waf',
              source_id: 'azure_waf',
              display_name: 'Azure WAF',
              flavor: 'pull' as const,
              health: 'ok' as const,
              supervisor_state: 'running' as const,
              last_event_at: new Date().toISOString(),
              event_count: azureCount,
              last_error: null,
            },
          ]
        : []),
    ],
  }
}

// ---------------------------------------------------------------------------
// [AC-1] dataVersion increments by 1 on positive delta
// ---------------------------------------------------------------------------

describe('[AC-1] dataVersion increments by exactly 1 when delta > 0', () => {
  beforeEach(() => { vi.clearAllMocks() })

  it('dataVersion increments from 0 to 1 on the first positive delta', async () => {
    vi.useFakeTimers()

    vi.mocked(mockFetchStats)
      .mockResolvedValueOnce(makeStats(500))  // poll 1: baseline
      .mockResolvedValueOnce(makeStats(600))  // poll 2: +100 events → delta > 0

    function Harness() {
      const { dataVersion } = useRefreshSignal()
      return <div data-testid="dv">{dataVersion}</div>
    }

    render(<RefreshProvider><Harness /></RefreshProvider>)

    // First poll: no delta (baseline).
    await act(async () => { await Promise.resolve() })
    expect(screen.getByTestId('dv').textContent).toBe('0')

    // Second poll: delta = 100 → dataVersion must become 1.
    await act(async () => {
      vi.advanceTimersByTime(HEALTH_POLL_MS + 100)
      await Promise.resolve()
    })

    vi.useRealTimers()
    expect(screen.getByTestId('dv').textContent).toBe('1')
  })

  it('dataVersion increments by 1 for each positive-delta cycle (not reset)', async () => {
    vi.useFakeTimers()

    vi.mocked(mockFetchStats)
      .mockResolvedValueOnce(makeStats(500))   // poll 1: baseline
      .mockResolvedValueOnce(makeStats(600))   // poll 2: +100 → dv=1
      .mockResolvedValueOnce(makeStats(700))   // poll 3: +100 → dv=2

    function Harness() {
      const { dataVersion } = useRefreshSignal()
      return <div data-testid="dv">{dataVersion}</div>
    }

    render(<RefreshProvider><Harness /></RefreshProvider>)

    await act(async () => { await Promise.resolve() })
    expect(screen.getByTestId('dv').textContent).toBe('0')

    await act(async () => {
      vi.advanceTimersByTime(HEALTH_POLL_MS + 100)
      await Promise.resolve()
    })
    expect(screen.getByTestId('dv').textContent).toBe('1')

    await act(async () => {
      vi.advanceTimersByTime(HEALTH_POLL_MS + 100)
      await Promise.resolve()
    })

    vi.useRealTimers()
    expect(screen.getByTestId('dv').textContent).toBe('2')
  })
})

// ---------------------------------------------------------------------------
// [AC-2] dataVersion does NOT change when delta is 0 or negative
// ---------------------------------------------------------------------------

describe('[AC-2] dataVersion does NOT change on zero/negative delta', () => {
  beforeEach(() => { vi.clearAllMocks() })

  it('dataVersion stays 0 when event counts are identical between polls', async () => {
    vi.useFakeTimers()

    vi.mocked(mockFetchStats)
      .mockResolvedValueOnce(makeStats(500))  // poll 1: baseline
      .mockResolvedValueOnce(makeStats(500))  // poll 2: no change → delta=0

    function Harness() {
      const { dataVersion } = useRefreshSignal()
      return <div data-testid="dv">{dataVersion}</div>
    }

    render(<RefreshProvider><Harness /></RefreshProvider>)

    await act(async () => { await Promise.resolve() })
    expect(screen.getByTestId('dv').textContent).toBe('0')

    await act(async () => {
      vi.advanceTimersByTime(HEALTH_POLL_MS + 100)
      await Promise.resolve()
    })

    vi.useRealTimers()
    // delta=0: dataVersion must NOT change.
    expect(screen.getByTestId('dv').textContent).toBe('0')
  })

  it('dataVersion stays 0 when event count decreases (negative delta)', async () => {
    vi.useFakeTimers()

    vi.mocked(mockFetchStats)
      .mockResolvedValueOnce(makeStats(600))  // poll 1: baseline
      .mockResolvedValueOnce(makeStats(500))  // poll 2: count dropped → negative delta

    function Harness() {
      const { dataVersion } = useRefreshSignal()
      return <div data-testid="dv">{dataVersion}</div>
    }

    render(<RefreshProvider><Harness /></RefreshProvider>)

    await act(async () => { await Promise.resolve() })
    await act(async () => {
      vi.advanceTimersByTime(HEALTH_POLL_MS + 100)
      await Promise.resolve()
    })

    vi.useRealTimers()
    expect(screen.getByTestId('dv').textContent).toBe('0')
  })
})

// ---------------------------------------------------------------------------
// [AC-3] grewSources populated on positive delta
// ---------------------------------------------------------------------------

describe('[AC-3] grewSources contains source_types that grew', () => {
  beforeEach(() => { vi.clearAllMocks() })

  it('grewSources contains the source whose event_count grew', async () => {
    vi.useFakeTimers()

    vi.mocked(mockFetchStats)
      .mockResolvedValueOnce(makeStats(500, 100))  // poll 1: suricata=500, azure=100
      .mockResolvedValueOnce(makeStats(600, 100))  // poll 2: suricata grew; azure did not

    function Harness() {
      const { grewSources } = useRefreshSignal()
      return <div data-testid="grew">{[...grewSources].sort().join(',')}</div>
    }

    render(<RefreshProvider><Harness /></RefreshProvider>)

    await act(async () => { await Promise.resolve() })
    expect(screen.getByTestId('grew').textContent).toBe('')

    await act(async () => {
      vi.advanceTimersByTime(HEALTH_POLL_MS + 100)
      await Promise.resolve()
    })

    vi.useRealTimers()
    expect(screen.getByTestId('grew').textContent).toContain('suricata')
    expect(screen.getByTestId('grew').textContent).not.toContain('azure_waf')
  })

  it('grewSources is empty on first poll (no baseline)', async () => {
    vi.mocked(mockFetchStats).mockResolvedValue(makeStats(500))

    function Harness() {
      const { grewSources } = useRefreshSignal()
      return <div data-testid="grew">{[...grewSources].join(',')}</div>
    }

    render(<RefreshProvider><Harness /></RefreshProvider>)

    await waitFor(() => {
      // After first poll completes, grewSources must still be empty.
      expect(screen.getByTestId('grew').textContent).toBe('')
    })
  })
})

// ---------------------------------------------------------------------------
// [AC-4] lastDeltaCount equals the net new-event count on the positive cycle
// ---------------------------------------------------------------------------

describe('[AC-4] lastDeltaCount equals the net new-event count', () => {
  beforeEach(() => { vi.clearAllMocks() })

  it('lastDeltaCount is 0 before any positive delta', async () => {
    vi.mocked(mockFetchStats).mockResolvedValue(makeStats(500))

    function Harness() {
      const { lastDeltaCount } = useRefreshSignal()
      return <div data-testid="ldc">{lastDeltaCount}</div>
    }

    render(<RefreshProvider><Harness /></RefreshProvider>)
    await waitFor(() => {
      expect(screen.getByTestId('ldc').textContent).toBe('0')
    })
  })

  it('lastDeltaCount equals 100 when net new-event count is 100', async () => {
    vi.useFakeTimers()

    vi.mocked(mockFetchStats)
      .mockResolvedValueOnce(makeStats(500))
      .mockResolvedValueOnce(makeStats(600))

    function Harness() {
      const { lastDeltaCount } = useRefreshSignal()
      return <div data-testid="ldc">{lastDeltaCount}</div>
    }

    render(<RefreshProvider><Harness /></RefreshProvider>)

    await act(async () => { await Promise.resolve() })

    await act(async () => {
      vi.advanceTimersByTime(HEALTH_POLL_MS + 100)
      await Promise.resolve()
    })

    vi.useRealTimers()
    expect(screen.getByTestId('ldc').textContent).toBe('100')
  })
})

// ---------------------------------------------------------------------------
// [AC-5] useRefreshSignal works inside RefreshProvider
// ---------------------------------------------------------------------------

describe('[AC-5] useRefreshSignal is callable inside RefreshProvider', () => {
  beforeEach(() => { vi.clearAllMocks() })

  it('returns a signal with expected fields inside a RefreshProvider', async () => {
    vi.mocked(mockFetchStats).mockResolvedValue(makeStats(500))

    function Harness() {
      const signal = useRefreshSignal()
      return (
        <div>
          <span data-testid="dv">{signal.dataVersion}</span>
          <span data-testid="is-live">{signal.isLive ? 'live' : 'paused'}</span>
          <span data-testid="ldc">{signal.lastDeltaCount}</span>
        </div>
      )
    }

    render(<RefreshProvider><Harness /></RefreshProvider>)

    await waitFor(() => {
      expect(screen.getByTestId('is-live').textContent).toBe('live')
    })
    // dataVersion starts at 0 (first poll is baseline, no delta).
    expect(screen.getByTestId('dv').textContent).toBe('0')
    expect(screen.getByTestId('ldc').textContent).toBe('0')
  })
})

// ---------------------------------------------------------------------------
// [AC-6] useRefreshSignal throws outside RefreshProvider
// ---------------------------------------------------------------------------

describe('[AC-6] useRefreshSignal throws when used outside RefreshProvider', () => {
  it('throws with a clear message when no provider is present', () => {
    // Suppress the expected React error output in test logs.
    const consoleError = vi.spyOn(console, 'error').mockImplementation(() => {})

    function MissingProvider() {
      useRefreshSignal()
      return null
    }

    expect(() => render(<MissingProvider />)).toThrow(
      /Must be used inside a <RefreshProvider>/,
    )

    consoleError.mockRestore()
  })
})

// ---------------------------------------------------------------------------
// [AC-7] useHeaderRefresh returns the existing UseHeaderRefreshResult shape
// ---------------------------------------------------------------------------

describe('[AC-7] useHeaderRefresh returns the existing shape (backward-compatible)', () => {
  beforeEach(() => { vi.clearAllMocks() })

  it('returns all expected fields from UseHeaderRefreshResult', async () => {
    vi.mocked(mockFetchStats).mockResolvedValue(makeStats(500))

    function Harness() {
      const result = useHeaderRefresh()
      return (
        <div>
          <span data-testid="is-live">{result.isLive ? 'live' : 'paused'}</span>
          <span data-testid="fm">{result.freshnessMinutes}</span>
          <span data-testid="delta">{result.lastSyncDeltaCount}</span>
          <span data-testid="sync-id">{result.syncEventId}</span>
          <span data-testid="pulsing">{[...result.pulsingSources].join(',')}</span>
          <span data-testid="items">{result.healthItems.length}</span>
        </div>
      )
    }

    render(<RefreshProvider><Harness /></RefreshProvider>)

    await waitFor(() => {
      expect(screen.getByTestId('is-live').textContent).toBe('live')
    })

    // Shape assertions: all fields are present and have the expected types.
    expect(screen.getByTestId('fm').textContent).toBe('5')
    expect(screen.getByTestId('delta').textContent).toBe('0')
    expect(screen.getByTestId('sync-id').textContent).toBe('0')
    expect(screen.getByTestId('pulsing').textContent).toBe('')
    expect(screen.getByTestId('items').textContent).toBe('1')
  })

  it('clearSyncDelta is a callable function in the result', async () => {
    vi.mocked(mockFetchStats).mockResolvedValue(makeStats(500))

    function Harness() {
      const result = useHeaderRefresh()
      return (
        <div data-testid="has-clear">
          {typeof result.clearSyncDelta === 'function' ? 'yes' : 'no'}
        </div>
      )
    }

    render(<RefreshProvider><Harness /></RefreshProvider>)
    await waitFor(() => {
      expect(screen.getByTestId('has-clear').textContent).toBe('yes')
    })
  })
})

// ---------------------------------------------------------------------------
// [AC-8] 503-safe: GET /stats failure preserves signal and sets isLive=false
// ---------------------------------------------------------------------------

describe('[AC-8] GET /stats failure: isLive=false, signal preserved', () => {
  beforeEach(() => { vi.clearAllMocks() })

  it('isLive is false when fetchStats rejects', async () => {
    vi.mocked(mockFetchStats).mockRejectedValue(new Error('network error'))

    function Harness() {
      const { isLive } = useRefreshSignal()
      return <div data-testid="is-live">{isLive ? 'live' : 'paused'}</div>
    }

    render(<RefreshProvider><Harness /></RefreshProvider>)

    await waitFor(() => {
      expect(screen.getByTestId('is-live').textContent).toBe('paused')
    })
  })

  it('dataVersion stays 0 (unchanged) when fetchStats rejects', async () => {
    vi.mocked(mockFetchStats).mockRejectedValue(new Error('network error'))

    function Harness() {
      const { dataVersion } = useRefreshSignal()
      return <div data-testid="dv">{dataVersion}</div>
    }

    render(<RefreshProvider><Harness /></RefreshProvider>)

    await waitFor(() => {
      // Give the rejected promise time to resolve — dataVersion must stay 0.
      expect(screen.getByTestId('dv').textContent).toBe('0')
    })
  })

  it('isLive recovers to true after a successful poll following a failure', async () => {
    vi.useFakeTimers()

    vi.mocked(mockFetchStats)
      .mockRejectedValueOnce(new Error('network error'))  // poll 1: fail
      .mockResolvedValueOnce(makeStats(500))               // poll 2: succeed

    function Harness() {
      const { isLive } = useRefreshSignal()
      return <div data-testid="is-live">{isLive ? 'live' : 'paused'}</div>
    }

    render(<RefreshProvider><Harness /></RefreshProvider>)

    // First poll fails → paused.
    await act(async () => { await Promise.resolve() })
    expect(screen.getByTestId('is-live').textContent).toBe('paused')

    // Second poll succeeds → live.
    await act(async () => {
      vi.advanceTimersByTime(HEALTH_POLL_MS + 100)
      await Promise.resolve()
    })

    vi.useRealTimers()
    expect(screen.getByTestId('is-live').textContent).toBe('live')
  })
})
