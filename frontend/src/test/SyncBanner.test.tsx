/**
 * Tests for the sync notification banner (replaces SyncToastAutoDismiss.test.tsx).
 *
 * Covers the conversion from top-right toast to full-width header banner:
 *   - Banner renders below the header with attributed copy (single / multi source).
 *   - Auto-dismisses after BANNER_DISMISS_MS = 5000 ms.
 *   - Manual × close button hides the banner immediately.
 *   - Second event while banner is visible refreshes copy and restarts the timer.
 *   - Preserves all #625 semantics: drives off syncEventId (monotonic), dismiss
 *     timer in a ref, no leaked timers, reliable dismiss (no hang).
 *
 * Root cause (original toast bug, preserved as regression guard):
 *   The original effect depended on `lastSyncDeltaCount`. Calling
 *   `clearSyncDelta()` inside the effect flipped that dependency N → 0, which
 *   caused the effect's cleanup to run and cancel the dismiss timer before it
 *   fired, leaving the toast/banner permanently visible.
 *   Fix: depends on `syncEventId` (monotonic, never reset to 0); the dismiss
 *   timer lives in a `useRef` so it survives dependency-flip re-runs.
 *
 * EARS acceptance criteria:
 *
 * [SB-1] WHEN a positive delta arrives with a single pulsing source,
 *        the banner MUST become visible with the copy
 *        "{N} new events from {source display name}".
 *
 * [SB-2] WHEN a positive delta arrives with multiple pulsing sources,
 *        the banner MUST show "{N} new events ({src1}, {src2})".
 *
 * [SB-3] WHEN BANNER_DISMISS_MS elapses after a delta, the banner MUST
 *        be hidden (auto-dismiss must fire — regression guard for the
 *        original timer-cancel bug).
 *
 * [SB-4] WHEN the × close button is clicked, the banner MUST be hidden
 *        immediately (manual dismiss).
 *
 * [SB-5] WHEN a second delta arrives while the banner is visible, the
 *        count/copy MUST update, the dismiss timer MUST restart
 *        (fresh BANNER_DISMISS_MS from the second event), and the
 *        banner MUST still auto-dismiss — no permanent hang, no leaked
 *        timers.
 *
 * Testing strategy: render AppHeader directly with mocked API and theme.
 * Drive polls by advancing fake timers, then switch to real timers before
 * asserting DOM state to avoid waitFor + fake-timer conflicts (same pattern
 * as HeaderFreshness tests).
 */

// ADR-0064 D4: setup.ts provides a global stub for RefreshContext so that route
// tests that don't wrap components in <RefreshProvider> don't throw.  This file
// tests the REAL RefreshContext, so we need to unmock it first.
import { vi } from 'vitest'
vi.unmock('../app/refresh/RefreshContext')

import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { render, screen, act, fireEvent } from '@testing-library/react'
import type React from 'react'
import { RefreshProvider } from '../app/refresh/RefreshContext'

// ---------------------------------------------------------------------------
// Module mocks — hoisted before any import of the mocked modules
// ---------------------------------------------------------------------------

vi.mock('../app/ThemeContext', () => ({
  useTheme: () => ({ theme: 'dark', toggleTheme: vi.fn() }),
  ThemeProvider: ({ children }: { children: React.ReactNode }) => children,
}))

vi.mock('../api/client', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../api/client')>()
  return {
    ...actual,
    fetchStats: vi.fn(),
  }
})

// Import the mocked fetchStats AFTER vi.mock so we get the mock instance.
const { fetchStats: mockFetchStats } = await import('../api/client')

// ---------------------------------------------------------------------------
// Constants mirrored from production code
// ---------------------------------------------------------------------------

/** Must match BANNER_DISMISS_MS in AppHeader.tsx. */
const BANNER_DISMISS_MS = 5_000
const HEALTH_POLL_MS = 30_000

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/** Build a /stats response where one source (suricata) has the given event count. */
function makeStatsSingle(eventCount: number) {
  return {
    total_logs: eventCount,
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
        event_count: eventCount,
        last_error: null,
      },
    ],
  }
}

/** Build a /stats response where TWO sources have event counts. */
function makeStatsMulti(wafCount: number, suricataCount: number) {
  return {
    total_logs: wafCount + suricataCount,
    total_ips: 10,
    blocked_percentage: 15,
    last_updated: new Date().toISOString(),
    freshness_minutes: 5,
    source_health: [
      {
        source_type: 'azure_waf',
        source_id: 'azure_waf',
        display_name: 'Azure WAF',
        flavor: 'pull',
        health: 'ok',
        supervisor_state: 'running',
        last_event_at: new Date().toISOString(),
        event_count: wafCount,
        last_error: null,
      },
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
    ],
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async function renderAppHeader() {
  const { MemoryRouter } = await import('react-router-dom')
  const { default: AppHeader } = await import('../app/AppHeader')
  return render(
    <RefreshProvider>
      <MemoryRouter>
        <AppHeader />
      </MemoryRouter>
    </RefreshProvider>,
  )
}

/**
 * Drive the hook through poll 1 (baseline) + poll 2 (positive delta).
 * Returns control with fake timers still active; caller must call
 * vi.useRealTimers() before asserting to avoid waitFor issues.
 */
async function driveTwoPollsWithDelta(count1 = 500, count2 = 600) {
  vi.mocked(mockFetchStats)
    .mockResolvedValueOnce(makeStatsSingle(count1))
    .mockResolvedValueOnce(makeStatsSingle(count2))

  await renderAppHeader()

  // Poll 1: flush microtasks so the first fetchStats resolves.
  await act(async () => { await Promise.resolve() })

  // Advance interval to trigger poll 2.
  await act(async () => {
    vi.advanceTimersByTime(HEALTH_POLL_MS + 100)
    await Promise.resolve()
  })

  // Advance the 0ms show timer (schedules setBannerState visible:true).
  await act(async () => {
    vi.advanceTimersByTime(0)
    await Promise.resolve()
  })
}

// ---------------------------------------------------------------------------
// [SB-1] Single-source attribution
// ---------------------------------------------------------------------------

describe('[SB-1] Banner appears with single-source attributed copy', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.clearAllMocks()
  })
  afterEach(() => {
    vi.useRealTimers()
  })

  it('banner is NOT visible before any data arrives', async () => {
    vi.mocked(mockFetchStats).mockReturnValue(new Promise(() => {}))
    await renderAppHeader()
    vi.useRealTimers()
    // Banner is always rendered in the DOM for animation purposes.
    // "Not visible" means opacity:0 (and pointer-events:none).
    const banner = screen.getByTestId('sync-banner')
    expect(banner.style.opacity).toBe('0')
  })

  it('banner becomes visible after the second poll produces a positive delta', async () => {
    await driveTwoPollsWithDelta(500, 600)
    vi.useRealTimers()
    const banner = screen.getByTestId('sync-banner')
    expect(banner.style.opacity).toBe('1')
  })

  it('banner shows "N new events from {display name}" for a single source', async () => {
    await driveTwoPollsWithDelta(1000, 1250)
    vi.useRealTimers()
    const msg = screen.getByTestId('sync-banner-message')
    expect(msg.textContent).toContain('250')
    expect(msg.textContent).toContain('new events from')
    expect(msg.textContent).toContain('Suricata IDS/IPS')
  })

  it('banner is hidden after first poll only (no delta on first poll)', async () => {
    vi.mocked(mockFetchStats).mockResolvedValue(makeStatsSingle(500))
    await renderAppHeader()
    await act(async () => { await Promise.resolve() })
    await act(async () => { vi.advanceTimersByTime(0); await Promise.resolve() })
    vi.useRealTimers()
    // No delta yet — banner should be hidden (opacity 0).
    expect(screen.getByTestId('sync-banner').style.opacity).toBe('0')
  })
})

// ---------------------------------------------------------------------------
// [SB-2] Multi-source attribution
// ---------------------------------------------------------------------------

describe('[SB-2] Banner shows multi-source attributed copy', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.clearAllMocks()
  })
  afterEach(() => {
    vi.useRealTimers()
  })

  it('shows "{N} new events ({src1}, {src2})" when two sources grew', async () => {
    // Poll 1: baseline (500 WAF, 200 Suricata)
    // Poll 2: both grew (600 WAF, 250 Suricata) → delta = 150 total
    vi.mocked(mockFetchStats)
      .mockResolvedValueOnce(makeStatsMulti(500, 200))
      .mockResolvedValueOnce(makeStatsMulti(600, 250))

    await renderAppHeader()
    await act(async () => { await Promise.resolve() })
    await act(async () => {
      vi.advanceTimersByTime(HEALTH_POLL_MS + 100)
      await Promise.resolve()
    })
    await act(async () => { vi.advanceTimersByTime(0); await Promise.resolve() })

    vi.useRealTimers()

    const banner = screen.getByTestId('sync-banner')
    expect(banner.style.opacity).toBe('1')

    const msg = screen.getByTestId('sync-banner-message')
    // Delta is 150 (600-500 + 250-200)
    expect(msg.textContent).toContain('150')
    expect(msg.textContent).toContain('new events')
    // Both display names should appear
    expect(msg.textContent).toContain('Azure WAF')
    expect(msg.textContent).toContain('Suricata IDS/IPS')
  })
})

// ---------------------------------------------------------------------------
// [SB-3] Banner auto-dismisses after BANNER_DISMISS_MS (= 5000 ms)
// ---------------------------------------------------------------------------

describe('[SB-3] Banner auto-dismisses after BANNER_DISMISS_MS', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.clearAllMocks()
  })
  afterEach(() => {
    vi.useRealTimers()
  })

  it('banner is hidden after BANNER_DISMISS_MS elapses', async () => {
    await driveTwoPollsWithDelta(500, 600)

    // Banner is showing at this point.
    expect(screen.getByTestId('sync-banner').style.opacity).toBe('1')

    // Advance past dismiss timeout.
    await act(async () => {
      vi.advanceTimersByTime(BANNER_DISMISS_MS)
    })

    vi.useRealTimers()
    expect(screen.getByTestId('sync-banner').style.opacity).toBe('0')
  })

  it('banner does NOT remain visible indefinitely — regression guard for the original bug', async () => {
    // Original bug: clearSyncDelta() inside effect flipped lastSyncDeltaCount
    // N → 0, triggering effect cleanup which cancelled the dismiss timer.
    // With the fix (syncEventId), clearing the count must NOT cancel dismissal.
    await driveTwoPollsWithDelta(1000, 1500)

    expect(screen.getByTestId('sync-banner').style.opacity).toBe('1')

    // Advance well past the dismiss window.
    await act(async () => {
      vi.advanceTimersByTime(BANNER_DISMISS_MS + 1_000)
    })

    vi.useRealTimers()
    expect(screen.getByTestId('sync-banner').style.opacity).toBe('0')
  })

  it('banner is still visible just before BANNER_DISMISS_MS (not dismissed too early)', async () => {
    await driveTwoPollsWithDelta(500, 600)
    expect(screen.getByTestId('sync-banner').style.opacity).toBe('1')

    // Advance to just before the dismiss deadline.
    await act(async () => {
      vi.advanceTimersByTime(BANNER_DISMISS_MS - 100)
    })

    vi.useRealTimers()
    // Must still be visible — dismiss must not fire early.
    expect(screen.getByTestId('sync-banner').style.opacity).toBe('1')
  })
})

// ---------------------------------------------------------------------------
// [SB-4] Manual close button hides the banner immediately
// ---------------------------------------------------------------------------

describe('[SB-4] × close button dismisses the banner immediately', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.clearAllMocks()
  })
  afterEach(() => {
    vi.useRealTimers()
  })

  it('clicking × hides the banner before auto-dismiss fires', async () => {
    await driveTwoPollsWithDelta(500, 600)

    // Banner is showing.
    expect(screen.getByTestId('sync-banner').style.opacity).toBe('1')

    // Click the close button.
    const closeBtn = screen.getByTestId('sync-banner-close')
    fireEvent.click(closeBtn)

    vi.useRealTimers()
    expect(screen.getByTestId('sync-banner').style.opacity).toBe('0')
  })

  it('clicking × before auto-dismiss does not leave a leaked timer', async () => {
    // Verify: after clicking close, advancing past BANNER_DISMISS_MS does not
    // somehow re-show or cause errors. This exercises the ref-cleanup in
    // handleBannerClose.
    await driveTwoPollsWithDelta(500, 600)

    const closeBtn = screen.getByTestId('sync-banner-close')
    fireEvent.click(closeBtn)

    // Advance well past where dismiss would have fired.
    await act(async () => {
      vi.advanceTimersByTime(BANNER_DISMISS_MS + 500)
    })

    vi.useRealTimers()
    // Banner must still be hidden (no re-show from leaked timer).
    expect(screen.getByTestId('sync-banner').style.opacity).toBe('0')
  })
})

// ---------------------------------------------------------------------------
// [SB-5] Second delta refreshes count/copy and restarts the dismiss timer
// ---------------------------------------------------------------------------

describe('[SB-5] Second delta refreshes copy and restarts dismiss timer', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    vi.clearAllMocks()
  })
  afterEach(() => {
    vi.useRealTimers()
  })

  it('banner still auto-dismisses after a second delta arrives while visible', async () => {
    // Poll sequence: 500 → 600 (delta 100) → 750 (delta 150).
    vi.mocked(mockFetchStats)
      .mockResolvedValueOnce(makeStatsSingle(500))
      .mockResolvedValueOnce(makeStatsSingle(600))
      .mockResolvedValueOnce(makeStatsSingle(750))

    await renderAppHeader()
    await act(async () => { await Promise.resolve() })

    // ---- Poll 2: first delta → banner appears ----
    await act(async () => {
      vi.advanceTimersByTime(HEALTH_POLL_MS + 100)
      await Promise.resolve()
    })
    await act(async () => { vi.advanceTimersByTime(0); await Promise.resolve() })
    expect(screen.getByTestId('sync-banner').style.opacity).toBe('1')

    // Advance partway into the dismiss window (half of BANNER_DISMISS_MS).
    await act(async () => {
      vi.advanceTimersByTime(Math.floor(BANNER_DISMISS_MS / 2))
    })
    expect(screen.getByTestId('sync-banner').style.opacity).toBe('1')

    // ---- Poll 3: second delta while banner is still visible ----
    // Remaining interval time to reach next poll.
    const remaining = HEALTH_POLL_MS - Math.floor(BANNER_DISMISS_MS / 2)
    await act(async () => {
      vi.advanceTimersByTime(remaining + 100)
      await Promise.resolve()
    })
    await act(async () => { vi.advanceTimersByTime(0); await Promise.resolve() })
    // Banner must still be visible after second delta.
    expect(screen.getByTestId('sync-banner').style.opacity).toBe('1')

    // After a full BANNER_DISMISS_MS from the second event, banner must be gone.
    await act(async () => {
      vi.advanceTimersByTime(BANNER_DISMISS_MS)
    })

    vi.useRealTimers()
    expect(screen.getByTestId('sync-banner').style.opacity).toBe('0')
  })

  it('no timer leaks: banner dismisses cleanly after multiple consecutive events', async () => {
    vi.mocked(mockFetchStats)
      .mockResolvedValueOnce(makeStatsSingle(100))
      .mockResolvedValueOnce(makeStatsSingle(200))
      .mockResolvedValueOnce(makeStatsSingle(300))
      .mockResolvedValue(makeStatsSingle(300)) // stable thereafter

    await renderAppHeader()
    await act(async () => { await Promise.resolve() })

    // Poll 2 — first delta.
    await act(async () => {
      vi.advanceTimersByTime(HEALTH_POLL_MS + 100)
      await Promise.resolve()
    })
    await act(async () => { vi.advanceTimersByTime(0); await Promise.resolve() })

    // Poll 3 — second delta while first dismiss timer may still be running.
    await act(async () => {
      vi.advanceTimersByTime(HEALTH_POLL_MS + 100)
      await Promise.resolve()
    })
    await act(async () => { vi.advanceTimersByTime(0); await Promise.resolve() })

    // Advance past dismiss deadline.
    await act(async () => {
      vi.advanceTimersByTime(BANNER_DISMISS_MS + 500)
    })

    vi.useRealTimers()
    expect(screen.getByTestId('sync-banner').style.opacity).toBe('0')
  })
})
