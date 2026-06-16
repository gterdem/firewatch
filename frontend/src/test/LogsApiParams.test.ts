/**
 * Tests for src/api/logs.ts — URL parameter mapping (issue #177).
 *
 * EARS criterion: WHEN a user enters free text in the Logs search, THEN the
 * table SHALL show only matching events.
 *
 * These tests assert the HTTP URL that fetchPaginatedLogs builds so that
 * regressions to a silently-ignored param name (e.g. ?search=) are caught
 * before they reach the backend.
 *
 * Design choice (documented here per PR requirement):
 *   The search box always maps to `?q=`.  The backend's `q` clause already
 *   matches source_ip (substring), rule_id, payload_snippet, and rule
 *   descriptions — so an IP fragment typed in the search box is correctly
 *   found via `?q=` without a separate `?ip=` code path.  Keeping a single
 *   param keeps the UX simple and avoids heuristic IP-detection logic in the
 *   frontend (which would be fragile and untestable at the unit level).
 *   The dedicated `?ip=` param (LogsFilter.ip) remains available for future
 *   tooling that wants an exact IP facet.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { fetchPaginatedLogs } from '../api/logs'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Capture the URL of the most recent fetch() call. */
function capturedUrl(): string {
  const calls = (globalThis.fetch as ReturnType<typeof vi.fn>).mock.calls
  const last = calls[calls.length - 1]
  return last ? String(last[0]) : ''
}

// ---------------------------------------------------------------------------
// Setup: mock fetch globally
// ---------------------------------------------------------------------------

beforeEach(() => {
  vi.stubGlobal(
    'fetch',
    vi.fn().mockResolvedValue({
      ok: true,
      json: () =>
        Promise.resolve({ logs: [], next_cursor: null, has_more: false, total_matching: 0 }),
    }),
  )
})

afterEach(() => {
  vi.unstubAllGlobals()
})

// ---------------------------------------------------------------------------
// Issue #177 regression tests — assert the real query-param names
// ---------------------------------------------------------------------------

describe('fetchPaginatedLogs — URL param mapping (issue #177)', () => {
  it('sends ?q= (not ?search=) when filter.q is set', async () => {
    await fetchPaginatedLogs({ q: 'injection', limit: 50 })
    const url = capturedUrl()
    const params = new URL(url, 'http://localhost').searchParams
    expect(params.get('q')).toBe('injection')
    // Regression guard: the old ?search= param must NOT be sent
    expect(params.has('search')).toBe(false)
  })

  it('sends ?ip= when filter.ip is set', async () => {
    await fetchPaginatedLogs({ ip: '192.0.2', limit: 50 })
    const url = capturedUrl()
    const params = new URL(url, 'http://localhost').searchParams
    expect(params.get('ip')).toBe('192.0.2')
  })

  it('sends both ?q= and ?ip= when both are set', async () => {
    await fetchPaginatedLogs({ q: 'sqli', ip: '10.0.0', limit: 50 })
    const url = capturedUrl()
    const params = new URL(url, 'http://localhost').searchParams
    expect(params.get('q')).toBe('sqli')
    expect(params.get('ip')).toBe('10.0.0')
    expect(params.has('search')).toBe(false)
  })

  it('omits ?q= entirely when filter.q is undefined', async () => {
    await fetchPaginatedLogs({ limit: 50 })
    const url = capturedUrl()
    const params = new URL(url, 'http://localhost').searchParams
    expect(params.has('q')).toBe(false)
    expect(params.has('search')).toBe(false)
  })

  it('includes cursor, limit, source_type, category, severity in URL', async () => {
    await fetchPaginatedLogs({
      cursor: 'tok123',
      limit: 25,
      source_type: 'suricata',
      category: 'sqli',
      severity: 'high',
    })
    const url = capturedUrl()
    const params = new URL(url, 'http://localhost').searchParams
    expect(params.get('cursor')).toBe('tok123')
    expect(params.get('limit')).toBe('25')
    expect(params.get('source_type')).toBe('suricata')
    expect(params.get('category')).toBe('sqli')
    expect(params.get('severity')).toBe('high')
  })
})
