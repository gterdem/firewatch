/**
 * Tests for src/hooks/useSourceStatsHealth.ts
 *
 * EARS criteria covered:
 *   - State-driven: GIVEN a /stats response with event_count + last_event_at,
 *     getHealthItem MUST return an item with those values (not zeroed/null).
 *   - State-driven: getHealth(source_type) returns the health string from /stats.
 *   - State-driven: getHealthItem(source_type) returns the full item including
 *     event_count and last_event_at matching the /stats wire shape.
 *   - State-driven: GIVEN no /stats item for a source_type, both lookups return null.
 *   - State-driven: GIVEN multiple instances of one source_type, event_count is
 *     summed and last_event_at is the most-recent across instances.
 *   - State-driven: GIVEN a /stats fetch failure, settled=true and lookups return null.
 *   - Consistency: getHealth and getHealthItem.health agree for the same source_type.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { useSourceStatsHealth } from '../hooks/useSourceStatsHealth'
import type { SourceHealth } from '../api/types'

// Hoist mocks so they are available before the vi.mock factory runs
const { mockFetchStats } = vi.hoisted(() => ({
  mockFetchStats: vi.fn(),
}))

vi.mock('../api/client', () => ({
  fetchStats: mockFetchStats,
}))

// ---------------------------------------------------------------------------
// Fixtures — ADR-0032 §B wire shape
// ---------------------------------------------------------------------------

const WAF_ITEM: SourceHealth = {
  source_type: 'azure_waf',
  source_id: 'azure_waf',
  display_name: 'Azure WAF',
  flavor: 'pull',
  health: 'amber',
  supervisor_state: null,
  last_event_at: '2026-06-14T05:04:00Z',
  event_count: 269,
  last_error: null,
}

const WAF_ITEM_2: SourceHealth = {
  source_type: 'azure_waf',
  source_id: 'azure_waf_secondary',
  display_name: 'Azure WAF',
  flavor: 'pull',
  health: 'ok',
  supervisor_state: 'running',
  last_event_at: '2026-06-14T05:10:00Z', // more recent than WAF_ITEM
  event_count: 100,
  last_error: null,
}

const SURICATA_ITEM: SourceHealth = {
  source_type: 'suricata',
  source_id: 'suricata',
  display_name: 'Suricata IDS/IPS',
  flavor: 'pull',
  health: 'ok',
  supervisor_state: 'running',
  last_event_at: '2026-06-14T04:00:00Z',
  event_count: 42,
  last_error: null,
}

// ---------------------------------------------------------------------------
// getHealth — backward-compat lookup (string only)
// ---------------------------------------------------------------------------

describe('useSourceStatsHealth — getHealth (backward compat)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('returns the health string for a known source_type', async () => {
    mockFetchStats.mockResolvedValue({
      source_health: [WAF_ITEM, SURICATA_ITEM],
      total_logs: 0, total_ips: 0, blocked_percentage: 0, last_updated: null,
    })

    const { result } = renderHook(() => useSourceStatsHealth())

    await waitFor(() => expect(result.current.settled).toBe(true))

    expect(result.current.getHealth('azure_waf')).toBe('amber')
    expect(result.current.getHealth('suricata')).toBe('ok')
  })

  it('returns null for an unknown source_type', async () => {
    mockFetchStats.mockResolvedValue({
      source_health: [WAF_ITEM],
      total_logs: 0, total_ips: 0, blocked_percentage: 0, last_updated: null,
    })

    const { result } = renderHook(() => useSourceStatsHealth())

    await waitFor(() => expect(result.current.settled).toBe(true))

    expect(result.current.getHealth('unknown_source')).toBeNull()
  })

  it('returns null before the fetch settles', () => {
    // Never-resolving promise — hook is in-flight
    mockFetchStats.mockReturnValue(new Promise(() => {}))

    const { result } = renderHook(() => useSourceStatsHealth())

    // Immediately after render, settled=false and getHealth returns null
    expect(result.current.settled).toBe(false)
    expect(result.current.getHealth('azure_waf')).toBeNull()
  })

  it('returns null on fetch failure (settled=true, empty map)', async () => {
    mockFetchStats.mockRejectedValue(new Error('Network error'))

    const { result } = renderHook(() => useSourceStatsHealth())

    await waitFor(() => expect(result.current.settled).toBe(true))

    expect(result.current.getHealth('azure_waf')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// getHealthItem — full item lookup (event_count + last_event_at)
// ---------------------------------------------------------------------------

describe('useSourceStatsHealth — getHealthItem (Events + Last event fix)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('GIVEN /stats returns event_count=269 and last_event_at, getHealthItem exposes both', async () => {
    mockFetchStats.mockResolvedValue({
      source_health: [WAF_ITEM],
      total_logs: 0, total_ips: 0, blocked_percentage: 0, last_updated: null,
    })

    const { result } = renderHook(() => useSourceStatsHealth())

    await waitFor(() => expect(result.current.settled).toBe(true))

    const item = result.current.getHealthItem('azure_waf')
    expect(item).not.toBeNull()
    expect(item!.eventCount).toBe(269)
    expect(item!.lastEventAt).toBe('2026-06-14T05:04:00Z')
  })

  it('getHealthItem.health agrees with getHealth for the same source_type', async () => {
    mockFetchStats.mockResolvedValue({
      source_health: [WAF_ITEM, SURICATA_ITEM],
      total_logs: 0, total_ips: 0, blocked_percentage: 0, last_updated: null,
    })

    const { result } = renderHook(() => useSourceStatsHealth())

    await waitFor(() => expect(result.current.settled).toBe(true))

    expect(result.current.getHealthItem('azure_waf')!.health).toBe(
      result.current.getHealth('azure_waf'),
    )
    expect(result.current.getHealthItem('suricata')!.health).toBe(
      result.current.getHealth('suricata'),
    )
  })

  it('returns null for an unknown source_type', async () => {
    mockFetchStats.mockResolvedValue({
      source_health: [WAF_ITEM],
      total_logs: 0, total_ips: 0, blocked_percentage: 0, last_updated: null,
    })

    const { result } = renderHook(() => useSourceStatsHealth())

    await waitFor(() => expect(result.current.settled).toBe(true))

    expect(result.current.getHealthItem('nonexistent_source')).toBeNull()
  })

  it('returns null before the fetch settles', () => {
    mockFetchStats.mockReturnValue(new Promise(() => {}))

    const { result } = renderHook(() => useSourceStatsHealth())

    expect(result.current.settled).toBe(false)
    expect(result.current.getHealthItem('azure_waf')).toBeNull()
  })

  it('returns null on fetch failure', async () => {
    mockFetchStats.mockRejectedValue(new Error('500'))

    const { result } = renderHook(() => useSourceStatsHealth())

    await waitFor(() => expect(result.current.settled).toBe(true))

    expect(result.current.getHealthItem('azure_waf')).toBeNull()
  })
})

// ---------------------------------------------------------------------------
// Multi-instance aggregation
// ---------------------------------------------------------------------------

describe('useSourceStatsHealth — multi-instance aggregation', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('event_count is summed across instances of the same source_type', async () => {
    // WAF_ITEM: 269 events, WAF_ITEM_2: 100 events → total 369
    mockFetchStats.mockResolvedValue({
      source_health: [WAF_ITEM, WAF_ITEM_2],
      total_logs: 0, total_ips: 0, blocked_percentage: 0, last_updated: null,
    })

    const { result } = renderHook(() => useSourceStatsHealth())

    await waitFor(() => expect(result.current.settled).toBe(true))

    const item = result.current.getHealthItem('azure_waf')
    expect(item).not.toBeNull()
    expect(item!.eventCount).toBe(369) // 269 + 100
  })

  it('last_event_at is the most-recent across instances', async () => {
    // WAF_ITEM: 2026-06-14T05:04:00Z, WAF_ITEM_2: 2026-06-14T05:10:00Z → pick the later
    mockFetchStats.mockResolvedValue({
      source_health: [WAF_ITEM, WAF_ITEM_2],
      total_logs: 0, total_ips: 0, blocked_percentage: 0, last_updated: null,
    })

    const { result } = renderHook(() => useSourceStatsHealth())

    await waitFor(() => expect(result.current.settled).toBe(true))

    const item = result.current.getHealthItem('azure_waf')
    expect(item).not.toBeNull()
    // Must be the LATER timestamp (WAF_ITEM_2's last_event_at)
    expect(item!.lastEventAt).toBe('2026-06-14T05:10:00Z')
  })

  it('health is worst-of across instances (amber wins over ok)', async () => {
    // WAF_ITEM: amber, WAF_ITEM_2: ok → worst = amber
    mockFetchStats.mockResolvedValue({
      source_health: [WAF_ITEM, WAF_ITEM_2],
      total_logs: 0, total_ips: 0, blocked_percentage: 0, last_updated: null,
    })

    const { result } = renderHook(() => useSourceStatsHealth())

    await waitFor(() => expect(result.current.settled).toBe(true))

    expect(result.current.getHealth('azure_waf')).toBe('amber')
    expect(result.current.getHealthItem('azure_waf')!.health).toBe('amber')
  })
})
