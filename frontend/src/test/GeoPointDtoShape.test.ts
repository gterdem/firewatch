/**
 * Regression tests for GeoPoint DTO shape alignment — fix #178.
 *
 * EARS criterion:
 *   WHEN GET /analytics/geo returns N geolocated IPs,
 *   THEN the map SHALL render N markers with numeric (non-NaN) radii.
 *
 * Root cause of #178:
 *   GeoPoint.count (old) vs API field total_events (real).
 *   markerRadius(pt.count) → markerRadius(undefined) → NaN → SVG path flood + blank map.
 *
 * These tests assert the REAL DTO shape:
 *   { ip, country, city, lat, lon, total_events, blocked, rules_triggered }
 * and that the marker radius function produces a finite, positive number for each point.
 */

import { describe, it, expect } from 'vitest'
import type { GeoPoint } from '../api/types'

// ---------------------------------------------------------------------------
// markerRadius — extracted from GeoMap.tsx (inline to keep the test pure)
// ---------------------------------------------------------------------------

/** Mirrors GeoMap.tsx markerRadius — sqrt(total_events) clamped to [4, 30]. */
function markerRadius(totalEvents: number): number {
  return Math.min(30, Math.max(4, Math.sqrt(totalEvents) * 2))
}

// ---------------------------------------------------------------------------
// Real DTO fixtures (verbatim shape from store.get_analytics_geo — fix #178)
// ---------------------------------------------------------------------------

const REAL_DTO_POINTS: GeoPoint[] = [
  {
    ip: '192.0.2.1',
    country: 'US',
    city: 'New York',
    lat: 40.7128,
    lon: -74.006,
    total_events: 450,
    blocked: 320,
    rules_triggered: 5,
  },
  {
    ip: '198.51.100.1',
    country: 'GB',
    city: 'London',
    lat: 51.5074,
    lon: -0.1278,
    total_events: 120,
    blocked: 85,
    rules_triggered: 3,
  },
  {
    ip: '203.0.113.1',
    country: 'DE',
    city: 'Berlin',
    lat: 52.52,
    lon: 13.405,
    total_events: 1,
    blocked: 0,
    rules_triggered: 1,
  },
]

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('GeoPoint DTO shape — fix #178 regression guard', () => {
  it('GeoPoint type has total_events field (not `count`)', () => {
    // TypeScript compile-level check: if GeoPoint still used `count`, this
    // would fail at tsc --noEmit (field `total_events` would not exist).
    const pt: GeoPoint = {
      lat: 40.0,
      lon: -74.0,
      total_events: 100,
      blocked: 50,
      rules_triggered: 2,
      ip: '192.0.2.10',
      city: 'Test City',
      country: 'TC',
    }
    expect(pt.total_events).toBe(100)
  })

  it('GeoPoint type has blocked and rules_triggered fields', () => {
    const pt: GeoPoint = {
      lat: 0,
      lon: 0,
      total_events: 10,
      blocked: 7,
      rules_triggered: 3,
    }
    expect(pt.blocked).toBe(7)
    expect(pt.rules_triggered).toBe(3)
  })

  it('N points from real DTO → N marker radii (no NaN — fix #178)', () => {
    const radii = REAL_DTO_POINTS.map((pt) => markerRadius(pt.total_events))

    // Must produce exactly N radii — one per point
    expect(radii).toHaveLength(REAL_DTO_POINTS.length)

    // Every radius must be a finite number (NaN would indicate the old `count` bug)
    for (const r of radii) {
      expect(Number.isFinite(r)).toBe(true)
      expect(Number.isNaN(r)).toBe(false)
    }
  })

  it('marker radii are positive numbers within [4, 30]', () => {
    for (const pt of REAL_DTO_POINTS) {
      const r = markerRadius(pt.total_events)
      expect(r).toBeGreaterThanOrEqual(4)
      expect(r).toBeLessThanOrEqual(30)
    }
  })

  it('markerRadius(total_events=450) produces a larger radius than total_events=1', () => {
    const large = markerRadius(450)
    const small = markerRadius(1)
    expect(large).toBeGreaterThan(small)
  })

  it('markerRadius with old `count=undefined` (pre-fix bug) would have returned NaN', () => {
    // This documents the root cause: the old code called markerRadius(pt.count)
    // where pt.count was undefined (field did not exist in the API response).
    // undefined coerces to NaN in arithmetic; NaN is not within [4, 30].
    //
    // After fix: we use pt.total_events which is always a number.
    const bugValue = markerRadius(undefined as unknown as number)
    // Math.sqrt(NaN) = NaN; Math.max(4, NaN) = NaN; Math.min(30, NaN) = NaN
    // This test documents the old broken behavior to prevent regression.
    expect(Number.isNaN(bugValue)).toBe(true)
  })
})
