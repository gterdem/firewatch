/**
 * Tests for src/components/analytics/geoPopup.ts — buildGeoPopup helper.
 *
 * EARS criteria covered:
 *   - WHEN /analytics/geo returns N geolocated IPs, THEN the popup SHALL display
 *     total_events (not `count` — fix #178: API uses `total_events`).
 *   - SECURITY (ADR-0029 D3): geo fields (ip, city, country) are attacker-derived
 *     (GeoIP of ingested src_ip). buildGeoPopup must render them as inert text via
 *     textContent — HTML/script payloads must never become live DOM nodes.
 *   - Functional: popup element contains the ip, label, and event count as text.
 *   - Functional: missing ip/city/country are handled gracefully (no crash).
 *
 * Fixture shape uses the REAL DTO from GET /analytics/geo (fix #178):
 *   { ip, country, city, lat, lon, total_events, blocked, rules_triggered }
 */

import { describe, it, expect } from 'vitest'
import { buildGeoPopup } from '../components/analytics/geoPopup'

// Minimal valid GeoPoint fixture matching the real API DTO shape (fix #178).
function geoPoint(overrides: Partial<Parameters<typeof buildGeoPopup>[0]> = {}) {
  return {
    lat: 0,
    lon: 0,
    total_events: 1,
    blocked: 0,
    rules_triggered: 0,
    ip: '198.51.100.1',
    city: undefined,
    country: undefined,
    ...overrides,
  }
}

describe('buildGeoPopup', () => {
  it('renders ip as text in a strong element', () => {
    const el = buildGeoPopup(geoPoint({ lat: 51.5, lon: -0.1, total_events: 5, ip: '203.0.113.1', city: 'London', country: 'GB' }))
    const strong = el.querySelector('strong')
    expect(strong).not.toBeNull()
    expect(strong!.textContent).toBe('203.0.113.1')
  })

  it('renders city and country as text', () => {
    const el = buildGeoPopup(geoPoint({ lat: 51.5, lon: -0.1, total_events: 3, ip: '203.0.113.2', city: 'Berlin', country: 'DE' }))
    expect(el.textContent).toContain('Berlin, DE')
  })

  it('renders total_events as event count in popup text (fix #178 — was NaN when field was `count`)', () => {
    const el = buildGeoPopup(geoPoint({ total_events: 42, ip: '198.51.100.1' }))
    expect(el.textContent).toContain('42 events')
  })

  it('handles missing ip gracefully', () => {
    const el = buildGeoPopup(geoPoint({ ip: null }))
    const strong = el.querySelector('strong')
    expect(strong!.textContent).toBe('')
  })

  it('handles missing city and country gracefully', () => {
    const el = buildGeoPopup(geoPoint({ total_events: 1, ip: '198.51.100.5' }))
    // No crash; event count still present
    expect(el.textContent).toContain('1 events')
  })

  describe('XSS safety — attacker-derived geo fields (ADR-0029 D3)', () => {
    it('script payload in ip is inert text — no live <script> node', () => {
      const xssIp = "<script>alert('xss')</script>"
      const el = buildGeoPopup(geoPoint({ total_events: 1, ip: xssIp }))

      // The literal payload must appear as text content
      expect(el.textContent).toContain(xssIp)

      // No <script> element must be present in the popup DOM
      expect(el.querySelector('script')).toBeNull()
    })

    it('img onerror payload in city is inert text — no live <img> node', () => {
      const xssCity = '"><img src=x onerror=alert(1)>'
      const el = buildGeoPopup(geoPoint({ total_events: 1, ip: '198.51.100.7', city: xssCity }))

      // The literal payload must appear as text content
      expect(el.textContent).toContain(xssCity)

      // No <img> element with onerror must exist
      expect(el.querySelector('img')).toBeNull()
    })

    it('script payload in country is inert text', () => {
      const xssCountry = "<script>alert('xss')</script>"
      const el = buildGeoPopup(geoPoint({ total_events: 1, ip: '198.51.100.8', country: xssCountry }))

      expect(el.textContent).toContain(xssCountry)
      expect(el.querySelector('script')).toBeNull()
    })

    it('combined XSS payloads — no script or img injected', () => {
      const xssIp = "<script>alert('xss')</script>"
      const xssCity = '"><img src=x onerror=alert(1)>'
      const el = buildGeoPopup(geoPoint({ total_events: 99, ip: xssIp, city: xssCity }))

      // Both payloads appear as inert literal text
      expect(el.textContent).toContain(xssIp)
      expect(el.textContent).toContain(xssCity)

      // No live script or img elements injected
      expect(el.querySelector('script')).toBeNull()
      expect(el.querySelector('img')).toBeNull()
    })
  })
})
