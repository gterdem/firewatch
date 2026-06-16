/**
 * buildGeoPopup — pure DOM helper for Leaflet popup content.
 *
 * SECURITY (ADR-0029 D3): geo fields (ip, city, country, as_name) are
 * attacker-derived — they are GeoIP-resolved from an ingested src_ip, not
 * operator config. Using textContent as the only sink ensures arbitrary HTML
 * in these fields is inert text and can never be parsed or executed.
 *
 * bindPopup(HTMLElement) passes the element directly to Leaflet without any
 * further string serialisation, so the safe-sink guarantee holds end-to-end.
 *
 * Extracted into its own module so it can be unit-tested without rendering
 * a full Leaflet map in jsdom.
 *
 * Issue #532 (EARS-3): adds a per-popup honesty line naming the AS and its
 * IP provenance class, e.g. "AS16509 Amazon — cloud egress; geographic origin
 * unreliable." This warns analysts before they anchor on the country label.
 */

import type { GeoPoint, IpClass } from '../../api/types'

/**
 * Human-readable honesty labels for each IP class (EARS-3).
 * Kept in this module so geoPopup.ts remains the single place describing
 * provenance semantics in the UI — no per-source code.
 */
const IP_CLASS_LABEL: Record<IpClass, string> = {
  datacenter: 'cloud egress; geographic origin unreliable',
  'vpn-likely': 'VPN / anonymiser; geographic origin unreliable',
  residential: 'residential ISP; likely actor location',
  private: 'private / non-routable; no public geo',
  unresolved: 'no ASN data; enrichment pending or absent',
}

/**
 * Build the honesty line text for a geo point.
 *
 * Examples:
 *   "AS16509 Amazon — cloud egress; geographic origin unreliable."
 *   "no ASN data; enrichment pending or absent."
 *
 * Returns null when ip_class is absent (older API responses).
 * All text is set via textContent — never innerHTML (ADR-0029 D3).
 */
export function buildHonestyLine(point: GeoPoint): string | null {
  const cls = point.ip_class ?? null
  if (!cls) return null

  const label = IP_CLASS_LABEL[cls] ?? cls

  if (point.asn != null) {
    const asnStr = `AS${point.asn}`
    const orgStr = point.as_name ? ` ${point.as_name}` : ''
    return `${asnStr}${orgStr} — ${label}.`
  }

  // No ASN integer but ip_class is still present (derived from IP range or name).
  if (point.as_name) {
    return `${point.as_name} — ${label}.`
  }

  return `${label}.`
}

/**
 * Build a popup DOM element for a geo point using textContent — never innerHTML.
 *
 * Structure:
 *   <strong>IP</strong>
 *   <br>City, Country
 *   <br>N events · N blocked
 *   <br><em>honesty line</em>  ← issue #532 EARS-3 (omitted when ip_class absent)
 */
export function buildGeoPopup(point: GeoPoint): HTMLElement {
  const label = [point.city, point.country].filter(Boolean).join(', ')

  const el = document.createElement('div')

  // IP heading
  const strong = document.createElement('strong')
  strong.textContent = String(point.ip ?? '')
  el.appendChild(strong)

  // Location
  el.appendChild(document.createElement('br'))
  el.appendChild(document.createTextNode(label))

  // Event count
  el.appendChild(document.createElement('br'))
  el.appendChild(document.createTextNode(`${Number(point.total_events)} events`))

  // EARS-3 honesty line — AS name + provenance class.
  // Rendered as an <em> node so it is visually distinct (italics) while
  // remaining a plain text node (no innerHTML, ADR-0029 D3).
  const honestyText = buildHonestyLine(point)
  if (honestyText !== null) {
    el.appendChild(document.createElement('br'))
    const em = document.createElement('em')
    em.textContent = honestyText
    el.appendChild(em)
  }

  return el
}
