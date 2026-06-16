/**
 * GeoMap — Leaflet map rendering server-side geo points (v2 kit restyle, MF-5 #162).
 *
 * Data source: GET /analytics/geo (server-side, #20).
 * SECURITY / AIR-GAP: This component makes ZERO external network requests.
 *   - Coordinates are resolved server-side (no client-side geo service calls).
 *   - Basemap is a bundled Natural Earth 1:110m world-outline GeoJSON rendered
 *     by Leaflet's L.geoJSON — no tile/CDN requests (ADR-0052, closes #528).
 *     Replaces the former CartoDB dark-matter tile layer that violated ADR-0022
 *     (local-first) and ADR-0047 (zero-egress attestation).
 *
 * V2 restyle (MF-5 #162):
 *   - Dark basemap: bundled vector world-outline styled with --fw-* tokens.
 *     Rationale: the SOC console runs in dark mode by default (ADR-0028 D6).
 *   - Marker color: --fw-accent (amber) on dark background: clearly visible,
 *     non-alarming geo marker (markers show geo presence, not severity).
 *
 * Issue #532 — honest geo provenance (EARS-1/EARS-2):
 *   - Marker styling encodes ip_class so analysts see provenance at a glance.
 *   - Datacenter / VPN-likely: hollow marker (no fill, dashed stroke weight)
 *     — signals "country is hosting location, not actor origin".
 *   - Unresolved: muted amber, 50% opacity — signals enrichment is pending.
 *   - Residential (default): solid amber fill — best-available origin signal.
 *   - Private: not plotted (no public lat/lon by definition; counted off-map).
 *
 * Leaflet is loaded via the npm package (not CDN), so its JS is bundled.
 * CSS is imported here to self-contain the component's styles.
 *
 * Each circle marker's radius scales with sqrt(total_events) to avoid extreme size variation.
 *
 * SECURITY (ADR-0029 D3): buildGeoPopup uses textContent — geo fields are
 * attacker-derived (GeoIP of ingested src_ip). No innerHTML interpolation (#74).
 */

import { useEffect, useRef } from 'react'
import type { CircleMarkerOptions, PathOptions } from 'leaflet'
import type { GeoPoint, IpClass } from '../../api/types'
import { buildGeoPopup } from './geoPopup'
// Leaflet CSS must be imported for the map to render correctly.
import 'leaflet/dist/leaflet.css'
// Bundled Natural Earth 1:110m world-outline (public-domain, ADR-0052).
// Zero runtime network requests — the basemap is part of the app bundle.
import worldOutlineRaw from '../../assets/world-outline.geojson'

// The GeoJSON import is validated by the Natural Earth source; cast once here.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const worldOutline = worldOutlineRaw as any

interface GeoMapProps {
  points: GeoPoint[]
}

const DEFAULT_CENTER: [number, number] = [20, 0]
const DEFAULT_ZOOM = 2

/** Scale marker radius: sqrt(total_events) clamped to [4, 30]. */
function markerRadius(totalEvents: number): number {
  return Math.min(30, Math.max(4, Math.sqrt(totalEvents) * 2))
}

/**
 * Resolve a CSS custom property to its computed string value.
 * Falls back to `fallback` when running outside a DOM (tests / SSR).
 * Used so Leaflet receives a concrete hex/rgb string while the source
 * of truth stays in the --fw-* token set (F5 #111: no raw hex in src).
 */
function cssToken(name: string, fallback: string): string {
  if (typeof window === 'undefined') return fallback
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback
}

/**
 * Build the Leaflet PathOptions for the world-outline base layer.
 * Reads colours from --fw-* tokens at mount time so the dark SOC theme
 * (ADR-0028) is honoured without raw hex literals in source (F5 #111).
 *
 * Land fill:   --fw-bg-card  (muted dark surface — matches the panel background).
 * Border stroke: --fw-border (subtle separator line between countries).
 */
function worldOutlineStyle(): PathOptions {
  // eslint-disable-next-line no-restricted-syntax -- fallback only used outside DOM (SSR/test); source of truth is --fw-* in index.css
  const fillColor = cssToken('--fw-bg-card', '#1e2330')
  // eslint-disable-next-line no-restricted-syntax -- fallback only used outside DOM (SSR/test); source of truth is --fw-* in index.css
  const strokeColor = cssToken('--fw-border', '#2d3347')
  return {
    fillColor,
    fillOpacity: 1,
    color: strokeColor,
    weight: 0.5,
    opacity: 1,
  }
}

/**
 * Build Leaflet CircleMarker options keyed on ip_class (EARS-2, issue #532).
 *
 * Styling intent:
 *   datacenter / vpn-likely — hollow ring (fillOpacity 0, weight 2):
 *       "country is hosting location, not actor origin"
 *   unresolved  — muted amber, low opacity (fillOpacity 0.25, weight 1):
 *       "enrichment pending or absent — treat with caution"
 *   residential — solid amber fill (fillOpacity 0.6, weight 1.5): best-available origin.
 *   private     — not plotted (no public lat/lon; counted off-map via summary chip).
 *
 * Colour source: --fw-accent (amber, canonical geo marker colour) and
 * --fw-muted (desaturated for unresolved).  No raw hex in source (F5 #111).
 */
function markerOptions(
  ipClass: IpClass | undefined,
  accentColor: string,
  mutedColor: string,
): CircleMarkerOptions {
  const cls = ipClass ?? 'unresolved'

  switch (cls) {
    case 'datacenter':
    case 'vpn-likely':
      // Hollow ring — analyst sees "this is a cloud/VPN IP" instantly.
      return {
        color: accentColor,
        fillColor: accentColor,
        fillOpacity: 0,
        weight: 2,
      }

    case 'unresolved':
      // Muted amber — enrichment is pending; treat location with caution.
      return {
        color: mutedColor,
        fillColor: mutedColor,
        fillOpacity: 0.25,
        weight: 1,
      }

    case 'residential':
    default:
      // Solid amber fill — best-available origin signal.
      return {
        color: accentColor,
        fillColor: accentColor,
        fillOpacity: 0.6,
        weight: 1.5,
      }
  }
}

export default function GeoMap({ points }: GeoMapProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const mapRef = useRef<any>(null)

  useEffect(() => {
    if (!containerRef.current) return

    // Dynamically import Leaflet to avoid SSR issues and allow proper CSS loading.
    import('leaflet').then((L) => {
      // If a map already exists, clean it up before re-initialising.
      if (mapRef.current) {
        mapRef.current.remove()
        mapRef.current = null
      }

      const map = L.map(containerRef.current!, {
        center: DEFAULT_CENTER,
        zoom: DEFAULT_ZOOM,
        scrollWheelZoom: false,
        // Natural Earth is public-domain — no attribution required (ADR-0052 §3).
        // CartoDB/OSM attribution removed along with the tile layer.
        attributionControl: false,
      })

      // Bundled Natural Earth 1:110m world-outline as the base layer (ADR-0052).
      // Replaces L.tileLayer — zero external network requests for basemap.
      L.geoJSON(worldOutline, {
        style: worldOutlineStyle(),
      }).addTo(map)

      // Resolve marker colours from DS tokens at render time — no raw hex in src (F5 #111).
      // eslint-disable-next-line no-restricted-syntax -- fallback only used outside DOM (SSR/test); source of truth is --fw-accent in index.css
      const accentColor = cssToken('--fw-accent', '#f59e0b')
      // eslint-disable-next-line no-restricted-syntax -- fallback only used outside DOM (SSR/test); source of truth is --fw-muted in index.css
      const mutedColor = cssToken('--fw-muted', '#6b7280')

      // Plot circle markers for each geo point.
      // Private IPs have no public lat/lon — they are skipped here and counted
      // off-map via the "Unresolved / private (N)" chip in AnalyticsRoute (EARS-4).
      // buildGeoPopup uses textContent — geo fields are attacker-derived (ADR-0029 D3, #74).
      for (const pt of points) {
        // Skip private IPs — no meaningful public coordinates (EARS-4: counted off-map).
        if (pt.ip_class === 'private') continue

        const radius = markerRadius(pt.total_events)
        const opts = markerOptions(pt.ip_class, accentColor, mutedColor)

        L.circleMarker([pt.lat, pt.lon], { radius, ...opts })
          .bindPopup(buildGeoPopup(pt))
          .addTo(map)
      }

      mapRef.current = map
    })

    return () => {
      if (mapRef.current) {
        mapRef.current.remove()
        mapRef.current = null
      }
    }
  }, [points])

  return (
    <div
      ref={containerRef}
      className="w-full rounded"
      style={{
        height: 380,
        borderRadius: 'var(--fw-r-sm)',
        overflow: 'hidden',
      }}
      data-testid="geo-map"
      aria-label="Threat Intelligence geo map"
    />
  )
}
