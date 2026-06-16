/**
 * AnalyticsRoute — /analytics page (v2 kit restyle, MF-5 #162).
 *
 * Geo map (Leaflet, server-side /analytics/geo) + charts from
 * /analytics/summary and /analytics/categories-timeline.
 *
 * Issue #532 — Threat Intelligence reframe (EARS-7):
 *   The page headline becomes "Threat Intelligence"; geo is one lens not the
 *   whole identity. Panel title is "Geo Intelligence".
 *
 * Issue #532 — Unresolved / private chip (EARS-4/EARS-5):
 *   When summary.unresolved_private_count > 0, a chip is shown below the map
 *   honestly counting RFC-1918 / unenriched IPs that are off-map.
 *
 * Issue #532 — Honest Unknown empty state (EARS-5):
 *   When geo returns [] AND top_country === "Unknown", the empty-state sub-line
 *   explains the honest reason rather than looking like a bug.
 *
 * Issue #533 A2 — Country | ASN toggle (EARS-1):
 *   A segmented control lets the analyst switch the panel between geo dot-map
 *   (Country) and the ranked ASN list (ASN mode).
 *   ASN data is lazily fetched on first activation and cached.
 *
 * V2 restyle changes:
 *   - Sections wrapped in DS Panel (fw-panel) with titled headers.
 *   - Dark basemap via bundled world-outline (ADR-0052).
 *   - KPI tiles replaced with DS StatCard (fw-stat) in AnalyticsCharts.
 *   - Category hues applied to timeline table cells via --fw-* tokens.
 *
 * EARS:
 *   - Geo uses server-side /analytics/geo (#20) — NEVER a client-side
 *     ip-api.com / external geo call. Air-gap-safe.
 *   - Charts rendered from /analytics/summary + /analytics/categories-timeline.
 *   - #98: Loading/Error use shared state components; empty geo (0 markers)
 *     shows EmptyState rather than a blank world map frame.
 *   - #162 (MF-5): Analytics tab renders in v2 kit. geoPopup stays XSS-safe (#74).
 *   - #532: Threat Intelligence reframe + provenance chip + honest Unknown.
 *   - #533: Country|ASN toggle + AsnPanel ranked list.
 *
 * SECURITY: all data rendered as text nodes via child components.
 */

import { useState, useEffect, useRef } from 'react'
import { useRefreshSignal } from '../app/refresh/RefreshContext'
import {
  fetchGeo,
  fetchAnalyticsSummary,
  fetchCategoriesTimeline,
  fetchAsnStats,
} from '../api/analytics'
import { ApiError } from '../api/client'
import type { GeoPoint, AnalyticsSummary, CategoryTimelineBucket, AsnRow } from '../api/types'
import GeoMap from '../components/analytics/GeoMap'
import CountryAsnToggle from '../components/analytics/CountryAsnToggle'
import AsnPanel from '../components/analytics/AsnPanel'
import type { ThreatLens } from '../components/analytics/CountryAsnToggle'
import AnalyticsCharts from '../components/analytics/AnalyticsCharts'
import LoadingState from '../components/states/LoadingState'
import ErrorState from '../components/states/ErrorState'
import EmptyState from '../components/states/EmptyState'
import { Panel } from '../components/ds'

interface AnalyticsData {
  geo: GeoPoint[]
  summary: AnalyticsSummary
  timeline: CategoryTimelineBucket[]
}

/** Geo empty-state icon — 🌍 matches the "geo map" glyph from the DS iconography spec (F5 #111). */
function GeoEmptyIcon() {
  return <span style={{ fontSize: '2rem', lineHeight: 1 }}>🌍</span>
}

/**
 * Determine the honest empty-state sub-line when geo returns no plotable points.
 *
 * EARS-5: when top_country === "Unknown" this is an honest answer (all traffic
 * is RFC-1918 or not yet enriched), not a bug.  The sub-line says so plainly.
 */
function geoEmptySubLine(summary: AnalyticsSummary | null): string {
  if (summary && summary.top_country === 'Unknown') {
    const count = summary.unresolved_private_count ?? 0
    if (count > 0) {
      return `${count} IP${count === 1 ? '' : 's'} are private or not yet geo-enriched — resolved on-box from DB-IP Lite (ADR-0047).`
    }
    return 'All traffic is from private / non-routable addresses or not yet enriched — resolved on-box (ADR-0047).'
  }
  return 'Events will appear here once the source produces geo-resolvable traffic.'
}

/**
 * UnresolvedPrivateChip — honest off-map count (EARS-4, issue #532).
 *
 * RFC-1918 / unenriched IPs are counted here rather than silently dropped.
 * Absent when count is 0 or the API field is missing (older responses).
 *
 * SECURITY: count is an integer from the server; rendered as text node only.
 */
function UnresolvedPrivateChip({ count }: { count: number }) {
  if (count <= 0) return null
  return (
    <div
      data-testid="unresolved-private-chip"
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 6,
        padding: '4px 10px',
        borderRadius: 'var(--fw-r-sm)',
        background: 'var(--fw-bg-card)',
        border: '1px solid var(--fw-border)',
        fontSize: 'var(--fw-fs-xs)',
        color: 'var(--fw-t2)',
        marginTop: 8,
      }}
      aria-label={`${count} IPs not shown on map: private or unresolved`}
    >
      <span style={{ color: 'var(--fw-muted)', fontSize: '0.9em' }}>&#9679;</span>
      <span>
        Unresolved / private:{' '}
        <strong data-testid="unresolved-private-count" style={{ color: 'var(--fw-t1)' }}>
          {count}
        </strong>{' '}
        IP{count === 1 ? '' : 's'} not mapped (resolved on-box, zero-egress)
      </span>
    </div>
  )
}

export default function AnalyticsRoute() {
  const [data, setData] = useState<AnalyticsData | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // ADR-0064 D4: subscribe to the shared live-refresh signal.
  // dataVersion increments only when a real ingest delta occurs — zero new polling.
  const { dataVersion } = useRefreshSignal()

  // ASN lens state — lazy-loaded on first ASN-mode activation (EARS-1).
  const [lens, setLens] = useState<ThreatLens>('country')

  type AsnStatus =
    | { phase: 'idle' }
    | { phase: 'loading' }
    | { phase: 'done'; rows: AsnRow[] }
    | { phase: 'error'; message: string }

  const [asnStatus, setAsnStatus] = useState<AsnStatus>({ phase: 'idle' })

  useEffect(() => {
    let cancelled = false

    Promise.all([fetchGeo(), fetchAnalyticsSummary(), fetchCategoriesTimeline()])
      .then(([geo, summary, timeline]) => {
        if (!cancelled) {
          setData({ geo, summary, timeline })
          setLoading(false)
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(
            err instanceof ApiError
              ? `Analytics unavailable (${err.status})`
              : 'Failed to load analytics data',
          )
          setLoading(false)
        }
      })

    return () => {
      cancelled = true
    }
  }, [dataVersion])

  // Request-token ref: incremented each time we start a new ASN fetch.
  // The cleanup captures the token at effect-run time; if the token has advanced
  // by the time a promise resolves, the result is stale and is discarded.
  // This avoids the self-cancelling race from issue #562 where `asnStatus` in
  // the dep array caused the effect to re-run on the 'loading' state change,
  // whose cleanup set `cancelled = true` before the fetch could resolve.
  const asnTokenRef = useRef(0)

  // Tracks whether we have already initiated (or completed) an ASN fetch so we
  // don't re-fetch when the user toggles Country→ASN→Country→ASN again.
  // Using a ref (not state) keeps this value out of the dep array.
  const asnFetchInitiatedRef = useRef(false)

  // Lazy-load ASN data when the analyst first switches to ASN mode (EARS-1/EARS-2).
  // `lens` is the only dep: changing asnStatus must NOT re-trigger this effect —
  // that was the root cause of #562.  Duplicate-fetch prevention uses a ref flag
  // rather than asnStatus.phase so the dep array stays minimal.
  useEffect(() => {
    if (lens !== 'asn') return
    // Guard: skip if we already initiated a fetch for this session.
    if (asnFetchInitiatedRef.current) return

    asnFetchInitiatedRef.current = true

    // Mint a new token for this fetch.  The cleanup increments the counter to
    // invalidate this request if the user leaves ASN mode before it resolves.
    const token = ++asnTokenRef.current

    // Set loading synchronously in the effect body (not inside a promise
    // callback).  Because `asnStatus` is NOT in the dep array, this setState
    // call does not re-run the effect — fixing the #562 self-cancelling race.
    setAsnStatus({ phase: 'loading' })

    // Capture the ref object itself (not .current) so cleanup can safely
    // mutate it. This avoids the react-hooks/exhaustive-deps warning that
    // fires when a cleanup reads `.current` directly.
    const tokenRef = asnTokenRef

    fetchAsnStats(15)
      .then((rows) => {
        if (tokenRef.current === token) {
          setAsnStatus({ phase: 'done', rows })
        }
      })
      .catch((err: unknown) => {
        if (tokenRef.current === token) {
          setAsnStatus({
            phase: 'error',
            message:
              err instanceof ApiError
                ? `ASN data unavailable (${err.status})`
                : 'Failed to load ASN data',
          })
        }
      })

    return () => {
      // Invalidate the live token so any in-flight request is discarded if the
      // user leaves ASN mode before the fetch resolves. We read from the local
      // `tokenRef` alias (same object as asnTokenRef) to satisfy the lint rule.
      tokenRef.current++
    }
  }, [lens])

  if (loading) {
    return (
      <main className="container mx-auto px-4 py-8 max-w-5xl" data-testid="analytics-loading">
        <LoadingState label="Loading analytics…" />
      </main>
    )
  }

  if (error !== null) {
    return (
      <main className="container mx-auto px-4 py-8 max-w-5xl" data-testid="analytics-error">
        <ErrorState
          headline={error}
          subLine="Check that the FireWatch API is reachable and retry."
        />
      </main>
    )
  }

  if (data === null) return null

  const geoIsEmpty = data.geo.length === 0
  const unresolvedCount = data.summary.unresolved_private_count ?? 0

  return (
    <main
      className="container mx-auto px-4 py-8 max-w-5xl"
      style={{ display: 'flex', flexDirection: 'column', gap: 24 }}
    >
      {/* EARS-7: page reframe — headline is now "Threat Intelligence".
          Geo becomes one lens not the page's whole identity. */}
      <div>
        <h1
          style={{
            fontSize: 'var(--fw-fs-h1)',
            fontWeight: 'var(--fw-fw-bold)',
            color: 'var(--fw-t1)',
            fontFamily: 'var(--fw-font-ui)',
            margin: 0,
          }}
          data-testid="analytics-page-title"
        >
          Threat Intelligence
        </h1>
        <p
          style={{
            fontSize: 'var(--fw-fs-sm)',
            color: 'var(--fw-t2)',
            marginTop: 4,
            marginBottom: 0,
          }}
          data-testid="analytics-page-subtitle"
        >
          Geo provenance, event patterns, and attack categories.
        </p>
      </div>

      {/* Geographic Distribution / ASN panel — Country|ASN toggle (EARS-1 issue #533).
          Panel stays present in both modes.  Dark basemap via bundled world-outline (ADR-0052).
          Marker styling encodes ip_class (issue #532 EARS-2). */}
      <Panel
        title="Geographic Distribution"
        icon="🌍"
        aria-label="Geographic distribution"
      >
        {/* EARS-1: segmented toggle Country | ASN */}
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: 12 }}>
          <CountryAsnToggle value={lens} onChange={setLens} />
        </div>

        {lens === 'country' ? (
          <>
            {geoIsEmpty ? (
              // Compact empty-state: drop the min-h-[380px] that matched map height
              // and left ~200–380px of dead space when empty (issue #577).
              // The EmptyState's own padding (50px 30px) is already generous; forcing
              // the map's 380px height onto the empty state is wasted real-estate.
              <EmptyState
                icon={<GeoEmptyIcon />}
                headline="No geo-resolvable traffic yet"
                subLine={geoEmptySubLine(data.summary)}
              />
            ) : (
              <GeoMap points={data.geo} />
            )}

            {/* EARS-4: honest off-map count — RFC-1918 / unenriched IPs are never
                silently dropped; this chip makes them visible on both map and
                empty-state paths so the count is always honest. */}
            <UnresolvedPrivateChip count={unresolvedCount} />
          </>
        ) : (
          /* EARS-2: ASN mode — ranked list beside (below on narrow) the map area.
             #578: minHeight:380 during loading matches the GeoMap panel height so
             switching Country→ASN doesn't collapse the geo panel to ~80px then
             jump back once the ASN list renders (layout reservation). */
          <div style={{ minHeight: asnStatus.phase === 'loading' ? 380 : 0 }}>
            <AsnPanel
              rows={asnStatus.phase === 'done' ? asnStatus.rows : []}
              loading={asnStatus.phase === 'loading'}
              error={asnStatus.phase === 'error' ? asnStatus.message : null}
              aiAvailable={true}
            />
          </div>
        )}
      </Panel>

      {/* Charts — summary StatCards + category timeline with hues */}
      <Panel
        title="Event Analytics"
        icon="📊"
        aria-label="Analytics charts"
      >
        <AnalyticsCharts summary={data.summary} timeline={data.timeline} />
      </Panel>
    </main>
  )
}
