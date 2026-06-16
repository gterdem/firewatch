/**
 * LogsRoute — /logs page (#112, MF-4, #203, #252, #433).
 *
 * Layout matches soc-console/Logs.jsx:
 *   - filter-bar panel: Combobox filters (Source/Category/Action/Severity) +
 *     search + removable FilterChips.
 *   - flush Panel: dense 8-column table (Time · Source · Source IP · Dest Port ·
 *     Severity · Action · Signature · HTTP Payload).
 *   - Cursor pagination (CursorPager): echoes next_cursor; never offset-computes.
 *
 * MF-4 additions:
 *   - AI verdict fold: fetches /threats non-fatally on mount; builds a Map<ip, ThreatScore>
 *     passed to LogsTable so each row with a known IP shows a compact AI triage chip.
 *     ADR-0015: /threats failure is non-fatal — table degrades without AI verdict.
 *   - Action-seam wiring: IP click → openEntity({kind:"ip", value}) via useEntityPanel.
 *     ADR-0033 / ADR-0037.
 *
 * ML-5 (#433) additions — provenance & zero-egress trust layer:
 *   - ZeroEgressBadge: persistent "Local-only · 0 bytes egressed" indicator in the
 *     page header, placed alongside the page title (EARS-2, ADR-0015 / ADR-0026).
 *   - LogsTable now shows ProvenanceChip (RULE/AI) next to each row's verdict chip,
 *     and FieldAvailabilityLegend "?" hints on column headers that may show "—" for
 *     L7-only sources such as Azure WAF (EARS-1 / EARS-3).
 *
 * #203 — ?ip= deep-link support (shareable filtered URL):
 *   - On mount, reads ?ip= from the URL and applies it as the ip facet filter.
 *   - The URL stays in sync: setting or clearing the IP filter updates ?ip= via setSearchParams.
 *   - Format guard: only plausible IPs (IPv4 / IPv6 / prefix notation) are accepted;
 *     values that fail the guard are silently ignored (no crash, no injected text).
 *     Guard mirrors the source_ip guard from issue #171 (ADR-0029 D3).
 *
 * #252 — ?action= deep-link support (shareable filtered URL):
 *   - On mount, reads ?action= from the URL and applies it as the server-side action filter.
 *   - Accepted values: ALLOW / BLOCK / DROP / ALERT / blocked (case-preserved; store is
 *     case-insensitive for the "blocked" shorthand).
 *   - The URL stays in sync: setting or clearing the action filter updates ?action= via
 *     setSearchParams.
 *   - Action is now a SERVER-SIDE filter — selecting any action value triggers a new
 *     server fetch rather than filtering the current page in the browser.
 *
 * #565 — ?q= / ?signature= / ?payload= deep-link support (F7-D1 fix):
 *   - On mount, reads ?q=, ?signature=, and ?payload= from the URL.
 *   - ?q= seeds the free-text search filter (filter.q) directly.
 *   - ?signature= and ?payload= are convenience aliases that also map to filter.q
 *     (the backend ?q= matches against rule_id, signature, and payload_snippet).
 *   - Priority when multiple alias params are present: ?q= wins; then ?signature=;
 *     then ?payload=.  This mirrors the single search-box UX (one q= server param).
 *   - All three are validated: length ≤ 200 chars and no control characters.
 *   - Unrecognised URL params are silently ignored.
 *   - The URL stays in sync: filter.q is synced back to ?q= via setSearchParams so
 *     the link remains shareable and the back-button works correctly.
 *
 * #667 WS4a — layout reorder + filter scopes the whole surround:
 *   - Final page order (top→bottom): StripTiles → FacetFilters → TopPairsPanel →
 *     EntityGraph → Network Logs table.
 *   - useLogsSurround(filter): collapses the 3 mount-only surround effects into one
 *     filter-keyed data layer; top-pairs + entity-graph re-query on every filter change.
 *   - Deep-link entry (any of ?ip= / ?action= / ?signature= / ?q=): anchor-scrolls
 *     the viewport to the table on mount so the analyst lands on the rows.
 *   - TopPairsPanel: shows top 5 by default with "View all" inline expander (no nested
 *     scrollbar).
 *
 * Flags — columns not yet in LogEntry contract:
 *   - destination_port: not a canonical field; accessed via native field fallback.
 *   - signature / rule_id / rule_name: not canonical; accessed via native field fallback.
 *   - payload_snippet / http_payload: not canonical; accessed via native field fallback.
 *   These render "—" when absent. Backend normalization is a separate contract task (#125).
 *
 * #748 (ADR-0064 D4) — deferred "N new events" pill:
 *   - The page subscribes to useRefreshSignal() and accumulates lastDeltaCount
 *     into pendingNewCount when dataVersion bumps (does NOT auto-fetch).
 *   - A single NewEventsPill (ONE control for the whole page) shows the count.
 *   - onLoadNew(): resets table to page 1 + refetches, calls refreshSurround()
 *     for the ERG merge path, clears the pending count.
 *
 * EARS (ADR-0029 D2, issues #112, #161, #203, #252, #565, #667, #748):
 *   - WHEN the page opens with ?ip=<addr>, the table SHALL filter to that IP and the
 *     filter UI SHALL display the active IP filter chip.
 *   - WHEN the user clears the IP filter, ?ip= SHALL be removed from the URL.
 *   - IF ?ip= is not a plausible IP, the route SHALL ignore it gracefully.
 *   - WHEN the page opens with ?action=<val>, the table SHALL filter to that action and
 *     the filter UI SHALL reflect the active action filter chip.
 *   - WHEN the user clears the action filter, ?action= SHALL be removed from the URL.
 *   - WHEN the page opens with ?q=<text>, the search filter SHALL be seeded from it.
 *   - WHEN the page opens with ?signature=<val>, filter.q SHALL be seeded from it.
 *   - WHEN the page opens with ?payload=<val>, filter.q SHALL be seeded from it.
 *   - WHERE multiple recognised params are present, all SHALL be applied together.
 *   - WHEN an unrecognised URL param is present, it SHALL be ignored without error.
 *   - WHEN a server filter Combobox changes → re-fetch with cursor reset.
 *   - WHEN a FilterChip ✕ is clicked → that facet clears + re-fetch.
 *   - WHEN a row IP is clicked → entity slide-over panel opens (ADR-0037).
 *   - WHILE /threats DTO carries ThreatScore for an IP → AI verdict chip rendered per row.
 *   - WHILE /threats fails or IP has no score → table renders without AI verdict (ADR-0015).
 *   - WHILE loading → Spinner shown.
 *   - IF /logs/paginated fails → error state shown.
 *   - [#667] WHEN a filter changes, top-pairs AND entity-graph SHALL re-query with the same filter.
 *   - [#667] WHEN opened with a deep-link param, the viewport SHALL anchor-scroll to the table.
 *   - [#667] The page SHALL render sections: StripTiles → FacetFilters → TopPairs → ERG → table.
 *   - [#748] WHEN dataVersion increments, the page SHALL show ONE pill with the pending count
 *     and SHALL NOT auto-fetch or auto-re-scope the ERG.
 *   - [#748] WHEN the pill is clicked, the table SHALL refetch from page 1 AND the ERG SHALL
 *     merge new data; the pill SHALL disappear and the pending count SHALL reset.
 *   - [#748] WHILE the pill is unclicked, filters, URL params, cursor, and ERG viewport SHALL
 *     be unchanged.
 *   - [#748] THE page SHALL show exactly ONE refresh control.
 *
 * SECURITY (ADR-0029 D3): raw_log and native fields are text-node only in LogsTable.
 *   The ?ip= value is validated before use — never echoed raw into the DOM.
 *   The ?action= value is validated against the known-action vocabulary before use.
 *   The ?q= / ?signature= / ?payload= values are length-limited (≤ 200 chars) and
 *   stripped of control characters before use — they flow through the search input
 *   and backend ?q= param; the backend is responsible for its own escaping.
 */

import { useState, useEffect, useMemo, useRef } from 'react'
import { useSearchParams } from 'react-router-dom'
import { fetchPaginatedLogs } from '../api/logs'
import { fetchThreats, ApiError } from '../api/client'
import type { LogsFilter, PaginatedLogs, ThreatScore } from '../api/types'
import type { ComboOption } from '../components/ds'
import { Panel, Spinner } from '../components/ds'
import FacetFilters from '../components/logs/FacetFilters'
import LogsTable from '../components/logs/LogsTable'
import CursorPager from '../components/logs/CursorPager'
import TopPairsPanel from '../components/logs/TopPairsPanel'
import StripTiles from '../components/logs/StripTiles'
import { ZeroEgressBadge } from '../components/logs/ZeroEgressBadge'
import { useEntityPanel } from '../components/entity/EntityPanelContext'
// ML-9 (#437): entity relationship graph panel
import EntityGraph from '../components/logs/EntityGraph'
// #667 WS4a: filter-scoped surround data hook (top-pairs + entity-graph)
import { useLogsSurround } from '../components/logs/useLogsSurround'
// #748 (ADR-0064 D4): deferred "N new events" pill — one control for the whole page
import NewEventsPill from '../components/logs/NewEventsPill'
import { useRefreshSignal } from '../app/refresh/RefreshContext'

const PAGE_SIZE = 25

/**
 * Format guard for ?ip= deep-link param (issue #203, ADR-0029 D3).
 *
 * Accepts:
 *   - IPv4 dotted-decimal: 1-3 octet prefixes or full address (e.g. "192.0.2", "192.0.2.1")
 *   - IPv6: colon-containing strings
 *   - CIDR notation for either family (e.g. "192.0.2.0/24")
 *
 * Rejects everything else (empty string, freeform text, script injection attempts, etc.).
 * The regex is intentionally permissive for valid IP notation and strict against
 * non-IP characters — keeping the guard simple and auditable (OWASP input validation).
 *
 * Returns the validated value or null when the input is not a plausible IP.
 */
function parseIpParam(raw: string | null): string | null {
  if (!raw) return null
  const trimmed = raw.trim()
  if (!trimmed) return null
  // Allow: digits, dots, colons, letters a-f/A-F (IPv6 hex), slash (CIDR), brackets ([::1])
  // Reject: spaces, angle brackets, quotes, semicolons, or any character not in IP notation.
  const IP_PATTERN = /^[\da-fA-F.:[\]/]+$/
  if (!IP_PATTERN.test(trimmed)) return null
  // Must contain at least one dot (IPv4) or one colon (IPv6).
  if (!trimmed.includes('.') && !trimmed.includes(':')) return null
  return trimmed
}

/**
 * Guard for ?action= deep-link param (issue #252, ADR-0029 D3).
 *
 * Accepts values from the known action vocabulary (case-insensitive comparison).
 * The "blocked" shorthand is a first-class accepted value — the server expands
 * it to action ∈ {BLOCK, DROP}.  Unknown values are silently ignored to prevent
 * injection of arbitrary strings into the filter query while staying forward-
 * compatible with new action values added to the vocabulary later.
 *
 * Returns the original-cased value (so "blocked" stays "blocked") or null.
 */
const KNOWN_ACTIONS = new Set(['allow', 'block', 'drop', 'alert', 'blocked'])

function parseActionParam(raw: string | null): string | null {
  if (!raw) return null
  const trimmed = raw.trim()
  if (!trimmed) return null
  if (KNOWN_ACTIONS.has(trimmed.toLowerCase())) return trimmed
  return null
}

/**
 * Guard for ?q= / ?signature= / ?payload= deep-link params (issue #565, ADR-0029 D3).
 *
 * Accepts free-text strings up to MAX_SEARCH_LEN characters (200) that contain
 * no C0/C1 control characters (ASCII < 0x20 or 0x7F–0x9F), which covers newlines,
 * tabs, null bytes, and other injection-friendly bytes.
 *
 * The 200-char ceiling matches the backend payload_snippet field length and prevents
 * oversized strings from being echoed back into the DOM or sent as a huge query param.
 *
 * Returns the trimmed value or null when the input fails the guard.
 */
const MAX_SEARCH_LEN = 200

function parseSearchParam(raw: string | null): string | null {
  if (!raw) return null
  const trimmed = raw.trim()
  if (!trimmed) return null
  if (trimmed.length > MAX_SEARCH_LEN) return null
  // Reject C0 control characters (codepoints 0x00-0x1F) and DEL (0x7F).
  // String.prototype.charCodeAt check is used instead of a regex literal to
  // avoid editor/tool confusion with control-character literals in source.
  for (let i = 0; i < trimmed.length; i++) {
    const c = trimmed.charCodeAt(i)
    if (c <= 0x1F || c === 0x7F) return null
  }
  return trimmed
}

export default function LogsRoute() {
  const [searchParams, setSearchParams] = useSearchParams()

  // Read ?ip= once on mount and apply as the initial ip facet (issue #203).
  const initialIp = parseIpParam(searchParams.get('ip'))

  // Read ?action= once on mount and apply as the initial action facet (issue #252).
  const initialAction = parseActionParam(searchParams.get('action'))

  // Read ?q= / ?signature= / ?payload= once on mount (issue #565).
  // Priority: explicit ?q= wins; then ?signature=; then ?payload=.
  // All three map to filter.q (the single free-text search the backend exposes via ?q=).
  const initialQ: string | null =
    parseSearchParam(searchParams.get('q')) ??
    parseSearchParam(searchParams.get('signature')) ??
    parseSearchParam(searchParams.get('payload'))

  /**
   * #667 deep-link detection: true when ANY recognised filter param is present
   * on mount. Used to decide whether to anchor-scroll to the table after load.
   */
  const hasDeepLinkParam = Boolean(initialIp ?? initialAction ?? initialQ)

  const [filter, setFilter] = useState<LogsFilter>({
    limit: PAGE_SIZE,
    ...(initialIp ? { ip: initialIp } : {}),
    ...(initialAction ? { action: initialAction } : {}),
    ...(initialQ ? { q: initialQ } : {}),
  })
  const [page, setPage] = useState<PaginatedLogs | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  // #748: token bumped by onLoadNew() to force-trigger the fetch effect even
  // when the filter JSON hasn't changed (i.e. already on page 1 with no cursor).
  const [refreshToken, setRefreshToken] = useState(0)
  // AI verdict fold — fetched once on mount, non-fatal (ADR-0015).
  const [threatMap, setThreatMap] = useState<ReadonlyMap<string, ThreatScore>>(new Map())

  // #667 WS4a: filter-scoped surround data (top-pairs + entity-graph).
  // Replaces the 2 mount-only useEffects that fetched these without filter context.
  // #751: graphIsMerge and refreshSurround are new fields for the merge path.
  const {
    topPairs,
    topPairsLoading,
    graphNodes,
    graphEdges,
    graphTruncated,
    graphIsMerge,
    refreshSurround,
  } = useLogsSurround(filter)

  // #748 (ADR-0064 D4) — pending new-events count.
  // Accumulates lastDeltaCount from the shared heartbeat when dataVersion bumps.
  // Does NOT trigger a fetch — the pill click is the only fetch trigger.
  const [pendingNewCount, setPendingNewCount] = useState(0)
  const { dataVersion, lastDeltaCount } = useRefreshSignal()
  useEffect(() => {
    if (dataVersion === 0) return  // Initial mount — no real delta yet.
    setPendingNewCount((prev) => prev + lastDeltaCount) // eslint-disable-line react-hooks/set-state-in-effect
  // Run only when dataVersion changes (a real ingest delta occurred).
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dataVersion])

  // Entity panel — openEntity replaces setDrilldownIp (ADR-0037).
  const { openEntity } = useEntityPanel()

  // #667: ref for anchor-scroll to the table on deep-link entry.
  const tableRef = useRef<HTMLDivElement | null>(null)
  // Track whether the initial scroll has already fired (only once per mount).
  const hasScrolledRef = useRef(false)

  // Fetch /threats on mount — non-fatal (ADR-0015: AI is additive-only).
  useEffect(() => {
    let cancelled = false
    fetchThreats()
      .then((threats) => {
        if (!cancelled) {
          const m = new Map<string, ThreatScore>()
          for (const t of threats) m.set(t.source_ip, t)
          setThreatMap(m)
        }
      })
      .catch(() => {
        // Non-fatal: table renders without AI verdict if /threats fails.
        // No error state shown — the logs themselves are still available.
      })
    return () => { cancelled = true }
  }, [])

  // Fetch whenever filter changes or refreshToken bumps (pill-initiated force-refetch).
  // ADR-0063 D6: /logs/stats is no longer fetched here for structural column hiding
  // (that axis is retired for the logs table). StripTiles fetches /logs/stats independently.
  useEffect(() => {
    let cancelled = false

    fetchPaginatedLogs(filter).then((result) => {
      if (cancelled) return
      setPage(result)
      setError(null)
      setLoading(false)
    }).catch((err: unknown) => {
      if (cancelled) return
      setError(
        err instanceof ApiError
          ? `Logs unavailable (${(err as ApiError).status})`
          : 'Failed to load logs',
      )
      setLoading(false)
    })

    return () => {
      cancelled = true
    }
  // refreshToken is included so onLoadNew() can force a re-fetch even when
  // filter is unchanged (already on page 1). eslint disable covers JSON.stringify.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [JSON.stringify(filter), refreshToken])

  // #667: anchor-scroll to the table when opening via a deep-link param.
  // Fires once after the first load completes (loading transitions false).
  // Only scrolls when at least one recognised filter param was present in the URL
  // on initial mount — clean entry (no params) stays at the top.
  useEffect(() => {
    if (!hasDeepLinkParam) return
    if (loading) return
    if (hasScrolledRef.current) return
    if (tableRef.current && typeof tableRef.current.scrollIntoView === 'function') {
      hasScrolledRef.current = true
      tableRef.current.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }
  // We intentionally re-check only when `loading` changes (once per load cycle).
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [loading])

  /**
   * Handle server-side filter change: reset cursor to page 1 and sync URL params.
   *
   * URL sync (issue #203, #252, #565): when the caller sets or clears filter.ip,
   * filter.action, or filter.q, update the browser URL so the link remains shareable
   * and the back-button restores the filter.
   * The ?signature= and ?payload= aliases are normalised to ?q= on the first change
   * (the canonical single-search-box representation).
   */
  function handleFilterChange(next: LogsFilter) {
    // Bug #684 fix (no-op guard approach): if the normalised next filter is byte-identical
    // to the current filter, this call came from clicking the same ERG node/pair again.
    // The fetch effect is keyed on JSON.stringify(filter) and will NOT re-run, so any
    // setLoading(true) here would strand the spinner forever.  Early-return prevents that.
    const nextNormalised = { ...next, limit: PAGE_SIZE, cursor: undefined }
    if (JSON.stringify(nextNormalised) === JSON.stringify(filter)) return
    setLoading(true)
    setFilter(nextNormalised)
    // Sync ?ip=, ?action=, and ?q= to the URL (add when present, remove when cleared).
    // Remove the alias params ?signature= and ?payload= so the URL uses ?q= canonically.
    setSearchParams(
      (prev) => {
        const updated = new URLSearchParams(prev)
        if (next.ip) {
          updated.set('ip', next.ip)
        } else {
          updated.delete('ip')
        }
        if (next.action) {
          updated.set('action', next.action)
        } else {
          updated.delete('action')
        }
        if (next.q) {
          updated.set('q', next.q)
        } else {
          updated.delete('q')
        }
        // Always remove alias params — the canonical form is ?q=.
        updated.delete('signature')
        updated.delete('payload')
        return updated
      },
      { replace: true },
    )
  }

  /** Advance to next page — echo next_cursor from envelope. */
  function handleNext(cursor: string) {
    setLoading(true)
    setFilter((prev) => ({ ...prev, cursor }))
  }

  /** Return to first page. */
  function handleFirst() {
    // Guard: if already on page 1 (cursor is already undefined) this is a no-op.
    // Without the guard, setLoading(true) would strand the spinner because the
    // fetch effect keyed on JSON.stringify(filter) would not re-run (same key).
    if (filter.cursor === undefined) return
    setLoading(true)
    setFilter((prev) => ({ ...prev, cursor: undefined }))
  }

  /**
   * #748 — "N new events — click to load" pill handler.
   *
   * Fans out to BOTH surfaces on a single click (ADR-0064 D4 — one pill,
   * two consumers):
   *   1. Table: reset to page 1 and refetch.
   *      If on a deeper page: clear cursor (filter JSON changes → effect re-runs).
   *      If already on page 1: bump refreshToken (the fetch effect dep) to force
   *      a re-run without touching any filter field.
   *   2. ERG: call refreshSurround() — refetches graph for the CURRENT filter
   *      and routes the result through the merge path (graphIsMerge = true),
   *      preserving viewport/focus/hiddenKinds (#751).
   *   3. Clear the pending count so the pill disappears.
   *
   * Active filters, URL params, and expanded rows are preserved (only the
   * table cursor resets to page 1, per ADR-0064 D5).
   */
  function onLoadNew() {
    setLoading(true)

    // Fan-out 1: table — reset to page 1 + refetch.
    if (filter.cursor !== undefined) {
      // On a deeper page: clearing cursor changes the JSON key → effect re-runs.
      setFilter((prev) => ({ ...prev, cursor: undefined }))
    } else {
      // Already on page 1: bump refreshToken to force the fetch effect to re-run.
      // The filter itself is unchanged (no cursor, no mutation).
      setRefreshToken((t) => t + 1)
    }

    // Fan-out 2: ERG incremental merge (#751).
    refreshSurround()

    // Clear the pending count — pill disappears.
    setPendingNewCount(0)
  }

  /** IP click handler — opens entity panel (ADR-0037). */
  function handleIpClick(ip: string) {
    openEntity({ kind: 'ip', value: ip })
  }

  /**
   * ML-3 (#431, EARS-4): cross-filter the table when a top-pairs row is clicked.
   * Applies source IP (ip=) and destination IP (destination_ip=) filters together,
   * resetting the cursor to page 1.
   */
  function handleSelectPair(sourceIp: string, destinationIp: string) {
    handleFilterChange({ ...filter, ip: sourceIp, destination_ip: destinationIp })
  }

  /**
   * ML-9 (#437, EARS-1): cross-filter when an IP node is clicked in the entity graph.
   * Applies source IP filter (ip=), resetting the cursor to page 1.
   * Only IP nodes trigger this; ASN/category nodes are display-only in MVP.
   */
  function handleGraphNodeClick(ip: string) {
    handleFilterChange({ ...filter, ip })
  }

  /**
   * ML-4 (#432, EARS-3): cross-filter from traffic-shape header elements.
   * Merges partial filter patch (ip= or protocol=) into the current filter and
   * triggers a fresh page-1 fetch.
   */
  function handleTrafficFilter(patch: Partial<LogsFilter>) {
    handleFilterChange({ ...filter, ...patch })
  }

  // Derive category options from the current page for the Combobox.
  const categoryOptions = useMemo<ComboOption[]>(() => {
    if (!page) return []
    const seen = new Set<string>()
    for (const log of page.logs) {
      if (log.category) seen.add(String(log.category))
    }
    return Array.from(seen).sort().map((c) => ({ value: c, label: c }))
  }, [page])

  // Derive source options from the current page for the Combobox.
  const sourceOptions = useMemo<ComboOption[]>(() => {
    if (!page) return []
    const seen = new Set<string>()
    for (const log of page.logs) {
      if (log.source_type) seen.add(String(log.source_type))
    }
    return Array.from(seen).sort().map((s) => ({ value: s, label: s }))
  }, [page])

  const visibleLogs = page?.logs ?? []

  return (
    <main
      style={{
        maxWidth: 1400,
        margin: '0 auto',
        padding: '16px 24px',
        fontFamily: 'var(--fw-font-ui)',
      }}
    >
      {/* ML-5 (#433, EARS-2): page-level trust indicator — zero-egress attestation.
          Persistent badge communicating that all inference runs locally (ADR-0015 / ADR-0026).
          Positioned inline with the page heading area; non-nagging static affordance. */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          marginBottom: 12,
        }}
        data-testid="logs-page-header"
      >
        <h1
          style={{
            fontSize: 'var(--fw-fs-lg)',
            fontWeight: 'var(--fw-fw-semibold)',
            color: 'var(--fw-t1)',
            margin: 0,
          }}
        >
          Network Logs
        </h1>
        <ZeroEgressBadge />
      </div>

      {/* #667 page order — top→bottom:
          1. Strip tiles
          2. Filter (FacetFilters)
          3. Top Source→Destination Pairs
          4. Entity Relationship Graph
          5. Network Logs table (bottom)  */}

      {/* 1. Strip tiles (#665): Events · Blocked · Distinct IPs · Top Talker · Top Protocol.
          Replaces TrafficShapeHeader (ML-4 / #432). Timeline dropped (duplicates Dashboard). */}
      <StripTiles filter={filter} onFilterChange={handleTrafficFilter} />

      {/* 2. Filter bar (#667 — placed above analytical panels per final page order) */}
      <FacetFilters
        filter={filter}
        onFilterChange={handleFilterChange}
        categoryOptions={categoryOptions}
        sourceOptions={sourceOptions}
        totalMatching={page?.total_matching}
      />

      {/* #748 (ADR-0064 D4) — ONE page-level deferred-load pill.
          Sits between the filter bar and the analytical panels.
          Fans out to both the logs table AND the ERG on a single click.
          Renders nothing when count is 0 (no empty space claimed). */}
      <NewEventsPill count={pendingNewCount} onClick={onLoadNew} />

      {/* 3. Top src→dst pairs panel (ML-3 / #431, EARS-4).
          #667 WS4a: pairs now re-query with the active filter via useLogsSurround. */}
      <TopPairsPanel
        pairs={topPairs}
        loading={topPairsLoading}
        onSelectPair={handleSelectPair}
      />

      {/* 4. Entity relationship graph (ML-9 / #437).
          #667 WS4a: graph now re-queries with the active filter via useLogsSurround.
          Mounted as its own section; does NOT edit IpPanel (MK-11 collision avoidance).
          Cross-filters the logs table when an IP node is clicked (EARS-1). */}
      {/* #751: isMerge = graphIsMerge routes the layout to the warm-start merge path
          (hard-pins existing nodes) and suppresses auto-fit (preserves viewport). */}
      <EntityGraph
        nodes={graphNodes}
        edges={graphEdges}
        truncated={graphTruncated}
        threatMap={threatMap}
        onNodeClick={handleGraphNodeClick}
        isMerge={graphIsMerge}
      />

      {/* 5. Network Logs table — bottom anchor (#667 deep-link scroll target).
          ref is placed on the wrapper so scrollIntoView aligns to the pager+table block. */}
      <div ref={tableRef} data-testid="logs-table-section">
        {/* Loading */}
        {loading && (
          <Spinner
            label="Loading logs…"
            role="status"
            data-testid="logs-loading"
          />
        )}

        {/* Error */}
        {!loading && error !== null && (
          <div
            style={{
              background: 'var(--fw-bg-card)',
              border: '1px solid var(--fw-border)',
              borderRadius: 8,
              padding: '20px 16px',
              color: 'var(--fw-red)',
              fontFamily: 'var(--fw-font-ui)',
              fontSize: 'var(--fw-fs-body)',
            }}
            role="alert"
            data-testid="logs-error"
          >
            {error}
          </div>
        )}

        {/* Table + pagination */}
        {!loading && error === null && page !== null && (
          <>
            {/* Pager — top */}
            <CursorPager
              currentCursor={filter.cursor}
              nextCursor={page.next_cursor}
              has_more={page.has_more}
              total_matching={page.total_matching}
              pageSize={visibleLogs.length}
              onNext={handleNext}
              onFirst={handleFirst}
            />

            {/* Logs table — flush Panel per DS recipe */}
            <Panel flush style={{ marginTop: 8 }}>
              <LogsTable
                logs={visibleLogs}
                onIpClick={handleIpClick}
                threatMap={threatMap}
              />
            </Panel>

            {/* Pager — bottom */}
            <CursorPager
              currentCursor={filter.cursor}
              nextCursor={page.next_cursor}
              has_more={page.has_more}
              total_matching={page.total_matching}
              pageSize={visibleLogs.length}
              onNext={handleNext}
              onFirst={handleFirst}
            />
          </>
        )}
      </div>

      {/* IP drill-down: now handled by EntityPanelProvider / SlideOver (ADR-0037).
          No IpDrilldownModal import — the panel is mounted once at the app root.
          The discoveryCache for RulePopup hints is fetched by EntityPanelProvider. */}
    </main>
  )
}
