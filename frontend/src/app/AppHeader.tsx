/**
 * AppHeader — sticky SOC console header (F1 #107, F2 #108, F3 #109).
 *
 * Matches the kit.css .hdr recipe:
 *   - Linear gradient fade from --fw-bg-card to --fw-bg (dark)
 *   - 🔥 FireWatch AI wordmark: flame + amber "FireWatch" + muted "AI"
 *   - SourceHealth dot row (F3/#109 — Combobox hidden until ADR-0038 A–B, see #282)
 *   - LiveBadge (DS feedback component, replaces F1 LiveDot stub)
 *   - ThemeToggle (DS navigation component, replaces F1 ThemeToggleStub)
 *   - MonoClock: local time with inline zone label + CellTooltip (hover/focus → live UTC)
 *     Zone authority moved here from the per-page DashboardZoneChip banner (#278).
 *     Visible on every tab, not just /dashboard.
 *
 * ADR-0032 (#134): All Sources = installed-driven list + 4-color server health dot.
 *   Data flows:
 *     GET /stats → source_health[] (installed-driven, ADR-0032 A) → toSourceHealthItems() → SourceHealth
 *     Dot color = server-computed `health` field (ADR-0032 C — no recency math here)
 *     GET /stats → source_health[].display_name → Combobox options when ADR-0038 A–B lands (#282)
 *
 * GET /sources is no longer needed for the dot — supervisor_state is already
 * embedded in source_health[] via the stats assembler. The fetch is removed to
 * keep the header lean (ADR-0032 E: /stats is the single source of health data).
 *
 * Issue #335: LiveBadge is now bound to real polling state (not hardcoded live={true}).
 *   live=true  — polling active, last poll succeeded (green pulsing).
 *   live=false — polling failed or not yet seeded (grey "Paused").
 *   Tooltip on LiveBadge: "Auto-refresh: 30s · last update Xs ago".
 *   Sync banner (full-width, below header): "{N} new events from {source}" on positive delta.
 *   Replaces the old top-right toast which was occluded by the slide-over panel.
 *   Post-sync pulse: affected source dots pulse briefly (animation, not color change).
 *
 * LIVE badge is DISTINCT from per-source dots (issue #335 spec):
 *   LIVE = "is this console refreshing?" (whole console auto-refresh state)
 *   Dots = "is each source ingesting?" (per-source freshness, server-computed)
 *
 * ADR-0019: React + Vite + TS. No legacy/ import. No per-source hardcode.
 */

import { useEffect, useRef, useState } from 'react'
import { useTheme } from './ThemeContext'
import { useNavigate } from 'react-router-dom'
// Combobox + ComboOption removed from imports — hidden until ADR-0038 phases A–B land (#282).
import { LiveBadge, ThemeToggle, SourceHealth, CellTooltip, SyncBanner } from '../components/ds'
import { useHeaderRefresh, HEALTH_POLL_MS } from '../hooks/useHeaderRefresh'
import { localZoneLabel, formatUtc } from '../lib/time'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * How long (ms) to show the sync banner before auto-dismissing.
 * 5 s gives the operator enough time to register the notification without
 * it feeling obtrusive; restored from the original toast duration.
 */
const BANNER_DISMISS_MS = 5_000

// ---------------------------------------------------------------------------
// MonoClock
// ---------------------------------------------------------------------------

/**
 * Build the local time string with inline zone label, e.g. "21:47:03 EDT".
 * Uses 24-hour format with seconds for SOC precision.
 */
function buildClockLabel(now: Date): string {
  const time = now.toLocaleTimeString(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  })
  return `${time} ${localZoneLabel()}`
}

/**
 * MonoClock — header clock that serves as the timezone authority (#278).
 *
 * - Renders local time with inline zone abbreviation: "21:47:03 EDT"
 * - CellTooltip (WCAG 1.4.13): hover or keyboard focus → live UTC time
 *   + legend "all times shown in <zone> · stored as UTC"
 * - The tooltip UTC string ticks in sync with the clock.
 */
function MonoClock() {
  const [now, setNow] = useState(() => new Date())

  useEffect(() => {
    const t = setInterval(() => {
      setNow(new Date())
    }, 1000)
    return () => clearInterval(t)
  }, [])

  const zone = localZoneLabel()
  const utcString = formatUtc(now)

  const tooltipContent = (
    <div data-testid="clock-tooltip-content" style={{ lineHeight: 1.6 }}>
      <div
        style={{
          fontFamily: 'var(--fw-font-mono)',
          fontSize: 12,
          color: 'var(--fw-t1)',
        }}
      >
        {utcString}
      </div>
      <div
        style={{
          fontSize: 11,
          color: 'var(--fw-t3)',
          marginTop: 4,
        }}
      >
        all times shown in {zone} · stored as UTC
      </div>
    </div>
  )

  return (
    <CellTooltip content={tooltipContent} data-testid="header-clock-trigger">
      <span
        data-testid="header-clock"
        style={{
          fontFamily: 'var(--fw-font-mono)',
          fontSize: 'var(--fw-fs-xs)',
          color: 'var(--fw-t3)',
          whiteSpace: 'nowrap',
        }}
      >
        {buildClockLabel(now)}
      </span>
    </CellTooltip>
  )
}

// ---------------------------------------------------------------------------
// LiveBadgeWithTooltip (issue #335)
// ---------------------------------------------------------------------------

/**
 * Format seconds elapsed into a human-relative string.
 * e.g. 5 → "5s ago", 90 → "2m ago"
 */
function formatSecondsAgo(seconds: number): string {
  if (seconds < 60) return `${Math.floor(seconds)}s ago`
  return `${Math.round(seconds / 60)}m ago`
}

interface LiveBadgeWithTooltipProps {
  isLive: boolean
  lastPollAt: string | null
}

/**
 * LiveBadgeWithTooltip — wraps LiveBadge in a CellTooltip that shows:
 *   "Auto-refresh: 30s · last update Xs ago"
 *
 * The badge reflects real polling state (issue #335):
 *   live=true  — polling active, last poll succeeded
 *   live=false — polling failed or not yet seeded
 *
 * DISTINCT from per-source dots:
 *   LIVE = "is this console refreshing?" (whole console auto-refresh state)
 *   Dots = "is each source ingesting?" (per-source freshness)
 */
function LiveBadgeWithTooltip({ isLive, lastPollAt }: LiveBadgeWithTooltipProps) {
  // Tick every second so "last update Xs ago" stays fresh.
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const t = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(t)
  }, [])

  const intervalSeconds = Math.round(HEALTH_POLL_MS / 1000)

  let sinceLast = ''
  if (lastPollAt) {
    const secondsAgo = Math.max(0, (now - new Date(lastPollAt).getTime()) / 1000)
    sinceLast = formatSecondsAgo(secondsAgo)
  }

  const tooltipContent = (
    <div data-testid="live-badge-tooltip-content" style={{ lineHeight: 1.6 }}>
      <div
        style={{
          fontSize: 11,
          color: 'var(--fw-t2)',
        }}
      >
        Auto-refresh: {intervalSeconds}s
        {sinceLast && ` · last update ${sinceLast}`}
      </div>
      <div
        data-testid="live-badge-tooltip-legend"
        style={{
          fontSize: 10,
          color: 'var(--fw-t3)',
          marginTop: 3,
        }}
      >
        {isLive ? 'Console is refreshing data' : 'Polling paused or unavailable'}
      </div>
    </div>
  )

  return (
    <CellTooltip content={tooltipContent} data-testid="live-badge-trigger">
      <LiveBadge
        data-testid="live-dot"
        live={isLive}
      >
        {isLive ? 'Live' : 'Paused'}
      </LiveBadge>
    </CellTooltip>
  )
}

// ---------------------------------------------------------------------------
// SourceFilterBar (issue #335 — uses useHeaderRefresh)
// ---------------------------------------------------------------------------

/**
 * SourceFilterBar — SourceHealth dots, LiveBadge and sync banner, driven by
 * GET /stats via useHeaderRefresh.
 *
 * ADR-0032 (#134):
 *   - List membership = installed plugins (every source_health[] entry).
 *   - Dot color = server-computed `health` field (no recency math here).
 *   - display_name used as the chip label (plugin-declared human name).
 *
 * GET /sources is no longer fetched — supervisor_state is already embedded
 * in source_health[] entries by the stats assembler (ADR-0032 E).
 *
 * 503-safe: if GET /stats fails, last good state is preserved (no crash);
 * LiveBadge transitions to Paused.
 *
 * Issue #335:
 *   - sync banner shown when event count grows between polls (replaces toast
 *     which was occluded by the right-side slide-over panel).
 *   - Attribution: "{N} new events from {source}" (single) or
 *     "{N} new events ({src1}, {src2})" (multi) using display_name from stats.
 *   - Auto-dismisses after BANNER_DISMISS_MS (3 s); × for manual close.
 *   - post-sync pulse forwarded to SourceHealth → HealthDot.
 *   - LiveBadgeWithTooltip replaces hardcoded live={true}.
 *
 * NOTE (#282 / ADR-0038): The "All Sources" Combobox has been removed.
 * To revive: see previous comment block in this file.
 */
function SourceFilterBar() {
  const {
    healthItems,
    isLive,
    lastPollAt,
    lastSyncDeltaCount,
    syncEventId,
    pulsingSources,
    clearSyncDelta,
    freshnessMinutes,
  } = useHeaderRefresh()

  // Banner state — single object to avoid cascading setState calls in the effect.
  const [bannerState, setBannerState] = useState<{
    visible: boolean
    count: number
    sources: ReadonlySet<string>
  }>({
    visible: false,
    count: 0,
    sources: new Set(),
  })

  // Ref for the dismiss timer so we can cancel + restart it when a new sync
  // event arrives while the banner is already showing. Kept in a ref so that
  // cancellation never interacts with the effect's own dependency array.
  const dismissTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  // Drive the banner off `syncEventId`, a monotonically-increasing counter that
  // is NEVER reset to 0. This decouples the banner lifecycle from the
  // `clearSyncDelta()` call (which resets lastSyncDeltaCount → 0). The old
  // approach depended on `lastSyncDeltaCount` directly: calling clearSyncDelta()
  // flipped its own dependency (N → 0), which re-ran the effect's cleanup and
  // cancelled the dismiss timer — leaving the banner permanently visible.
  useEffect(() => {
    if (syncEventId === 0) return undefined

    // Capture the current delta count and pulsing sources then immediately clear
    // so the values don't double-fire on the next render without a new poll.
    const count = lastSyncDeltaCount
    // Snapshot pulsingSources — it's a ReadonlySet; capture by reference is safe
    // here because we only read it for the banner message.
    const sources = pulsingSources
    clearSyncDelta()

    // Cancel any in-flight dismiss timer from a previous banner so we get a
    // fresh BANNER_DISMISS_MS window for this event (no leaked timers).
    if (dismissTimerRef.current !== null) {
      clearTimeout(dismissTimerRef.current)
      dismissTimerRef.current = null
    }

    // Show the banner. setState inside a setTimeout satisfies the
    // react-hooks/set-state-in-effect lint rule (state update must be inside
    // a callback, not directly in the synchronous effect body).
    const showTimer = setTimeout(() => {
      setBannerState({ visible: true, count, sources })
    }, 0)

    dismissTimerRef.current = setTimeout(() => {
      dismissTimerRef.current = null
      setBannerState((prev) => ({ ...prev, visible: false }))
    }, BANNER_DISMISS_MS)

    return () => {
      // Only cancel the show timer on cleanup — the dismiss timer is owned by
      // the ref so that it survives the dependency-flip-free re-runs caused by
      // clearSyncDelta(). Cancelling dismissTimerRef here would re-introduce
      // the original bug.
      clearTimeout(showTimer)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [syncEventId])

  /**
   * Build the attributed banner message from the delta count and pulsing sources.
   *
   * Attribution strategy: look up display names from `healthItems` (the
   * SourceHealthItem[] from /stats — each item has a `label` field that is the
   * plugin-declared display_name, e.g. "Azure WAF" or "Suricata IDS/IPS").
   * We match on `sourceType` key from `pulsingSources`.
   * If no healthItem is found for a key (unlikely race), we fall back to the
   * raw type key.
   */
  function buildBannerMessage(count: number, sources: ReadonlySet<string>): string {
    const n = count.toLocaleString()
    const sourceKeys = [...sources]

    if (sourceKeys.length === 0) {
      // Fallback: no source attribution available.
      return `${n} new events ingested`
    }

    // Build a lookup map: sourceType → display label.
    const labelByType = new Map(healthItems.map((item) => [item.sourceType, item.label]))
    const sourceLabels = sourceKeys.map((key) => labelByType.get(key) ?? key)

    if (sourceLabels.length === 1) {
      // Single source: "{N} new events from {source}"
      return `${n} new events from ${sourceLabels[0]}`
    }

    // Multiple sources: "{N} new events ({src1}, {src2}, …)"
    return `${n} new events (${sourceLabels.join(', ')})`
  }

  const bannerMessage = buildBannerMessage(bannerState.count, bannerState.sources)

  // Manual close — immediately hides the banner and cancels the auto-dismiss timer.
  function handleBannerClose() {
    if (dismissTimerRef.current !== null) {
      clearTimeout(dismissTimerRef.current)
      dismissTimerRef.current = null
    }
    setBannerState((prev) => ({ ...prev, visible: false }))
  }

  return (
    <>
      {/*
       * Sync banner — full-width fixed overlay below the header.
       *
       * Rendered unconditionally (visibility controlled by the `visible` prop)
       * so the slide animation can run. The SyncBanner itself uses
       * pointer-events:none when not visible so it doesn't block clicks.
       *
       * Positioning: fixed; top = --fw-header-h (52px); z-index 115.
       * This overlays content without reflowing the page layout (no layout shift),
       * and sits above the entity slide-over (z-index 110) so the right sidebar
       * cannot occlude it (the original toast issue).
       */}
      <SyncBanner
        visible={bannerState.visible}
        message={bannerMessage}
        onClose={handleBannerClose}
      />

      <div
        data-testid="source-filter-bar"
        style={{ display: 'flex', alignItems: 'center', gap: 8 }}
      >
        {/* "All Sources" Combobox removed until ADR-0038 phases A–B land (#282, #286). */}
        {healthItems.length > 0 && (
          <SourceHealth
            data-testid="source-health-row"
            sources={healthItems}
            pulsingSources={pulsingSources}
            freshnessMinutes={freshnessMinutes}
          />
        )}
      </div>

      {/* LiveBadge with tooltip — bound to real polling state (issue #335).
          DISTINCT from per-source dots — LIVE = "is this console refreshing?"
          Dots = "is each source ingesting?" (server-computed, ADR-0032 C) */}
      <LiveBadgeWithTooltip isLive={isLive} lastPollAt={lastPollAt} />
    </>
  )
}

// ---------------------------------------------------------------------------
// AppHeader
// ---------------------------------------------------------------------------

export default function AppHeader() {
  const navigate = useNavigate()
  const { theme, toggleTheme } = useTheme()

  return (
    <header
      data-testid="app-header"
      style={{
        /*
         * kit.css .hdr — gradient from bg-card (#111827) to bg (#0a0e17) in dark.
         * In light theme the gradient source is #ffffff per kit.css:
         *   [data-theme="light"] .hdr { background: linear-gradient(180deg, #ffffff, var(--fw-bg)); }
         * We use CSS custom properties so both themes resolve correctly.
         */
        background: 'linear-gradient(180deg, var(--fw-bg-card), var(--fw-bg))',
        borderBottom: '1px solid var(--fw-border)',
        padding: '14px 24px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        position: 'sticky',
        top: 0,
        zIndex: 100,
        height: 'var(--fw-header-h)',
      }}
    >
      {/* Left: wordmark */}
      <div
        style={{ display: 'flex', alignItems: 'center', gap: 12, cursor: 'pointer' }}
        onClick={() => navigate('/dashboard')}
        role="button"
        aria-label="FireWatch home"
        data-testid="header-wordmark"
      >
        <span style={{ fontSize: 24 }} aria-hidden="true">
          🔥
        </span>
        {/*
          * Wordmark demoted from <h1> to <span> — each page renders its own
          * <h1> (Settings, Logs, AI, Analytics). Two <h1>s per page violates
          * WCAG SC 1.3.1 and degrades screen-reader heading navigation (#567).
          * Visual appearance is unchanged; only the element role changes.
          */}
        <span
          style={{
            fontSize: 'var(--fw-fs-h1)',
            fontWeight: 'var(--fw-fw-bold)',
            color: 'var(--fw-accent)',
            lineHeight: 1,
          }}
        >
          FireWatch{' '}
          <span
            style={{
              color: 'var(--fw-t2)',
              fontWeight: 'var(--fw-fw-regular)',
            }}
          >
            AI
          </span>
        </span>
      </div>

      {/* Right: source-filter + health dots + live badge (inside SourceFilterBar) + toggle + clock */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        {/* F3/#109: real source filter + health dots + LiveBadge, all driven by API.
            Issue #335: LiveBadge moved inside SourceFilterBar to co-locate with the
            polling hook that drives its state. */}
        <SourceFilterBar />

        {/* DS ThemeToggle — replaces F1 ThemeToggleStub (F2 #108) */}
        <ThemeToggle theme={theme} onToggle={toggleTheme} />

        <MonoClock />
      </div>
    </header>
  )
}
