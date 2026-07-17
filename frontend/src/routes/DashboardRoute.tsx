/**
 * DashboardRoute — /dashboard page (MF-2 v2 triage redesign, issue #159).
 *
 * v2 layout (triage-first, SOC Design System):
 *   TriageBanner        — leads with "N actors need BLOCK decision" (SIEM alert)
 *   KpiStrip            — demoted to thin single-row strip + AiEnginePill right slot (#207)
 *   ThreatActorSummary  — merged provenance-tagged top-actor block (#207)
 *   .dash-grid          — `1fr 300px` grid (dash-main + sidebar)
 *   .dash-main    → .grid-2 (Attack categories + Threat actors)
 *                   + Activity timeline Panel (+ 12h/24h window toggle)
 *                   + RecommendationCards unified queue (issue #208, via action seam)
 *   .sidebar      → AiSidebar (recommendations · IP scores)
 *                   NOTE: "AI threat summary" card removed (issue #207);
 *                   replaced by ThreatActorSummary above the dash-grid.
 *   Recently Blocked Network Logs — FULL WIDTH below the dash-grid (#253 hero placement)
 *
 * Fetches:
 *   GET /stats            → KpiStrip
 *   GET /logs/timeline    → TimelineChart (re-fetches when window toggle changes)
 *   GET /logs/categories  → CategoryBreakdown
 *   GET /threats          → ThreatActors + AiSidebar + TriageBanner + RecommendationCards + ThreatActorSummary
 *   GET /health           → KpiStrip AiEnginePill + ThreatActorSummary (authoritative; fix #180)
 *   GET /banner/summary   → TriageBanner attempts headline + pressure strip (issue #55)
 *   GET /logs/categories  → BlockedLogsPanel category tabs (via useBlockedCategories)
 *   GET /logs/paginated   → BlockedLogsPanel rows (action=blocked, via useBlockedLogs)
 *
 * Window controls (part-4 P3 / follow-up):
 *   Two modes coexist in the Activity-timeline Panel header:
 *   1. Preset toggle (12h / 24h) — trailing window from now; quick shortcut.
 *   2. Custom date-range pickers (From / To datetime-local) — arbitrary range up to 24h.
 *   Whichever the user touched LAST drives the chart (activeTimelineMode state).
 *   Clicking a preset switches back to trailing mode (deactivates the custom pickers).
 *   Editing the pickers switches to custom mode (deactivates the preset highlight).
 *   On preset change, refetches GET /logs/timeline with start = now − windowHours, end = now.
 *   On custom range change, refetches with the explicit start/end (UTC ISO).
 *   The 24h cap on the custom range matches the hourly-bucket limit (≤ 24 bars).
 *   The TimelineBrush drag-select overlay was removed because its pointer-events:auto
 *   div sat over the chart bars and blocked CellTooltip hover interactions (the brush
 *   and the bar-hover were fundamentally incompatible — part-4 P3 root cause).
 *
 * Action seam (ADR-0033):
 *   makeOnAction is the SINGLE implementation for all triage verbs.
 *   TriageBanner + RecommendationCards call onAction(actor, verb).
 *   They hold ZERO per-verb logic.
 *
 * EARS:
 *   - Event-driven: on mount, fetches /stats, /logs/timeline, /logs/categories, /threats.
 *   - State-driven: WHILE one or more actors need a decision → TriageBanner shows count + chips.
 *   - State-driven: WHILE none do → TriageBanner shows all-clear.
 *   - Event-driven: WHEN Block/Investigate/Dismiss → onAction dispatched (seam).
 *   - Ubiquitous: KPI summary renders as a thin strip (not the large card grid).
 *   - State-driven: WHEN source filter selects source with no events → EmptyState.
 *   - State-driven: WHILE loading → Spinner; IF /stats fails → error state.
 *   - Ubiquitous: /threats failure is non-fatal (ADR-0015); sidebar + banner degrade.
 *   - State-driven: AiEnginePill (global, #207) derives from GET /health (authoritative);
 *     fallback to threat-derived while health is in flight (fix #180, mirrors MF-3 #160).
 *   - Ubiquitous: ThreatActorSummary (#207) uses RULE chip when ai_status != ok;
 *     title is always "Threat summary" (never "AI …" when rule-only content — ADR-0035).
 *   - #253: "Recently Blocked Network Logs" pane spans full content width (hero placement).
 *   - #43 (ADR-0067 D5(2)): observed-stratum actors (tier=null) rolled up into
 *     deriveObservedRecord and passed to TriageBanner as one aggregate line —
 *     never rendered as individual chips, never silently dropped.
 *   - #55 (ADR-0070 D1/D3): GET /banner/summary is fetched non-blocking and
 *     passed to TriageBanner as attemptSummary; WHEN attempt_count > 0, the
 *     attempts headline + pressure strip supersede the #43 line in the same
 *     slot; WHEN null/zero, the #43 line renders unchanged.
 *
 * ADR-0015: AI is additive-only. /threats failure must not break the dashboard.
 * ADR-0029 D3: raw data rendered as text nodes only.
 * ADR-0028 D6: no raw hex — all colors via --fw-* tokens.
 * ADR-0033: action seam — makeOnAction is the single wire-in point.
 */

import { memo, useState, useEffect, useCallback, useRef, useMemo } from 'react'
import { useEntityActions } from '../components/entity/EntityPanelContext'
import { useRefreshSignal } from '../app/refresh/RefreshContext'
import { fetchStats, fetchTimeline, fetchCategories, fetchThreats, fetchHealth, fetchBannerSummary, getRuntimeConfig, ApiError } from '../api/client'
import { fetchAttackDispositions } from '../api/analytics'
import type { StatsResponse, TimelineBucket, CategoryCount, AiStatus, ThreatScore, HealthResponse, AttackDispositionRow, BannerAttemptSummary } from '../api/types'
import { makeOnAction, isDismissed, reconcileAcknowledged } from '../lib/triageActions'
import type { OnAction } from '../lib/triageActions'
import { deriveTriageActors, deriveObservedRecord } from '../lib/triageBand'
import { toDatetimeLocalValue } from '../lib/timelineDateRange'
import KpiStripBase from '../components/dashboard/KpiStrip'
import TimelineChartBase from '../components/dashboard/TimelineChart'
import CategoryBreakdownBase from '../components/dashboard/CategoryBreakdown'
import AttackCategoriesPaneBase from '../components/dashboard/AttackCategoriesPane'
import AttackDispositionFlowBase from '../components/dashboard/AttackDispositionFlow'
import ThreatActorsBase from '../components/dashboard/ThreatActors'
import AiSidebarBase from '../components/dashboard/AiSidebar'
import BlockedLogsPanelBase from '../components/dashboard/BlockedLogsPanel'
import TriageBannerBase from '../components/dashboard/TriageBanner'
import ThreatActorSummaryBase from '../components/dashboard/ThreatActorSummary'
import { deriveAiStatus } from '../components/dashboard/aiEngineStatus'
import { Panel, Input, EmptyState, ProvenanceChip } from '../components/ds'
import LoadingState from '../components/states/LoadingState'
import ErrorState from '../components/states/ErrorState'
import TimelineDateRangePicker from '../components/dashboard/TimelineDateRangePicker'

// ---------------------------------------------------------------------------
// Issue #324 — memoized panel wrappers (belt-and-suspenders).
//
// The primary fix is the EntityPanelContext split (useEntityActions() for
// action-only consumers so DashboardRoute itself does not re-render on
// slide-over open/close). These React.memo wrappers are belt-and-suspenders:
// even if DashboardRoute re-renders for another reason (e.g. window toggle),
// panels with stable props are skipped.
// ---------------------------------------------------------------------------
const KpiStrip = memo(KpiStripBase)
const TimelineChart = memo(TimelineChartBase)
const CategoryBreakdown = memo(CategoryBreakdownBase)
const AttackCategoriesPane = memo(AttackCategoriesPaneBase)
const AttackDispositionFlow = memo(AttackDispositionFlowBase)
const ThreatActors = memo(ThreatActorsBase)
const AiSidebar = memo(AiSidebarBase)
const BlockedLogsPanel = memo(BlockedLogsPanelBase)
const TriageBanner = memo(TriageBannerBase)
const ThreatActorSummary = memo(ThreatActorSummaryBase)

interface DashboardData {
  stats: StatsResponse
  timeline: TimelineBucket[]
  categories: CategoryCount[]
  threats: ThreatScore[]
  attackDispositions: AttackDispositionRow[]
}

// deriveTriageActors and isHighTierEscalation are imported from lib/triageBand.ts
// (ADR-0059 D1+D2 / issue #650 — extracted to avoid react-refresh/only-export-components
// lint constraint and to share the predicate with tests).

/**
 * DashboardRoute — exported default.
 *
 * No TimeRangeProvider wrapper — the brush and its context were removed in
 * part-4 P3 because the brush overlay (pointer-events:auto) blocked CellTooltip
 * bar hover in TimelineChart. The 12h/24h window toggle is the replacement.
 */
export default function DashboardRoute() {
  // Issue #324: useEntityActions() subscribes to the STABLE actions context.
  // DashboardRoute only calls openEntity (from onAction/investigate); it never
  // renders panel state — so this consumer must NOT re-render when the slide-over
  // opens or closes.
  const { openEntity } = useEntityActions()

  // ADR-0064 D4: subscribe to the shared live-refresh signal.
  // dataVersion increments only when a real ingest delta occurs — zero new polling.
  const { dataVersion } = useRefreshSignal()

  const [data, setData] = useState<DashboardData | null>(null)
  const [aiStatus, setAiStatus] = useState<AiStatus | null>(null)
  /**
   * GET /health — authoritative AI engine state for the KPI AiEnginePill and
   * ThreatActorSummary (fix #180, issue #207). Starts as null (health in flight);
   * stays null if the fetch fails (graceful degradation — falls back to
   * threat-derived aiStatus per ADR-0015).
   */
  const [health, setHealth] = useState<HealthResponse | null>(null)
  /**
   * GET /banner/summary (issue #55) — the attempts headline + pressure-strip
   * source of truth. Starts null (fetch in flight); stays null on failure
   * (non-fatal — ADR-0015 graceful degradation). TriageBanner falls back to
   * the #43 ObservedRecordLine unchanged while this is null.
   */
  const [attemptSummary, setAttemptSummary] = useState<BannerAttemptSummary | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [logsSearch, setLogsSearch] = useState('')
  // Dismissed actors trigger a re-render to recompute the triage banner count.
  // dismissVersion is exposed (not just setter) so useMemo can key on it (issue #755).
  const [dismissVersion, setDismissVersion] = useState(0)

  /**
   * Triage threshold — band gate for the triage banner's severity half (ADR-0059 D1 / #650).
   * Default "HIGH" preserves today's hard-coded {CRITICAL, HIGH} set exactly.
   * Loaded from GET /config/runtime on mount; non-blocking (falls back to "HIGH" on failure).
   * The escalation-tier half of deriveTriageActors is UNCONDITIONAL (ADR-0058 D2 / ADR-0036).
   */
  const [triageThreshold, setTriageThreshold] = useState<string>('HIGH')

  /**
   * Preset toggle state — 12h (default) or 24h trailing window.
   * On change, refetches GET /logs/timeline with start = now − windowHours, end = now.
   * Replaces the removed TimelineBrush (part-4 P3).
   */
  const [windowHours, setWindowHours] = useState<12 | 24>(12)

  /**
   * activeTimelineMode — which control is currently driving the chart.
   *   'preset'  → 12h / 24h trailing window from now.
   *   'custom'  → explicit From / To range entered by the user.
   * Switching a preset → 'preset'. Editing the pickers → 'custom'.
   */
  const [activeTimelineMode, setActiveTimelineMode] = useState<'preset' | 'custom'>('preset')

  /**
   * Custom range picker values (datetime-local strings, local time).
   * Initialised to empty; populated lazily when the user interacts.
   */
  const [customStart, setCustomStart] = useState('')
  const [customEnd, setCustomEnd] = useState('')

  /**
   * windowedTimeline — timeline data for the selected window (preset or custom).
   * Starts as null (uses initial data.timeline); populated by the refetch effects.
   */
  const [windowedTimeline, setWindowedTimeline] = useState<TimelineBucket[] | null>(null)
  const windowFetchRef = useRef<{ cancelled: boolean } | null>(null)

  /**
   * Re-fetch timeline when the preset window changes (windowHours) OR when the user
   * switches back to preset mode (activeTimelineMode → 'preset').
   * Skips the initial mount — data.timeline from the main fetch covers the default 12h window.
   */
  const isFirstWindowRender = useRef(true)
  useEffect(() => {
    // Skip the very first render — the main fetch below populates data.timeline.
    if (isFirstWindowRender.current) {
      isFirstWindowRender.current = false
      return
    }
    // Only act when in preset mode — custom-range changes are handled by handleCustomRangeApply.
    if (activeTimelineMode !== 'preset') return

    if (windowFetchRef.current) windowFetchRef.current.cancelled = true
    const ctrl = { cancelled: false }
    windowFetchRef.current = ctrl

    const now = new Date()
    const start = new Date(now.getTime() - windowHours * 60 * 60 * 1000).toISOString()
    const end = now.toISOString()

    void (async () => {
      try {
        const tl = await fetchTimeline({ start, end })
        if (!ctrl.cancelled) setWindowedTimeline(tl)
      } catch {
        // Non-fatal: if the window refetch fails, keep existing timeline.
      }
    })()

    return () => {
      ctrl.cancelled = true
    }
  }, [windowHours, activeTimelineMode])

  /**
   * Stable callback for the custom date-range picker's onApply.
   * Called with UTC ISO strings; fetches the custom range.
   */
  const handleCustomRangeApply = useCallback((startUtc: string, endUtc: string) => {
    if (windowFetchRef.current) windowFetchRef.current.cancelled = true
    const ctrl = { cancelled: false }
    windowFetchRef.current = ctrl

    void (async () => {
      try {
        const tl = await fetchTimeline({ start: startUtc, end: endUtc })
        if (!ctrl.cancelled) setWindowedTimeline(tl)
      } catch {
        // Non-fatal.
      }
    })()

    return () => {
      ctrl.cancelled = true
    }
  }, [])

  /**
   * Helper: initialise the custom picker to "last 12h from now" and activate
   * custom mode — used to prime the pickers when the user clicks into them
   * for the first time (so the fields are not blank).
   */
  function initCustomRange() {
    const now = new Date()
    const defaultStart = new Date(now.getTime() - 12 * 60 * 60 * 1000)
    setCustomStart(toDatetimeLocalValue(defaultStart))
    setCustomEnd(toDatetimeLocalValue(now))
  }

  useEffect(() => {
    let cancelled = false

    Promise.all([
      fetchStats(),
      fetchTimeline(),
      fetchCategories(),
      // Non-fatal: threats endpoint failure must not break the dashboard (ADR-0015)
      fetchThreats().catch((): ThreatScore[] => []),
      // Non-fatal: attack-dispositions is additive (issue #214); degrade to empty strip on failure.
      fetchAttackDispositions().catch((): AttackDispositionRow[] => []),
    ])
      .then(([stats, timeline, categories, threats, attackDispositions]) => {
        if (!cancelled) {
          // Issue #755: run material-change eviction on the data-refresh path,
          // not inside isDismissed (which must stay pure). If any acknowledged
          // actor has had a material change, bump dismissVersion so the derived
          // triage lists re-compute with the evicted actors re-surfaced.
          const anyEvicted = reconcileAcknowledged(threats)
          if (anyEvicted) {
            setDismissVersion((v) => v + 1)
          }
          setData({ stats, timeline, categories, threats, attackDispositions })
          setAiStatus(deriveAiStatus(threats))
          setLoading(false)
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(
            err instanceof ApiError
              ? `Dashboard data unavailable (${err.status})`
              : 'Failed to load dashboard data',
          )
          setLoading(false)
        }
      })

    return () => {
      cancelled = true
    }
  }, [dataVersion])

  // Fetch health — authoritative AI engine state (fix #180, mirrors AIRoute pattern).
  // Health fetch failure is non-blocking: AiEnginePill + ThreatActorSummary fall back
  // to threat-derived aiStatus (ADR-0015 graceful degradation).
  useEffect(() => {
    let cancelled = false

    fetchHealth()
      .then((healthData) => {
        if (!cancelled) setHealth(healthData)
      })
      .catch(() => {
        // Non-blocking: health unavailable → components fall back to threat-derived status.
      })

    return () => {
      cancelled = true
    }
  }, [dataVersion])

  // Fetch GET /banner/summary (issue #55) — non-blocking, mirrors the health
  // fetch pattern above. Failure is non-fatal (ADR-0015): TriageBanner falls
  // back to the #43 ObservedRecordLine unchanged while attemptSummary is null.
  useEffect(() => {
    let cancelled = false

    fetchBannerSummary()
      .then((summary) => {
        if (!cancelled) setAttemptSummary(summary)
      })
      .catch(() => {
        // Non-blocking: keep attemptSummary null — the #43 fallback line renders.
      })

    return () => {
      cancelled = true
    }
  }, [dataVersion])

  // Fetch triage threshold from /config/runtime (ADR-0059 D1 / issue #650).
  // Non-blocking: banner falls back to safe default "HIGH" on failure, which matches
  // today's hard-coded behaviour exactly — no regression risk.
  useEffect(() => {
    let cancelled = false

    getRuntimeConfig()
      .then((cfg) => {
        if (!cancelled && cfg.triage_threshold) {
          setTriageThreshold(cfg.triage_threshold)
        }
      })
      .catch(() => {
        // Non-blocking: keep the "HIGH" default (mirrors hard-coded legacy behaviour).
      })

    return () => {
      cancelled = true
    }
  }, [dataVersion])

  // Action seam (ADR-0033): single implementation for all triage verbs.
  // useCallback so the reference is stable across renders.
  //
  // MH (#204, ADR-0037): investigate → openEntity (slide-over); no route navigation.
  const onAction: OnAction = useCallback(
    (actor, verb) => {
      return makeOnAction({
        openEntity,
        onDismiss: () => {
          // Bump version to re-render after a dismiss clears an actor from the triage count
          setDismissVersion((v) => v + 1)
        },
        onBlock: () => {
          setDismissVersion((v) => v + 1)
        },
      })(actor, verb)
    },
    [openEntity],
  )

  // Issue #755: memoize both triage derivations so isDismissed runs once per actor
  // per data-change (not 3× per render across the three call sites). Hooks must be
  // called unconditionally (before any early return), so we fall back to an empty
  // array when data is not yet loaded — those code-paths return early anyway.
  //
  // dismissVersion is a deliberate invalidation signal: isDismissed reads module-level
  // in-memory state that React cannot track via its normal dep-analysis, so we use
  // this counter to force a re-computation whenever a dismiss/acknowledge action fires.
  const pendingActors = useMemo(
    () => (data != null ? deriveTriageActors(data.threats, triageThreshold) : []),
    [data, triageThreshold, dismissVersion], // eslint-disable-line react-hooks/exhaustive-deps
  )

  // Issue #43 (ADR-0067 D5(2)): the observed-stratum aggregate record line.
  // null when there is nothing below the bar to report — TriageBanner renders
  // no line in that case.
  const observedRecord = useMemo(
    () => (data != null ? deriveObservedRecord(data.threats, pendingActors) : null),
    [data, pendingActors],
  )

  const activeThreats = useMemo(
    () => (data != null ? data.threats.filter((t) => !isDismissed(t)) : []),
    [data, dismissVersion], // eslint-disable-line react-hooks/exhaustive-deps
  )

  if (loading) {
    return (
      <main
        style={{
          maxWidth: 1400,
          margin: '0 auto',
          padding: '20px 24px',
          fontFamily: 'var(--fw-font-ui)',
        }}
      >
        <LoadingState label="Loading dashboard…" />
      </main>
    )
  }

  if (error !== null) {
    return (
      <main
        style={{
          maxWidth: 1400,
          margin: '0 auto',
          padding: '20px 24px',
          fontFamily: 'var(--fw-font-ui)',
        }}
        data-testid="dashboard-error"
      >
        <ErrorState
          headline={error}
          subLine="Check that the FireWatch API is reachable and retry."
        />
      </main>
    )
  }

  if (data === null) return null

  // Empty state: no events at all
  if (data.stats.total_logs === 0) {
    return (
      <main
        style={{
          maxWidth: 1400,
          margin: '0 auto',
          padding: '20px 24px',
          fontFamily: 'var(--fw-font-ui)',
        }}
        data-testid="dashboard-empty"
      >
        {/* Still show KPI strip with zeroes */}
        <KpiStrip stats={data.stats} aiStatus={aiStatus} health={health} timeline={data.timeline} />
        <EmptyState
          icon="📊"
          title="No events yet"
          data-testid="dashboard-empty-state"
        >
          No events have been ingested. Point your source at FireWatch and wait for the first sync.
        </EmptyState>
      </main>
    )
  }

  // The timeline to display: windowed refetch (if available) else initial load
  const displayTimeline = windowedTimeline ?? data.timeline

  return (
    <main
      style={{
        maxWidth: 1400,
        margin: '0 auto',
        padding: '20px 24px',
        fontFamily: 'var(--fw-font-ui)',
      }}
    >
      {/* Triage banner — leads with "N actors need BLOCK decision" (SIEM, ADR-0033) */}
      <TriageBanner
        pendingActors={pendingActors}
        onAction={onAction}
        observedRecord={observedRecord}
        attemptSummary={attemptSummary}
      />

      {/* KPI strip — v2 thin row (demoted from large 5-up grid) */}
      {/* health is authoritative for AI chip; aiStatus is the fallback (fix #180) */}
      {/* timeline fed for per-KPI sparklines (issue #254) */}
      <KpiStrip stats={data.stats} aiStatus={aiStatus} health={health} timeline={data.timeline} />

      {/* Merged threat-actor summary — honest provenance-tagged block (issue #207).
          Replaces both the old AiPanel and AiSidebar's "AI threat summary" card.
          One block, one ProvenanceChip — never claims AI when only rules ran. */}
      <ThreatActorSummary threats={data.threats} health={health} />

      {/* .dash-grid — 1fr 300px */}
      <div
        data-testid="dash-grid"
        style={{
          display: 'grid',
          gridTemplateColumns: '1fr 300px',
          gap: 16,
        }}
      >
        {/* .dash-main */}
        <div
          data-testid="dash-main"
          style={{ display: 'flex', flexDirection: 'column', gap: 16 }}
        >
          {/* .grid-2 — 2×2 bento (issue #262):
              Left column (~40%): Attack categories (top) + Dispositions (bottom) — short top-5 bar lists.
              Right column (~60%): Threat actors spanning the full height of both left panes.
              The 2:3 column ratio gives Threat actors ~600 px at 1400 px maxWidth + 300 px sidebar,
              enough to display all five columns (IP · Last Active · Events · Blocked · Score)
              without clipping. Total row height unchanged from the 1fr 1fr 1fr layout, so
              🧠 AI threat summary and ⚡ Recommendations stay above the fold (Maintainer's constraint).
              Cross-reading Attacks vs Dispositions reveals e.g. "geo-blocks absorbing the sqli wave".
              Issue #206: split the old single "Attack categories" panel into two honest panes.
              Breakpoint: when viewport is below grid breakpoint the panels stack vertically. */}
          <div
            data-testid="grid-2"
            style={{
              display: 'grid',
              gridTemplateColumns: '2fr 3fr',
              gridTemplateRows: 'auto auto',
              gap: 16,
            }}
          >
            {/* Left top: Attacks (attempted) — aggregated from attack_types on GET /threats.
                Carries RULE chip: derived from the rule engine (ADR-0035). */}
            <Panel
              title="Attack categories"
              icon="⚔️"
              actions={
                <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                  <ProvenanceChip derivation="rule" data-testid="attacks-pane-chip" />
                </div>
              }
              style={{ gridColumn: 1, gridRow: 1 }}
            >
              <AttackCategoriesPane threats={data.threats} />
            </Panel>

            {/* Left bottom: Dispositions (outcome) — what the WAF/IDS did — GET /logs/categories */}
            <Panel
              title="Dispositions"
              icon="🛡️"
              style={{ gridColumn: 1, gridRow: 2 }}
            >
              <CategoryBreakdown categories={data.categories} />
            </Panel>

            {/* Right: Threat actors — spans both rows → full height of left column.
                ~60% width (~600 px) restores all 5 columns including LAST ACTIVE (#241). */}
            <Panel
              title="Threat actors"
              icon="🎯"
              flush
              style={{ gridColumn: 2, gridRow: '1 / span 2' }}
              data-testid="threat-actors-panel"
            >
              <ThreatActors threats={data.threats} />
            </Panel>
          </div>

          {/* Attack → Disposition flow strip — footers P5 panes (issue #214).
              Degrade-to-hidden when cross-tab is empty (non-fatal, additive). */}
          {data.attackDispositions.length > 0 && (
            <Panel
              title="Detection vs Enforcement"
              icon="🔀"
            >
              <AttackDispositionFlow rows={data.attackDispositions} />
            </Panel>
          )}

          {/* Activity timeline — GET /logs/timeline.
              Two modes in the Panel actions slot (part-4 P3 + follow-up):
              1. 12h / 24h preset toggle — trailing window shortcut.
              2. Custom From / To datetime-local pickers — explicit range (≤ 24h).
              Whichever the user touched last drives the chart (activeTimelineMode). */}
          <Panel
            title="Activity timeline"
            icon="📈"
            actions={
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 10,
                  flexWrap: 'wrap',
                }}
                data-testid="timeline-controls"
              >
                {/* 12h / 24h preset toggle — same visual pattern as the severity/disposition
                    segmented toggle inside TimelineChart.tsx (--fw-* tokens, no raw hex).
                    ADR-0028 D6. Real buttons, keyboard-toggleable, aria-pressed (WCAG 4.1.2).
                    Active only when activeTimelineMode === 'preset'. */}
                <div
                  role="group"
                  aria-label="Timeline window"
                  data-testid="timeline-window-toggle"
                  style={{
                    display: 'flex',
                    gap: 0,
                    borderRadius: 5,
                    overflow: 'hidden',
                    border: '1px solid var(--fw-border-l)',
                  }}
                >
                  <button
                    type="button"
                    data-testid="timeline-window-12h"
                    aria-pressed={activeTimelineMode === 'preset' && windowHours === 12}
                    onClick={() => {
                      setWindowHours(12)
                      setActiveTimelineMode('preset')
                    }}
                    style={{
                      padding: '3px 10px',
                      fontSize: 11,
                      fontFamily: 'var(--fw-font-ui)',
                      background: activeTimelineMode === 'preset' && windowHours === 12 ? 'var(--fw-bg-hover)' : 'transparent',
                      color: activeTimelineMode === 'preset' && windowHours === 12 ? 'var(--fw-t1)' : 'var(--fw-t3)',
                      border: 'none',
                      cursor: 'pointer',
                      borderRight: '1px solid var(--fw-border-l)',
                      fontWeight: activeTimelineMode === 'preset' && windowHours === 12 ? 600 : 400,
                    }}
                  >
                    12h
                  </button>
                  <button
                    type="button"
                    data-testid="timeline-window-24h"
                    aria-pressed={activeTimelineMode === 'preset' && windowHours === 24}
                    onClick={() => {
                      setWindowHours(24)
                      setActiveTimelineMode('preset')
                    }}
                    style={{
                      padding: '3px 10px',
                      fontSize: 11,
                      fontFamily: 'var(--fw-font-ui)',
                      background: activeTimelineMode === 'preset' && windowHours === 24 ? 'var(--fw-bg-hover)' : 'transparent',
                      color: activeTimelineMode === 'preset' && windowHours === 24 ? 'var(--fw-t1)' : 'var(--fw-t3)',
                      border: 'none',
                      cursor: 'pointer',
                      fontWeight: activeTimelineMode === 'preset' && windowHours === 24 ? 600 : 400,
                    }}
                  >
                    24h
                  </button>
                </div>

                {/* Custom From / To date-range pickers.
                    Active when activeTimelineMode === 'custom'.
                    On first interaction the pickers are primed to "last 12h → now". */}
                <TimelineDateRangePicker
                  startValue={customStart}
                  endValue={customEnd}
                  isActive={activeTimelineMode === 'custom'}
                  onStartChange={(newStart, correctedEnd) => {
                    if (!customStart && !customEnd) {
                      // First interaction: prime both fields before applying user's Start
                      initCustomRange()
                    }
                    setCustomStart(newStart)
                    setCustomEnd(correctedEnd)
                    setActiveTimelineMode('custom')
                  }}
                  onEndChange={(correctedEnd) => {
                    setCustomEnd(correctedEnd)
                    setActiveTimelineMode('custom')
                  }}
                  onApply={(startUtc, endUtc) => {
                    setActiveTimelineMode('custom')
                    handleCustomRangeApply(startUtc, endUtc)
                  }}
                />
              </div>
            }
          >
            <div data-testid="timeline-panel-inner">
              <TimelineChart buckets={displayTimeline} />
            </div>
          </Panel>

        </div>

        {/* .sidebar — Risk Movers (orient) + Recommended actions (respond) */}
        {/* CR6 (#617): Recommended actions moved from dash-main into sidebar,
            positioned BELOW Risk Movers (orient → respond scan order).
            Compact top-3 + "view all" affordance; no inner scrollbar. */}
        <aside
          data-testid="ai-sidebar-col"
          style={{ display: 'flex', flexDirection: 'column', gap: 12 }}
        >
          <AiSidebar threats={activeThreats} onAction={onAction} health={health} />
        </aside>
      </div>

      {/* Recently Blocked Network Logs — FULL WIDTH hero placement (#253).
          Placed outside dash-grid so it spans the full content width (the primary
          work table for the analyst's most-used view).
          IP search is lifted here for the Panel header actions slot;
          BlockedLogsPanel debounces the value before querying the backend. */}
      <div style={{ marginTop: 16 }}>
        <Panel
          title="Recently Blocked Network Logs"
          icon="🚫"
          flush
          actions={
            <Input
              size="sm"
              placeholder="Search by IP…"
              value={logsSearch}
              onChange={(e) => setLogsSearch(e.target.value)}
              style={{ width: 160 }}
              data-testid="logs-search"
            />
          }
        >
          <BlockedLogsPanel ipSearch={logsSearch} timeRange={null} />
        </Panel>
      </div>
    </main>
  )
}
