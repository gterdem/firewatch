/**
 * AIRoute — the /ai page: AI Engine (ADR-0043).
 *
 * MK-1 honesty pass (issue #406):
 *   - Nav tab renamed "AI Analysis" → "AI Engine" (AppNav.tsx).
 *   - Page subtitle added: "Every verdict, what the model saw, and proof nothing left this box."
 *   - AiSummaryPanel retitled "Threat summary" with RULE ProvenanceChip (no false AI label).
 *   - AI coverage sentence templated from real ai_status counts, not false claim.
 *   - Block recommendation reframed as advisory copy (ADR-0033 / ADR-0035).
 *
 * MM #452 (drop "Reveal scores" gate):
 *   - summaryRun state + onSummaryRun callback removed.
 *   - AiSummaryPanel no longer receives summaryRun / onSummaryRun — scores shown by default.
 *
 * MM #450 (clickable priority IPs):
 *   - Priority actor IPs in AiSummaryPanel now render via ClickableIp (handled in component).
 *
 * MK-3 (issue #408): Replace duplicate AiThreatTable with:
 *   (a) Coverage ledger pane — CoverageLedger (headline + AI-specific actor table).
 *   (b) Verdict cards pane — VerdictCardList (per stored analysis, read-only).
 *
 * MK-6 (issue #411): Add Agree/Disagree controls (VerdictFeedback, in VerdictCard) and
 *   the agreement headline stat (AgreementStat — mounted below the verdict cards panel
 *   title). AgreementStat self-fetches GET /ai/feedback/summary; no new page-level state.
 *
 * MK-6 D2 (defect fix): AgreementStat now re-fetches after each successful analyst submit.
 *   feedbackVersion counter is lifted here; it bumps on every successful submit via
 *   handleFeedbackChange → VerdictCardList → VerdictCard → VerdictFeedback → onSuccess.
 *   AgreementStat receives refreshKey={feedbackVersion} to re-run its fetch on change.
 *
 * Layout (top to bottom):
 *   1. Page heading + subtitle (ADR-0043 D2).
 *   2. AiSummaryPanel — threat summary with RULE chip, Reveal scores, advisory advice.
 *   3. Coverage ledger — AI-specific actor view (NOT the Dashboard duplicate).
 *   4. Verdict cards — persisted AI analyses with AI ProvenanceChip + feedback controls.
 *      4a. AgreementStat headline — agreement % with denominator + RULE chip (ADR-0045 D4).
 *   5. Model trust panel — verdict-drift report (MK-9, ADR-0043 D3 block 4).
 *
 * Wire-up:
 *   - GET /threats (ThreatScore[]) — coverage ledger actor list + ai_status counts
 *   - GET /health  (HealthResponse) — authoritative Local AI engine state (MF-3 #160)
 *   - GET /ai/analyses?limit=200 (AnalysisListPage) — stored verdict cards (ADR-0044).
 *     Fetched with limit=200 (API max) so the rollup count is accurate. If has_more=true
 *     (>200 analyses), the headline renders "200+" rather than a false exact number.
 *   - IP click → entity slide-over panel (ADR-0037; useEntityPanel().openEntity)
 *
 * EARS (issue #160 MF-3):
 *   - Ubiquitous: AI Engine tab remains a distinct top-level tab (5 tabs total).
 *   - State-driven: WHILE Local AI engine enabled/disabled, AI page status reflects
 *     that state via GET /health (single source of truth — no duplicate state).
 *   - Ubiquitous: #111 adherence lint gate passes.
 *
 * EARS (issue #264 — ?filter=below-threshold deep-link):
 *   - WHEN the page opens with ?filter=below-threshold, the coverage ledger SHALL show
 *     only score-0 actors (below-threshold filter applied as a coverage facet).
 *   - Format guard: only the literal value "below-threshold" is accepted; any other
 *     value is silently ignored (no crash, no injected text — ADR-0029 D3).
 *
 * EARS (issue #408 MK-3):
 *   - THE coverage pane SHALL show the coverage headline from real data (RULE chip).
 *   - THE actor list SHALL show AI-specific columns ONLY (ADR-0043 D1).
 *   - WHEN stored analyses exist → verdict cards with AI ProvenanceChip, ConfidenceLabel,
 *     model+age, ScoreBadge (ADR-0035/0036 provenance).
 *   - WHEN no analyses stored → honest EmptyState (no fabricated counts).
 *   - Bounded panes: no inner scrollbars; top-N + "view all" count.
 *
 * ADR-0015: AI is additive-only. AI being offline is informational — not an error.
 * ADR-0029 D3: attacker-controlled fields rendered as text nodes only.
 *              The ?filter= value is validated before use — never echoed raw into the DOM.
 * ADR-0035: no pane titled "AI …" without ai derivation; rule-templated text carries RULE chip.
 * ADR-0043: page identity — local-AI accountability surface; subtitle specified by D2.
 * ADR-0044: verdict ledger — persisted analyses feed the verdict cards.
 *
 * MM #451: ProvenanceChipLegend mounted in a clearly-delimited block under the
 *   subtitle. Shown once per session (dismissed via sessionStorage). Explains
 *   RULE / AI / AI+RULE at the point of first encounter.
 */

import { useState, useEffect, useCallback } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useRefreshSignal } from '../app/refresh/RefreshContext'
import { fetchThreats, fetchHealth, ApiError } from '../api/client'
import type { ThreatScore, AiStatus, HealthResponse } from '../api/types'
import { deriveAiStatus } from '../components/dashboard/aiEngineStatus'
import AiSummaryPanel from '../components/ai/AiSummaryPanel'
import { CoverageLedger } from '../components/ai/ledger/CoverageLedger'
import { VerdictCardList } from '../components/ai/ledger/VerdictCardList'
import { AgreementStat } from '../components/ai/ledger/AgreementStat'
import { useVerdictLedger } from '../components/ai/ledger/useVerdictLedger'
import { DriftPanel } from '../components/ai/drift/DriftPanel'
import { Panel, ProvenanceChipLegend } from '../components/ds'

/**
 * Accepted values for the ?filter= URL param (issue #264).
 * Only the exact string "below-threshold" is valid — guards against injection.
 */
const VALID_FILTER_VALUES = ['below-threshold'] as const
type FilterValue = (typeof VALID_FILTER_VALUES)[number] | null

/**
 * Format guard for ?filter= deep-link param (issue #264, ADR-0029 D3).
 * Returns the validated filter value, or null if invalid / absent.
 */
function parseFilterParam(raw: string | null): FilterValue {
  if (raw === null) return null
  if ((VALID_FILTER_VALUES as readonly string[]).includes(raw)) {
    return raw as FilterValue
  }
  return null
}

export default function AIRoute() {
  const [threats, setThreats] = useState<ThreatScore[]>([])
  const [aiStatus, setAiStatus] = useState<AiStatus | null>(null)
  const [health, setHealth] = useState<HealthResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  /**
   * D2 reactivity: feedbackVersion is bumped on every successful analyst submit.
   * AgreementStat receives this as refreshKey so it re-fetches GET /ai/feedback/summary
   * automatically — no full page reload needed.
   */
  const [feedbackVersion, setFeedbackVersion] = useState(0)
  const handleFeedbackChange = useCallback(() => setFeedbackVersion((v) => v + 1), [])

  /**
   * MK-11 ledger reactivity: ledgerVersion bumped after a Re-run analysis completes
   * on any VerdictCard. useVerdictLedger re-fetches when refreshKey changes, so the
   * new analysis row appears without a full page reload.
   * Pattern mirrors feedbackVersion above (D2 reactivity).
   */
  const [ledgerVersion, setLedgerVersion] = useState(0)
  const handleRerunComplete = useCallback(() => setLedgerVersion((v) => v + 1), [])

  // Read and validate the ?filter= URL param (issue #264).
  const [searchParams] = useSearchParams()
  const filterParam = parseFilterParam(searchParams.get('filter'))

  // ADR-0064 D4: subscribe to the shared live-refresh signal.
  // dataVersion increments only when a real ingest delta occurs — zero new polling.
  const { dataVersion } = useRefreshSignal()

  // Verdict ledger — GET /ai/analyses (ADR-0044 / MK-3).
  // Fetched with limit=200 (API max) so the rollup count is accurate.
  // If has_more=true (>200 analyses on a busy box), the headline renders
  // "200+" rather than a false exact total (never invent a number — ADR-0043 D1).
  // 503 degrades to empty state honestly.
  // MK-11: refreshKey={ledgerVersion} causes re-fetch after Re-run analysis completes.
  // ADR-0064 D4: dataVersion added so a real ingest delta also triggers a ledger refresh.
  const ledger = useVerdictLedger({ limit: 200, refreshKey: ledgerVersion + dataVersion })

  // Fetch threats — drives the coverage ledger actor list and ai_status counts.
  useEffect(() => {
    let cancelled = false

    fetchThreats()
      .then((threatData) => {
        if (!cancelled) {
          setThreats(threatData)
          setAiStatus(deriveAiStatus(threatData))
          setLoading(false)
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(
            err instanceof ApiError
              ? `Threat data unavailable (${err.status})`
              : 'Failed to load threat data',
          )
          setLoading(false)
        }
      })

    return () => {
      cancelled = true
    }
  }, [dataVersion])

  // ADR-0064 D4/D6: health now follows the shared dataVersion signal.
  // The standalone 15 s setInterval (BUG-2 fix #449) is removed — its freshness
  // is superseded by the app-wide heartbeat in RefreshProvider (one interval for
  // the whole app).  A failed health fetch is non-blocking (ADR-0015).
  useEffect(() => {
    let cancelled = false

    fetchHealth()
      .then((healthData) => {
        if (!cancelled) setHealth(healthData)
      })
      .catch(() => {
        // Non-blocking: health unavailable → AiSummaryPanel falls back to
        // threat-derived status (ADR-0015 graceful degradation).
      })

    return () => {
      cancelled = true
    }
  }, [dataVersion])

  if (loading) {
    return (
      <main
        style={{
          maxWidth: 1400,
          margin: '0 auto',
          padding: '24px 16px',
        }}
      >
        <p style={{ color: 'var(--fw-t3)', fontSize: 'var(--fw-fs-body)' }} role="status">
          Loading AI Engine…
        </p>
      </main>
    )
  }

  if (error !== null) {
    return (
      <main
        style={{
          maxWidth: 1400,
          margin: '0 auto',
          padding: '24px 16px',
        }}
      >
        <p
          style={{ color: 'var(--fw-red)', fontSize: 'var(--fw-fs-body)' }}
          role="alert"
          data-testid="ai-route-error"
        >
          {error}
        </p>
      </main>
    )
  }

  return (
    <>
      <main
        style={{
          maxWidth: 1400,
          margin: '0 auto',
          padding: '24px 16px',
          display: 'flex',
          flexDirection: 'column',
          gap: 16,
        }}
        data-testid="ai-page"
      >
        {/* Page heading + ADR-0043 D2 subtitle */}
        <div>
          <h1
            style={{
              fontSize: 'var(--fw-fs-lg)',
              fontWeight: 'var(--fw-fw-semibold)',
              color: 'var(--fw-t1)',
              margin: 0,
            }}
            data-testid="ai-page-title"
          >
            AI Engine
          </h1>
          <p
            style={{
              fontSize: 'var(--fw-fs-body)',
              color: 'var(--fw-t3)',
              marginTop: 4,
              marginBottom: 0,
            }}
            data-testid="ai-page-subtitle"
          >
            Every verdict, what the model saw, and proof nothing left this box.
          </p>
        </div>

        {/* ── MM #451: Provenance chip legend ─────────────────────────────────
            First-appearance "what do RULE/AI/AI+RULE mean?" key.
            Rendered once per session; user-dismissible (sessionStorage).
            Mounted here (immediately after the subtitle, before panel content)
            so analysts see the key on first visit before encountering chips.
            Kept in its own clearly-delimited block so concurrent MM issues
            that touch AIRoute do not conflict with this section.
            ─────────────────────────────────────────────────────────────────── */}
        <ProvenanceChipLegend />
        {/* ── end MM #451 legend ──────────────────────────────────────────── */}

        {/* Panel 1: Threat summary — RULE-derived template (MK-1 honesty fix).
            health drives the page-level AiStatusChip (Local AI panel state, MF-3 #160).
            aiStatus (threat-derived) is the fallback when health is not yet loaded.
            analyses passed for BUG-1a fix (#447): coverage counts derived from ledger,
            not from the broken ai_status='active' filter. */}
        <AiSummaryPanel
          threats={threats}
          aiStatus={aiStatus}
          health={health}
          analyses={ledger.analyses.length > 0 ? ledger.analyses : null}
        />

        {/* Panel 2: Coverage ledger — AI-specific actor view (MK-3, ADR-0043).
            NOT a duplicate of the Dashboard threat table (ADR-0043 D1).
            ?filter=below-threshold folds in as a coverage facet (#264).
            analyses/analysesHasMore come from the limit=200 ledger fetch — accurate rollup. */}
        <Panel
          title={
            filterParam === 'below-threshold'
              ? 'AI coverage — below threshold'
              : 'AI coverage'
          }
          data-testid="coverage-ledger-panel"
        >
          {/* Below-threshold banner preserved for backward-compat testid (#264). */}
          {filterParam === 'below-threshold' && (
            <div
              data-testid="ai-below-threshold-banner"
              style={{
                padding: '6px 0 10px',
                fontSize: 11,
                color: 'var(--fw-t3)',
              }}
            >
              Showing actors below score threshold (score = 0). These were excluded from the
              dashboard threat actor table.
            </div>
          )}
          <CoverageLedger
            threats={threats}
            analyses={ledger.analyses.length > 0 ? ledger.analyses : null}
            analysesHasMore={ledger.hasMore}
            filterParam={filterParam}
          />
        </Panel>

        {/* Panel 3: Verdict cards — persisted analyses + feedback controls (MK-3/MK-6).
            AI ProvenanceChip on every card (ADR-0035).
            VerdictFeedback (Agree/Disagree) mounted inside each VerdictCard (MK-6).
            AgreementStat headline below the panel title: agreement % + RULE chip (ADR-0045).
            feedbackVersion bumps on every successful submit → AgreementStat re-fetches (D2).
            Empty state when ledger is empty or unavailable (honest degrade).
            Issue #524 fix: rendered eagerly — lazy-mount (useLazyMount) caused this panel
            to never appear when the page fits in a single viewport (sentinel never intersected). */}
        <Panel
          title="AI verdicts"
          data-testid="verdict-cards-panel"
        >
          {/*
           * MK-6 (ADR-0045 D4): agreement headline stat from GET /ai/feedback/summary.
           * refreshKey={feedbackVersion}: re-fetches after every successful analyst submit
           * (D2 fix — stat stays current without a full page reload).
           * Non-fatal degrade: 503 / empty → renders nothing (no broken state).
           */}
          <AgreementStat refreshKey={feedbackVersion} />
          {/*
           * onFeedbackChange threads the callback all the way down:
           * AIRoute.handleFeedbackChange → VerdictCardList → VerdictCard
           * → VerdictFeedback → useFeedbackSubmit onSuccess.
           * MK-11: onRerunComplete threads AIRoute.handleRerunComplete → VerdictCardList
           * → VerdictCard → StageTicker onStreamResult → bumps ledgerVersion.
           */}
          <VerdictCardList
            ledger={ledger}
            onFeedbackChange={handleFeedbackChange}
            onRerunComplete={handleRerunComplete}
          />
        </Panel>

        {/* Panel 4: Model trust — verdict-drift report (MK-9, ADR-0043 D3 block 4).
            Fetches GET /ai/baseline + GET /ai/baseline/drift.
            Shows CLI-triggered drift output; no UI-triggered baseline runs.
            Issue #524 fix: rendered eagerly — lazy-mount (useLazyMount) caused DriftPanel
            to never appear when the page fits in a single viewport. */}
        <DriftPanel />
      </main>
      {/* IP drill-down: handled by EntityPanelProvider / SlideOver (ADR-0037).
          openEntity() is called inside ClickableIp — no local modal state needed. */}
    </>
  )
}
