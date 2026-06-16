/**
 * CoverageLedger — AI coverage headline + facets + AI-specific actor list (MK-3).
 *
 * Pane (a) of the AI Engine page (ADR-0043 D3 item 2).
 *
 * MM #453: sortable headers (score/confidence/analysis-age), IP search/filter,
 *          column-header glosses via CellTooltip, sort-basis caption.
 * MM #457: pagination (prev/next + page count) — no inner scrollbar (ADR-0043 D3).
 *
 * Shows:
 *   - Coverage headline: "N of M actors have AI verdicts · K rules-only · …"
 *   - ?filter=below-threshold deep-link (#264 folded in as a coverage facet)
 *   - IP search input + sort-basis caption (sort is never a mystery)
 *   - AI-specific actor columns ONLY: IP (ClickableIp), verdict/threat_level,
 *     ConfidenceLabel, analysis age, ai_status, ScoreBadge.
 *   - NOT the Dashboard's Events/Blocked/Location/Attacks columns (ADR-0043 D1).
 *   - Pagination controls (prev/next + "Page N of M") below the table.
 *
 * All numeric claims come from API fields — never invented.
 * RULE ProvenanceChip on the headline (deterministic arithmetic, ADR-0035).
 *
 * Bounded page height, no inner scrollbars. Empty when threats array is empty.
 *
 * SECURITY (ADR-0029 D3): ip, threat_level, ai_status are attacker-controlled or
 * model-authored. Rendered as text nodes via DS components — never innerHTML.
 */

import type { ThreatScore } from '../../../api/types'
import type { AnalysisSummary } from '../../../api/types'
import { ProvenanceChip, ScoreBadge, ConfidenceLabel, EmptyState, CellTooltip } from '../../ds'
import ClickableIp from '../../entity/ClickableIp'
import {
  computeCoverageRollup,
  formatCoverageHeadline,
  formatAnalysisAge,
  formatAiStatus,
  aiStatusColor,
} from './coverage'
import { useCoverageLedgerTable, PAGE_SIZE } from './useCoverageLedgerTable'
import type { SortColumn, SortState } from './useCoverageLedgerTable'

// ---------------------------------------------------------------------------
// Column header glosses (MM #453 — plain-language one-liners for each column)
// ---------------------------------------------------------------------------

const COLUMN_GLOSSES: Record<string, string> = {
  ip: 'The IP address of the observed threat actor. Click to open the entity detail panel.',
  verdict:
    'The severity call for this actor, with a chip showing who made it (RULE = detection rules, AI = local model, AI+RULE = both contributed).',
  confidence:
    'How sure the local AI model is about its verdict — only meaningful for actors the AI analysed. High ≥ 70%, Medium 40–69%, Low < 40%.',
  score:
    'The current engine risk score (0–100). CRITICAL ≥ 76 · HIGH 51–75 · MEDIUM 26–50 · LOW < 26.',
  ai_status:
    '"Rules-only" is the normal floor — AI runs on demand via deep analysis, not automatically. "AI-analyzed" means AI ran on this actor’s score.',
  analysis_age:
    'How long ago the AI last analysed this actor. "—" means the AI has not looked at this actor yet.',
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

/** Sort direction indicator rendered next to the active column header. */
function SortIndicator({ direction }: { direction: 'asc' | 'desc' }) {
  return (
    <span
      aria-hidden="true"
      style={{ marginLeft: 4, fontSize: 10, opacity: 0.8 }}
    >
      {direction === 'desc' ? '▼' : '▲'}
    </span>
  )
}

/** Sortable column header cell with a CellTooltip gloss (MM #453). */
function SortableHeader({
  column,
  label,
  sort,
  onSort,
  style,
}: {
  column: SortColumn
  label: string
  sort: SortState
  onSort: (col: SortColumn) => void
  style?: React.CSSProperties
}) {
  const isActive = sort.column === column
  return (
    <th
      style={{
        padding: '8px 12px',
        fontWeight: 'var(--fw-fw-medium)',
        cursor: 'pointer',
        userSelect: 'none',
        whiteSpace: 'nowrap',
        color: isActive ? 'var(--fw-t1)' : undefined,
        ...style,
      }}
      onClick={() => onSort(column)}
      aria-sort={
        isActive
          ? sort.direction === 'asc'
            ? 'ascending'
            : 'descending'
          : 'none'
      }
      data-testid={`coverage-col-${column}`}
    >
      <CellTooltip content={<span>{COLUMN_GLOSSES[column]}</span>}>
        <span>
          {label}
          {isActive && <SortIndicator direction={sort.direction} />}
        </span>
      </CellTooltip>
    </th>
  )
}

/** Non-sortable column header with a CellTooltip gloss (MM #453). */
function GlossedHeader({
  glossKey,
  label,
  style,
}: {
  glossKey: string
  label: string
  style?: React.CSSProperties
}) {
  return (
    <th
      style={{
        padding: '8px 12px',
        fontWeight: 'var(--fw-fw-medium)',
        whiteSpace: 'nowrap',
        ...style,
      }}
      data-testid={`coverage-col-${glossKey}`}
    >
      <CellTooltip content={<span>{COLUMN_GLOSSES[glossKey]}</span>}>
        <span>{label}</span>
      </CellTooltip>
    </th>
  )
}

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface CoverageLedgerProps {
  /** All threat actors from GET /threats. */
  threats: ThreatScore[]
  /**
   * Analyses from the ledger (GET /ai/analyses items), or null when the ledger
   * is unavailable (503 — ledger not yet wired). Used for the ledger count.
   */
  analyses: AnalysisSummary[] | null
  /**
   * Whether the ledger API returned has_more=true.
   * When true, the rollup count is a lower bound; headline renders "N+" (ADR-0043 D1).
   */
  analysesHasMore?: boolean
  /**
   * Active filter from ?filter= URL param (#264 deep-link).
   * 'below-threshold' → show only score-0 actors as a coverage facet.
   * null → show all actors.
   */
  filterParam: 'below-threshold' | null
  /** Optional: current timestamp injectable for analysis age display (tests). */
  now?: number
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Look up the most recent ledger analysis for this actor (by IP match).
 * Analyses arrive newest-first from the API; returns the first match.
 */
function findLatestAnalysis(
  ip: string,
  analyses: AnalysisSummary[] | null,
): AnalysisSummary | null {
  if (!analyses || analyses.length === 0) return null
  return analyses.find((a) => a.ip === ip) ?? null
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function CoverageLedger({
  threats,
  analyses,
  analysesHasMore = false,
  filterParam,
  now,
}: CoverageLedgerProps) {
  const rollup = computeCoverageRollup(threats, analyses, analysesHasMore)
  const headline = formatCoverageHeadline(rollup)

  // Apply below-threshold facet filter when deep-link is active.
  const facetThreats =
    filterParam === 'below-threshold'
      ? threats.filter((t) => t.score === 0)
      : threats

  // Sort + search + pagination state (MM #453, #457).
  const table = useCoverageLedgerTable(facetThreats, analyses)

  // Human-readable description of the current sort (never a mystery — #453).
  const sortCaption =
    table.sort.column === 'score'
      ? `Sorted by score, ${table.sort.direction === 'desc' ? 'highest first' : 'lowest first'}`
      : table.sort.column === 'confidence'
        ? `Sorted by confidence, ${table.sort.direction === 'desc' ? 'highest first' : 'lowest first'}`
        : `Sorted by analysis age, ${table.sort.direction === 'desc' ? 'newest first' : 'oldest first'}`

  return (
    <div data-testid="coverage-ledger">
      {/* Coverage headline — RULE chip (deterministic arithmetic, ADR-0035) */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          marginBottom: 12,
          flexWrap: 'wrap',
        }}
      >
        <ProvenanceChip
          derivation="rule"
          data-testid="coverage-provenance-chip"
        />
        <span
          data-testid="coverage-headline"
          style={{
            fontSize: 'var(--fw-fs-body)',
            color: 'var(--fw-t2)',
          }}
        >
          {/* Numbers from real API data — never invented (ADR-0043 D1) */}
          {headline}
        </span>
        {rollup.belowThreshold > 0 && filterParam !== 'below-threshold' && (
          <span
            style={{
              fontSize: 'var(--fw-fs-xs)',
              color: 'var(--fw-t3)',
            }}
          >
            · {rollup.belowThreshold} below threshold
          </span>
        )}
      </div>

      {/* Below-threshold facet indicator — shown when the deep-link filter is active (#264) */}
      {filterParam === 'below-threshold' && (
        <div
          data-testid="coverage-below-threshold-facet"
          style={{
            padding: '6px 10px',
            marginBottom: 10,
            fontSize: 11,
            color: 'var(--fw-t3)',
            background: 'var(--fw-bg-input)',
            border: '1px solid var(--fw-border)',
            borderRadius: 'var(--fw-r-sm)',
          }}
        >
          Coverage facet: actors below sampling threshold (score = 0)
          {rollup.belowThreshold > 0 && ` — ${rollup.belowThreshold} actors`}
        </div>
      )}

      {/* Empty state — no threats observed at all */}
      {facetThreats.length === 0 && (
        <EmptyState
          data-testid="coverage-ledger-empty"
          title="No actors observed"
        >
          {filterParam === 'below-threshold'
            ? 'No actors are below the score threshold.'
            : 'No threat data yet. Events will appear here once the collector processes telemetry.'}
        </EmptyState>
      )}

      {/* AI-specific actor table — sortable, searchable, paginated (no inner scrollbar) */}
      {facetThreats.length > 0 && (
        <div data-testid="coverage-actor-table">
          {/* Search input + sort caption row (MM #453) */}
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 8,
              marginBottom: 8,
              flexWrap: 'wrap',
            }}
          >
            <input
              type="search"
              aria-label="Filter actors by IP"
              placeholder="Filter by IP…"
              value={table.searchQuery}
              onChange={(e) => table.setSearchQuery(e.target.value)}
              data-testid="coverage-search-input"
              style={{
                flex: '0 0 auto',
                width: 220,
                padding: '4px 8px',
                fontSize: 'var(--fw-fs-xs)',
                fontFamily: 'var(--fw-font-ui)',
                background: 'var(--fw-bg-input)',
                border: '1px solid var(--fw-border)',
                borderRadius: 'var(--fw-r-xs)',
                color: 'var(--fw-t1)',
                outline: 'none',
              }}
            />
            {/* Sort caption — states the current order so it is never a mystery (#453) */}
            <span
              data-testid="coverage-sort-caption"
              style={{
                fontSize: 'var(--fw-fs-xs)',
                color: 'var(--fw-t3)',
                fontStyle: 'italic',
              }}
            >
              {sortCaption}
            </span>
          </div>

          {/* No-match message after search filter */}
          {table.filteredCount === 0 && (
            <p
              data-testid="coverage-search-empty"
              style={{
                padding: '8px 0',
                fontSize: 'var(--fw-fs-xs)',
                color: 'var(--fw-t3)',
              }}
            >
              No actors match &ldquo;{table.searchQuery}&rdquo;.
            </p>
          )}

          {table.filteredCount > 0 && (
            <div style={{ overflowX: 'auto' }}>
              <table
                style={{
                  width: '100%',
                  fontSize: 'var(--fw-fs-xs)',
                  borderCollapse: 'collapse',
                  fontFamily: 'var(--fw-font-ui)',
                }}
                aria-label="AI coverage — per-actor verdict summary"
              >
                <thead>
                  <tr
                    style={{
                      borderBottom: '1px solid var(--fw-border)',
                      color: 'var(--fw-t3)',
                      textAlign: 'left',
                    }}
                  >
                    {/* AI-specific columns ONLY — NOT Dashboard duplicates (ADR-0043 D1) */}

                    {/* IP — identifier, not sortable */}
                    <th
                      style={{
                        padding: '8px 12px 8px 0',
                        fontWeight: 'var(--fw-fw-medium)',
                        whiteSpace: 'nowrap',
                      }}
                      data-testid="coverage-col-ip"
                    >
                      <CellTooltip content={<span>{COLUMN_GLOSSES.ip}</span>}>
                        <span>IP</span>
                      </CellTooltip>
                    </th>

                    {/* Verdict — composite chip + label, not directly sortable */}
                    <GlossedHeader
                      glossKey="verdict"
                      label="Verdict"
                      style={{ textAlign: 'center' }}
                    />

                    {/* Confidence — sortable (MM #453) */}
                    <SortableHeader
                      column="confidence"
                      label="Confidence"
                      sort={table.sort}
                      onSort={table.toggleSort}
                    />

                    {/* Score — sortable, default sort column (MM #453) */}
                    <SortableHeader
                      column="score"
                      label="Score"
                      sort={table.sort}
                      onSort={table.toggleSort}
                      style={{ textAlign: 'right' }}
                    />

                    {/* AI status — not sortable */}
                    <GlossedHeader glossKey="ai_status" label="AI status" />

                    {/* Analysis age — sortable (MM #453).
                        #566: paddingRight:16 so the value doesn't press the card right edge. */}
                    <SortableHeader
                      column="analysis_age"
                      label="Analysis age"
                      sort={table.sort}
                      onSort={table.toggleSort}
                      style={{ paddingLeft: 12, paddingRight: 16 }}
                    />
                  </tr>
                </thead>
                <tbody>
                  {table.visibleThreats.map((threat) => {
                    const latestAnalysis = findLatestAnalysis(threat.source_ip, analyses)

                    // Prefer ledger data; fall back to threat-derived fields (ADR-0015 graceful degrade)
                    const confidence = latestAnalysis?.confidence ?? threat.ai_confidence
                    const scoreDerivation =
                      latestAnalysis?.score_derivation ??
                      (threat.ai_status === 'active' ? 'ai' : 'rule')
                    const analysisAge =
                      latestAnalysis?.created_at != null
                        ? formatAnalysisAge(latestAnalysis.created_at, now)
                        : null

                    return (
                      <tr
                        key={threat.source_ip}
                        style={{ borderBottom: '1px solid var(--fw-border)' }}
                        data-testid="coverage-actor-row"
                      >
                        {/* IP — ADR-0037 entity slide-over; text node only (ADR-0029 D3) */}
                        <td style={{ padding: '8px 12px 8px 0' }}>
                          <ClickableIp
                            value={String(threat.source_ip)}
                            aria-label={`Investigate ${threat.source_ip}`}
                          />
                        </td>

                        {/* Verdict / threat_level — AI-specific column (not in Dashboard) */}
                        <td style={{ padding: '8px 12px', textAlign: 'center' }}>
                          <ProvenanceChip
                            derivation={scoreDerivation ?? 'rule'}
                            data-testid="actor-provenance-chip"
                            style={{ marginRight: 4 }}
                          />
                          <span
                            data-testid="actor-threat-level"
                            style={{
                              fontSize: 'var(--fw-fs-xs)',
                              fontWeight: 'var(--fw-fw-medium)',
                              color: 'var(--fw-t2)',
                            }}
                          >
                            {/* threat_level is model-validated — text node (ADR-0029 D3) */}
                            {String(threat.threat_level)}
                          </span>
                        </td>

                        {/* Confidence band — ADR-0036 word-banded */}
                        <td style={{ padding: '8px 12px' }}>
                          <ConfidenceLabel
                            confidence={confidence}
                            data-testid="actor-confidence-label"
                          />
                        </td>

                        {/* Score badge — ADR-0036 banded */}
                        <td style={{ padding: '8px 12px', textAlign: 'right' }}>
                          <ScoreBadge
                            score={threat.score}
                            threatLevel={threat.threat_level}
                            variant="compact"
                            data-testid="actor-score-badge"
                          />
                        </td>

                        {/* AI status — mapped to plain label (BUG-1b fix, #448).
                         * Never renders the raw enum as text (ADR-0029 D3). */}
                        <td style={{ padding: '8px 12px' }}>
                          <span
                            data-testid="actor-ai-status"
                            style={{
                              color: aiStatusColor(threat.ai_status),
                              fontSize: 'var(--fw-fs-xs)',
                            }}
                          >
                            {/* formatAiStatus maps enum to plain label — never the raw value */}
                            {formatAiStatus(threat.ai_status)}
                          </span>
                        </td>

                        {/* Analysis age — from ledger or "—" when no ledger record.
                            #566: paddingRight:16 matches the header gutter. */}
                        <td
                          style={{ padding: '8px 16px 8px 12px', color: 'var(--fw-t3)' }}
                          data-testid="actor-analysis-age"
                        >
                          {analysisAge ?? '—'}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}

          {/* Pagination controls + footer (MM #457) */}
          {table.filteredCount > 0 && (
            <div
              data-testid="coverage-pager"
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: 8,
                padding: '8px 0',
                fontSize: 'var(--fw-fs-xs)',
                color: 'var(--fw-t3)',
              }}
            >
              {/* Prev / page-info / Next */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <button
                  type="button"
                  disabled={!table.hasPrevPage}
                  onClick={table.goPrev}
                  data-testid="coverage-pager-prev"
                  aria-label="Previous page"
                  style={{
                    background: 'var(--fw-bg-input)',
                    border: '1px solid var(--fw-border-l)',
                    borderRadius: 'var(--fw-r-xs)',
                    color: 'var(--fw-t2)',
                    cursor: table.hasPrevPage ? 'pointer' : 'default',
                    opacity: table.hasPrevPage ? 1 : 0.4,
                    fontFamily: 'var(--fw-font-ui)',
                    fontSize: 'var(--fw-fs-xs)',
                    padding: '3px 10px',
                  }}
                >
                  ← Prev
                </button>

                <span
                  data-testid="coverage-pager-info"
                  style={{ fontSize: 'var(--fw-fs-xs)', color: 'var(--fw-t3)' }}
                >
                  Page {table.currentPage} of {table.totalPages}
                  {table.searchQuery && ` (${table.filteredCount} matching)`}
                </span>

                <button
                  type="button"
                  disabled={!table.hasNextPage}
                  onClick={table.goNext}
                  data-testid="coverage-pager-next"
                  aria-label="Next page"
                  style={{
                    background: 'var(--fw-bg-input)',
                    border: '1px solid var(--fw-border-l)',
                    borderRadius: 'var(--fw-r-xs)',
                    color: 'var(--fw-t2)',
                    cursor: table.hasNextPage ? 'pointer' : 'default',
                    opacity: table.hasNextPage ? 1 : 0.4,
                    fontFamily: 'var(--fw-font-ui)',
                    fontSize: 'var(--fw-fs-xs)',
                    padding: '3px 10px',
                  }}
                >
                  Next →
                </button>
              </div>

              {/* Honest count + Dashboard escape hatch (MM #453 #457) */}
              <span
                data-testid="coverage-remaining-count"
                style={{ fontSize: 'var(--fw-fs-xs)', color: 'var(--fw-t3)' }}
              >
                {table.totalPages > 1
                  ? `Showing ${PAGE_SIZE} of ${table.filteredCount} actors${table.searchQuery ? ' matching filter' : ''}. `
                  : `${table.filteredCount} actor${table.filteredCount !== 1 ? 's' : ''}. `}
                <a
                  href="/dashboard"
                  style={{
                    color: 'var(--fw-blue)',
                    textDecoration: 'none',
                  }}
                  data-testid="coverage-dashboard-link"
                >
                  See all on the Dashboard →
                </a>
              </span>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
