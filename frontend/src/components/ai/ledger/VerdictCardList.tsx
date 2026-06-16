/**
 * VerdictCardList — verdict card grid with workflow filters and pagination (MM #456).
 *
 * Renders the AI verdicts pane with:
 *   - Filter chips: All / Ungraded / Disagreed / AI-moved (workflow triage affordances)
 *   - Bounded card grid for the current page (no inner scrollbars — ADR-0043 D3)
 *   - Prev/Next pager with "Page N of M" indicator
 *   - "Load more from server" affordance when the ledger has_more (cursor pagination)
 *   - Honest "Showing X of N[+]" count that tracks filters and server-side ceiling
 *
 * Filter semantics (client-side over the loaded set, EARS MM #456):
 *   Ungraded  — no analyst feedback yet (drives the feedback loop)
 *   Disagreed — analyst disagreed with the AI verdict
 *   AI-moved  — score_derivation includes 'ai' (boost fired; AI changed the score)
 *
 * Server cursor pagination (EARS MM #456):
 *   When hasMore=true (server had >200 records), a "Load more from server" button
 *   appears at the bottom. Clicking calls loadMore() from useVerdictLedger which
 *   fetches the next cursor page and appends items. The count updates honestly.
 *
 * ADR-0043 D3 (no inner scrollbar):
 *   Growth is exclusively via pagination and load-more. No overflow:auto on the card list.
 *
 * States driven from useVerdictLedger hook:
 *   loading  — shows a lightweight placeholder (not a spinner-forever)
 *   empty    — honest EmptyState with a call-to-action (no fabricated counts)
 *   error    — concise error note
 *   ok       — filter chips + card grid + pager
 *
 * SECURITY (ADR-0029 D3): all string fields forwarded to VerdictCard are rendered
 * as text nodes. No attacker-controlled string reaches dangerouslySetInnerHTML.
 *
 * D2 reactivity: onFeedbackChange is forwarded to each VerdictCard so that
 * AIRoute receives a callback after any successful submit and can bump
 * feedbackVersion → AgreementStat re-fetches without a page reload.
 */

import { EmptyState } from '../../ds'
import { VerdictCard } from './VerdictCard'
import type { VerdictLedgerState } from './useVerdictLedger'
import { useVerdictFilters, PAGE_SIZE } from './useVerdictFilters'
import type { VerdictFilter } from './useVerdictFilters'

// ---------------------------------------------------------------------------
// Filter chip label map
// ---------------------------------------------------------------------------

const FILTER_LABELS: Record<VerdictFilter, string> = {
  all: 'All',
  ungraded: 'Ungraded',
  disagreed: 'Disagreed',
  'ai-moved': 'AI moved score',
}

const FILTER_EMPTY_MESSAGES: Record<VerdictFilter, string> = {
  all: 'No AI verdicts recorded yet. Run a deep analysis from any actor to generate a verdict.',
  ungraded: 'No ungraded verdicts. Every verdict has been reviewed — great work.',
  disagreed: 'No disagreements recorded. All graded verdicts agree with the AI assessment.',
  'ai-moved': 'No verdicts where the AI moved the score. Run deep analyses to see AI-boosted scores here.',
}

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

/** MM #456: accepts full VerdictLedgerResult or a plain VerdictLedgerState for testability. */
export interface VerdictCardListProps {
  /**
   * Ledger state from useVerdictLedger.
   * Accepts VerdictLedgerResult (includes loadMore) or plain VerdictLedgerState.
   * When loadMore is absent, the "Load more from server" button is not rendered.
   */
  ledger: VerdictLedgerState & { loadMore?: () => void }
  /** Optional: current timestamp injectable for card age tests. */
  now?: number
  /**
   * Called after a successful feedback submit on any card (server confirmed).
   * Forwarded to each VerdictCard → VerdictFeedback → useFeedbackSubmit onSuccess.
   * AIRoute uses this to bump feedbackVersion → AgreementStat re-fetches (D2 fix).
   */
  onFeedbackChange?: () => void
  /**
   * MK-11: called after a Re-run analysis stream completes on any VerdictCard.
   * AIRoute uses this to bump ledgerVersion → useVerdictLedger re-fetches.
   */
  onRerunComplete?: () => void
}

// ---------------------------------------------------------------------------
// Sub-component: VerdictFilterBar
// ---------------------------------------------------------------------------

interface FilterBarProps {
  activeFilter: VerdictFilter
  filterCounts: Record<VerdictFilter, number>
  onSelect: (f: VerdictFilter) => void
}

/**
 * FilterBar — row of toggle chips for workflow triage filters (MM #456).
 * Active chip shows a filled background; badge shows per-filter count.
 * Keyboard accessible: role="group" with focusable chip buttons.
 */
function FilterBar({ activeFilter, filterCounts, onSelect }: FilterBarProps) {
  const filters: VerdictFilter[] = ['all', 'ungraded', 'disagreed', 'ai-moved']

  return (
    <div
      data-testid="verdict-filter-bar"
      role="group"
      aria-label="Filter verdicts by workflow status"
      style={{
        display: 'flex',
        flexWrap: 'wrap',
        gap: 6,
        marginBottom: 12,
      }}
    >
      {filters.map((f) => {
        const isActive = activeFilter === f
        const count = filterCounts[f]
        return (
          <button
            key={f}
            type="button"
            data-testid={`verdict-filter-chip-${f}`}
            aria-pressed={isActive}
            onClick={() => onSelect(f)}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: 5,
              padding: '4px 10px',
              borderRadius: 12,
              border: isActive ? '1px solid var(--fw-accent)' : '1px solid var(--fw-border)',
              background: isActive ? 'var(--fw-accent)' : 'var(--fw-bg-input)',
              color: isActive ? 'var(--fw-bg)' : 'var(--fw-t2)',
              fontSize: 'var(--fw-fs-xs)',
              fontFamily: 'var(--fw-font-ui)',
              cursor: 'pointer',
              transition: 'background 0.1s, border-color 0.1s',
            }}
          >
            {FILTER_LABELS[f]}
            <span
              style={{
                fontSize: 'var(--fw-fs-2xs)',
                fontFamily: 'var(--fw-font-mono)',
                opacity: 0.8,
              }}
            >
              {count}
            </span>
          </button>
        )
      })}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Sub-component: VerdictPager
// ---------------------------------------------------------------------------

interface PagerProps {
  currentPage: number
  pageCount: number
  onPrev: () => void
  onNext: () => void
}

/**
 * VerdictPager — simple prev/next pager with page indicator (MM #456).
 * No inner scrollbar (ADR-0043 D3) — purely navigational.
 */
function VerdictPager({ currentPage, pageCount, onPrev, onNext }: PagerProps) {
  if (pageCount <= 1) return null

  return (
    <div
      data-testid="verdict-pager"
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 10,
        marginTop: 12,
        fontSize: 'var(--fw-fs-xs)',
        color: 'var(--fw-t3)',
        fontFamily: 'var(--fw-font-ui)',
      }}
    >
      <button
        type="button"
        data-testid="verdict-pager-prev"
        aria-label="Previous page"
        disabled={currentPage === 0}
        onClick={onPrev}
        style={{
          padding: '3px 10px',
          border: '1px solid var(--fw-border)',
          borderRadius: 4,
          background: 'var(--fw-bg-input)',
          color: 'var(--fw-t2)',
          cursor: currentPage === 0 ? 'not-allowed' : 'pointer',
          opacity: currentPage === 0 ? 0.4 : 1,
          fontSize: 'var(--fw-fs-xs)',
          fontFamily: 'var(--fw-font-ui)',
        }}
      >
        ← Prev
      </button>

      <span data-testid="verdict-pager-indicator">
        Page {currentPage + 1} of {pageCount}
      </span>

      <button
        type="button"
        data-testid="verdict-pager-next"
        aria-label="Next page"
        disabled={currentPage >= pageCount - 1}
        onClick={onNext}
        style={{
          padding: '3px 10px',
          border: '1px solid var(--fw-border)',
          borderRadius: 4,
          background: 'var(--fw-bg-input)',
          color: 'var(--fw-t2)',
          cursor: currentPage >= pageCount - 1 ? 'not-allowed' : 'pointer',
          opacity: currentPage >= pageCount - 1 ? 0.4 : 1,
          fontSize: 'var(--fw-fs-xs)',
          fontFamily: 'var(--fw-font-ui)',
        }}
      >
        Next →
      </button>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function VerdictCardList({ ledger, now, onFeedbackChange, onRerunComplete }: VerdictCardListProps) {
  const { status, analyses, hasMore, error, loadMore } = ledger

  // Client-side filter + page state over the loaded set (MM #456).
  const {
    activeFilter,
    setFilter,
    pageItems,
    filteredTotal,
    pageCount,
    currentPage,
    prevPage,
    nextPage,
    filterCounts,
  } = useVerdictFilters(analyses)

  // Loading state — lightweight text placeholder (no spinner-forever, ADR-0043 D3).
  if (status === 'loading') {
    return (
      <p
        data-testid="verdict-list-loading"
        style={{ color: 'var(--fw-t3)', fontSize: 'var(--fw-fs-body)' }}
        role="status"
      >
        Loading AI verdicts…
      </p>
    )
  }

  // Error state — concise error note (no fabricated content).
  if (status === 'error') {
    return (
      <p
        data-testid="verdict-list-error"
        style={{ color: 'var(--fw-red)', fontSize: 'var(--fw-fs-body)' }}
        role="alert"
      >
        {error ?? 'AI verdicts could not be loaded.'}
      </p>
    )
  }

  // Empty state — honest, actionable (EARS: "No AI verdicts recorded yet").
  if (status === 'empty' || analyses.length === 0) {
    return (
      <EmptyState
        data-testid="verdict-list-empty"
        title="No AI verdicts recorded yet"
      >
        Run a deep analysis from any actor to generate a verdict. Completed analyses appear
        here automatically.
      </EmptyState>
    )
  }

  // Total loaded count — "N+" when server has more pages not yet fetched.
  const totalLoaded = analyses.length
  const totalDisplay = hasMore ? `${totalLoaded}+` : String(totalLoaded)

  // Showing line tracks the filtered/page context.
  const pageStart = currentPage * PAGE_SIZE + 1
  const pageEnd = Math.min(pageStart + PAGE_SIZE - 1, filteredTotal)
  const filterLabel = activeFilter !== 'all' ? ` (${FILTER_LABELS[activeFilter]})` : ''

  return (
    <div data-testid="verdict-card-list">
      {/* Filter chips — workflow triage (MM #456) */}
      <FilterBar
        activeFilter={activeFilter}
        filterCounts={filterCounts}
        onSelect={setFilter}
      />

      {/* Per-filter empty state (filtered set is empty, but analyses exist) */}
      {filteredTotal === 0 ? (
        <EmptyState
          data-testid="verdict-filter-empty"
          title={`No ${FILTER_LABELS[activeFilter].toLowerCase()} verdicts`}
        >
          {FILTER_EMPTY_MESSAGES[activeFilter]}
        </EmptyState>
      ) : (
        <>
          {/* Bounded card grid — no inner scrollbar (ADR-0043 D3) */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))',
              gap: 12,
            }}
          >
            {pageItems.map((analysis) => (
              <VerdictCard
                key={analysis.id}
                analysis={analysis}
                now={now}
                onFeedbackSubmitted={onFeedbackChange}
                onRerunComplete={onRerunComplete}
              />
            ))}
          </div>

          {/* Pager — prev/next navigation (MM #456, no inner scrollbar) */}
          <VerdictPager
            currentPage={currentPage}
            pageCount={pageCount}
            onPrev={prevPage}
            onNext={nextPage}
          />
        </>
      )}

      {/* Honest count line — tracks filter + page + server ceiling (MM #456) */}
      <p
        data-testid="verdict-list-count"
        style={{
          marginTop: 10,
          fontSize: 'var(--fw-fs-xs)',
          color: 'var(--fw-t3)',
        }}
      >
        {filteredTotal > 0
          ? `Showing ${pageStart}–${pageEnd} of ${filteredTotal}${filterLabel} (${totalDisplay} loaded)`
          : `0 of ${totalDisplay} verdicts match this filter`}
      </p>

      {/* Load more from server — only shown when server has additional pages (EARS MM #456) */}
      {hasMore && (
        <div style={{ marginTop: 8 }}>
          <button
            type="button"
            data-testid="verdict-load-more"
            disabled={status === 'loadingMore'}
            onClick={loadMore}
            style={{
              fontSize: 'var(--fw-fs-xs)',
              color: 'var(--fw-t3)',
              background: 'none',
              border: '1px solid var(--fw-border)',
              borderRadius: 4,
              padding: '4px 10px',
              cursor: status === 'loadingMore' ? 'not-allowed' : 'pointer',
              opacity: status === 'loadingMore' ? 0.6 : 1,
              fontFamily: 'var(--fw-font-ui)',
            }}
          >
            {status === 'loadingMore' ? 'Loading…' : `Load more from server (${totalDisplay} so far)`}
          </button>
        </div>
      )}
    </div>
  )
}
