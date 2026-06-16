/**
 * RiskMovers — Risk Movers sidebar pane (issue #251).
 *
 * Answers: "who is escalating RIGHT NOW?" — top IPs by |score_delta| in the
 * last 1-hour window (the Splunk ES "recent risk changes" pattern).
 *
 * Replaces the former "IP threat scores" card in AiSidebar (lines 181-248),
 * which was a duplicate of the Threat Actors pane (both top-6 by absolute score).
 *
 * Row anatomy (issue #615 — real <table> with colgroup):
 *   | IP            | Score             | Delta/NEW |
 *   | (colspan=3)   Sparkline trajectory            |
 *
 *   <table> layout with a colgroup (IP | Score | Delta/NEW) guarantees column
 *   alignment across rows regardless of IP length, replacing the former
 *   flex-div + marginLeft:auto that distorted on short IPs (issue #615).
 *
 * ScoreBadge rendered in compact variant (issue #616):
 *   Passing variant="compact" suppresses the trailing '?' glyph that was
 *   visible in the default variant when scoreBreakdown is provided — the glyph
 *   is redundant because the whole badge is already a keyboard-accessible
 *   breakdown trigger with cursor/focus-glow/aria-label affordances.
 *   The fix is scoped to RiskMovers to avoid changing the shared ScoreBadge
 *   default (other call sites may rely on the default '?' affordance).
 *
 * Hover slot for LLM rationale is RESERVED for issue #213.
 * Until #213 lands, hover shows only data-derived facts — no AI-attributed text (ADR-0035).
 *
 * Constraints:
 *   - No inner scrollbar (ADR-0017).
 *   - Colors via --fw-* tokens only (ADR-0028 D6).
 *   - All attacker-controlled fields rendered as text nodes (ADR-0029 D3).
 *   - score_delta is data-only; never re-derived or re-scored here (ADR-0036).
 *   - ADR-0035: no AI-attributed text until #213.
 */

import { useEffect, useState } from 'react'
import type { ThreatScore } from '../../api/types'
import type { SeriesPoint } from '../../lib/series'
import { topMovers } from '../../lib/movers'
import { fetchScoreHistory } from '../../api/client'
import ClickableIp from '../entity/ClickableIp'
import { ScoreBadge, Sparkline } from '../ds'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/**
 * Abbreviated time window — appears ONCE in the pane title (AiSidebar: "Risk Movers · 1h").
 * Rows omit it to prevent wrap on narrow widths (issue #331).
 */
export const WINDOW_LABEL = '1h'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface RiskMoversProps {
  threats: ThreatScore[]
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Format a signed delta for display.
 * Examples: +38, -12, — (dash for zero — avoids near-invisible "0" on muted text, issue #577)
 */
function formatDelta(delta: number): string {
  if (delta > 0) return `+${delta}`
  if (delta < 0) return String(delta)
  // delta === 0: no measurable change in window — render as em-dash, not "0"
  // (issue #577: "0" in --fw-t3 muted is ~6px and near-invisible; dash is clearer)
  return '—'
}

/**
 * Color for the signed delta text: red for positive (rising), green for
 * negative (falling), muted for zero/unchanged.
 */
function deltaColor(delta: number): string {
  if (delta > 0) return 'var(--fw-red)'
  if (delta < 0) return 'var(--fw-green)'
  return 'var(--fw-t3)'
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

interface NewBadgeProps {
  'data-testid'?: string
}

/** "NEW" badge for actors with null score_delta (no prior snapshot in window). */
function NewBadge(props: NewBadgeProps) {
  return (
    <span
      data-testid={props['data-testid'] ?? 'new-actor-badge'}
      style={{
        fontSize: 9,
        fontWeight: 700,
        textTransform: 'uppercase',
        letterSpacing: 0.5,
        padding: '1px 5px',
        borderRadius: 3,
        background: 'color-mix(in srgb, var(--fw-blue) 15%, transparent)',
        border: '1px solid color-mix(in srgb, var(--fw-blue) 35%, transparent)',
        color: 'var(--fw-blue)',
        fontFamily: 'var(--fw-font-ui)',
        flexShrink: 0,
      }}
    >
      NEW
    </span>
  )
}

// ---------------------------------------------------------------------------
// MoverRowCard — single entry rendered as two <tr>s inside a <tbody>.
// Issue #615: replaced flex-div + marginLeft:auto with real table rows so
// columns align vertically across all entries regardless of IP length.
// Issue #616: ScoreBadge rendered in compact variant to suppress '?' glyph.
// ---------------------------------------------------------------------------

interface MoverRowProps {
  threat: ThreatScore
  isNew: boolean
  delta: number | undefined
  history: SeriesPoint[]
}

function MoverRowCard({ threat, isNew, delta, history }: MoverRowProps) {
  // The sparkline detail row renders only when there is real history to display.
  // Skipping it when history is absent eliminates the empty dashed-placeholder
  // gap that left large vertical dead-space between entries (#MR walkthrough fix).
  const hasHistory = !isNew && history.length > 0

  return (
    <tbody data-testid="risk-mover-row">
      {/* Primary row: IP | Score | Delta/NEW.
          Always carries the border-bottom so entries remain visually separated
          even when no sparkline detail row follows. */}
      <tr style={{ borderBottom: '1px solid var(--fw-border)' }}>
        {/* IP cell — capped width prevents long IPv6 addresses from dominating the
            row; maxWidth:180 replaces the old maxWidth:0 trick that relied on
            width:100% on the IP <col> (#MR layout fix). Ellipsis still active. */}
        <td style={{ padding: '6px 4px 2px 0', verticalAlign: 'middle', maxWidth: 180, overflow: 'hidden' }}>
          <ClickableIp
            value={threat.source_ip}
            style={{
              fontSize: 11,
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
              minWidth: 0,
              display: 'block',
            }}
          />
        </td>

        {/* Score cell — centered in the flexible middle column (#MR layout fix);
            compact variant suppresses '?' artifact (issue #616) */}
        <td style={{ padding: '6px 4px 2px 4px', verticalAlign: 'middle', whiteSpace: 'nowrap', textAlign: 'center' }}>
          <ScoreBadge
            score={threat.score}
            threatLevel={threat.threat_level}
            scoreBreakdown={threat.score_breakdown}
            variant="compact"
          />
        </td>

        {/* Delta/NEW cell — right-aligned, shrinks to content */}
        <td style={{ padding: '6px 0 2px 4px', verticalAlign: 'middle', textAlign: 'right', whiteSpace: 'nowrap' }}>
          {isNew ? (
            <NewBadge />
          ) : (
            <span
              data-testid="mover-delta"
              style={{
                fontFamily: 'var(--fw-font-mono)',
                fontSize: 11,
                fontWeight: 600,
                color: deltaColor(delta ?? 0),
              }}
            >
              {formatDelta(delta ?? 0)}
            </span>
          )}
        </td>
      </tr>

      {/* Sparkline detail row — rendered ONLY when history is non-empty.
          When history is absent we omit the row entirely; no "no history"
          placeholder is needed because the compact primary row already conveys
          the entry clearly (#MR walkthrough fix). */}
      {hasHistory && (
        <tr>
          <td colSpan={3} style={{ padding: '2px 0 6px 0', verticalAlign: 'top' }}>
            <Sparkline
              series={history}
              label="Score trajectory"
              width={80}
              height={18}
              color={delta !== undefined && delta > 0 ? 'var(--fw-red)' : 'var(--fw-green)'}
              style={{ flexShrink: 0 }}
            />
          </td>
        </tr>
      )}
    </tbody>
  )
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function RiskMovers({ threats }: RiskMoversProps) {
  const movers = topMovers(threats)

  // Fetch score-history for each mover IP (sparkline trajectory).
  // State: Map<ip, SeriesPoint[]> — empty array = loading or no data.
  const [histories, setHistories] = useState<Map<string, SeriesPoint[]>>(new Map())

  useEffect(() => {
    if (movers.length === 0) return

    // Only fetch for actors that have a known delta (new actors don't need sparklines).
    const ipsToFetch = movers
      .filter((m) => !m.isNew)
      .map((m) => m.threat.source_ip)

    if (ipsToFetch.length === 0) return

    let cancelled = false

    // Fire parallel fetches.
    Promise.allSettled(
      ipsToFetch.map((ip) =>
        fetchScoreHistory(ip, 1).then((points) => ({ ip, points })),
      ),
    ).then((results) => {
      if (cancelled) return
      setHistories((prev) => {
        const next = new Map(prev)
        for (const result of results) {
          if (result.status === 'fulfilled') {
            const { ip, points } = result.value
            // ScoreHistoryPoint has same shape as SeriesPoint: { t, value }.
            next.set(ip, points as SeriesPoint[])
          }
        }
        return next
      })
    })

    return () => {
      cancelled = true
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [threats])

  if (movers.length === 0) {
    return (
      <div data-testid="risk-movers-empty" style={{ fontSize: 12, color: 'var(--fw-t3)', padding: '4px 0' }}>
        No score movers in window
      </div>
    )
  }

  return (
    // Table with colgroup: IP | Score | Delta/NEW (issue #615).
    // No overflow: scroll/auto — top-N is capped; inner scrollbar forbidden (ADR-0017).
    <table
      data-testid="risk-movers"
      style={{
        width: '100%',
        borderCollapse: 'collapse',
        tableLayout: 'auto',
      }}
    >
      <colgroup>
        {/* IP column: auto — shrinks to content (capped at maxWidth:180 on the <td>) */}
        <col style={{ width: 'auto' }} />
        {/* Score column: takes the leftover space — keeps the badge visually centred
            between IP and Delta rather than cramming both right (#MR layout fix) */}
        <col style={{ width: '100%' }} />
        {/* Delta/NEW column: auto — shrinks to content */}
        <col style={{ width: 'auto' }} />
      </colgroup>

      {movers.map((m) => (
        <MoverRowCard
          key={m.threat.source_ip}
          threat={m.threat}
          isNew={m.isNew}
          delta={m.delta}
          history={histories.get(m.threat.source_ip) ?? []}
        />
      ))}
    </table>
  )
}
