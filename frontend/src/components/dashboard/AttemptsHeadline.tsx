/**
 * AttemptsHeadline — the attempts headline + bounded pressure strip
 * (issue #55, ADR-0070 D1 attempt predicate / D3 tier-attribution
 * correction / D5 constants).
 *
 * Renders ONE honest sentence built entirely from `GET /banner/summary`
 * integers — "412 hostile attempts from 87 actors — 0 succeeded · 2 need
 * review" — plus a bounded top-N (N <= 5) pressure strip naming the
 * highest-pressure actors on the record, with no decision demanded.
 *
 * Extends #43's aggregate "N detections on the record" line: this component
 * supersedes that line IN THE SAME SLOT only when `summary.attempt_count > 0`
 * (TriageBanner decides which of the two to render — see its module doc).
 * When no attempts exist, the caller falls back to the #43 ObservedRecordLine
 * unchanged.
 *
 * CORRECTNESS (the crux of #55): every integer here — attempt_count,
 * actor_count, succeeded_count, queue_size, and each row's attempt_count/
 * span_minutes — is rendered VERBATIM from the server. This component
 * contains ZERO counting/derivation logic; it never re-sums, re-ranks, or
 * re-derives "succeeded" from tier client-side (ADR-0070 D3 hard
 * constraint — the banner must never count differently than the engine).
 *
 * Strategist condition (ADR-0070/ADR-0069 conditions, 2026-07-16): the
 * pressure strip's "show me the math" slice is plain text integers — never
 * hover-only (WCAG 1.4.13/2.1.1) — via `escalationCopy.pressureRowText`.
 * `GET /banner/summary` does not yet expose a peak-vs-threshold pair (only
 * attempt_count/span_minutes per row), so the fuller "peak pressure X of Y"
 * affordance is NOT rendered here — see the PR description for the flagged
 * follow-up (additive backend field), never estimated client-side.
 *
 * Bounded top-N, not a worklist: at most 5 rows (server-bounded), no inner
 * scrollbar, no decision verbs (block/investigate/dismiss) on any row — the
 * remainder links to Network Logs instead of being dumped into the DOM.
 *
 * Each row's IP uses ClickableIp (ADR-0037): clicking/keyboard-activating it
 * opens the entity slide-over for that actor — the row's "link to the
 * actor's detail" (issue #55 acceptance criterion).
 *
 * SECURITY (ADR-0029 D3): `source_ip` is attacker-influenced; rendered as a
 * text node only (via ClickableIp, which itself renders a text-node button).
 * ADR-0028 D6: colors via --fw-* tokens only.
 */

import { useNavigate } from 'react-router-dom'
import type { BannerAttemptSummary } from '../../api/types'
import { attemptsHeadlineText, pressureRowText } from '../../lib/escalationCopy'
import ClickableIp from '../entity/ClickableIp'

interface AttemptsHeadlineProps {
  summary: BannerAttemptSummary
}

/** Belt-and-suspenders bound — the server already caps `top_pressure` at 5
 * (issue #55 acceptance criterion), but the strip re-asserts the bound here
 * so a future contract regression can never flood this DOM slot. Slicing an
 * already-ordered, already-server-ranked array is not a re-derivation of any
 * count (ADR-0070 D3 hard constraint is about attempt/actor/succeeded/queue
 * counts and ranking, not about defensively bounding row count). */
const MAX_PRESSURE_ROWS = 5

export default function AttemptsHeadline({ summary }: AttemptsHeadlineProps) {
  const navigate = useNavigate()
  const { attempt_count, actor_count, succeeded_count, queue_size, top_pressure } = summary
  const visiblePressure = top_pressure.slice(0, MAX_PRESSURE_ROWS)

  // Remainder = actors with qualifying attempts NOT shown in the bounded
  // top-N strip (server already bounds top_pressure to <= 5 — this is
  // purely "how many more exist", not a re-ranking of anything).
  const remainder = Math.max(0, actor_count - visiblePressure.length)

  return (
    <div data-testid="attempts-headline-block">
      {/* The headline sentence — text node only, all integers server-provided.
          Red when succeeded_count > 0 (the breach-visible case, ADR-0070 D3):
          a nonzero succeeded_count means the compromise rule IS firing and
          must not read as calm. */}
      <div
        data-testid="attempts-headline"
        style={{
          fontSize: 13,
          fontWeight: 600,
          color: succeeded_count > 0 ? 'var(--fw-red)' : 'var(--fw-t1)',
          marginBottom: visiblePressure.length > 0 ? 8 : 0,
        }}
      >
        {attemptsHeadlineText({ attempt_count, actor_count, succeeded_count, queue_size })}
      </div>

      {/* Pressure strip — bounded top-N (<= 5, MAX_PRESSURE_ROWS above), no
          inner scrollbar (house rule): rows are appended to normal DOM flow. */}
      {visiblePressure.length > 0 && (
        <div
          data-testid="pressure-strip"
          aria-label="Highest-pressure actors on the record"
          style={{ display: 'flex', flexDirection: 'column', gap: 4 }}
        >
          {visiblePressure.map((row) => (
            <div
              key={row.source_ip}
              data-testid="pressure-row"
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                fontSize: 12,
                color: 'var(--fw-t2)',
              }}
            >
              <ClickableIp
                value={row.source_ip}
                style={{ fontSize: 11 }}
                aria-label={`Investigate ${row.source_ip}`}
              />
              {/* Plain-text integers only — no decision verb (block/investigate/
                  dismiss) on this row (issue #55 acceptance criterion). */}
              <span>{pressureRowText(row.attempt_count, row.span_minutes)}</span>
            </div>
          ))}

          {/* Remainder link — the actors beyond the bounded top-N, never
              dumped into the DOM (no nested scrollbar — house rule). */}
          {remainder > 0 && (
            <button
              type="button"
              data-testid="pressure-strip-remainder"
              onClick={() => {
                navigate('/logs')
              }}
              style={{
                background: 'none',
                border: 'none',
                padding: 0,
                marginTop: 2,
                font: 'inherit',
                fontSize: 12,
                color: 'var(--fw-t3)',
                textDecoration: 'underline',
                cursor: 'pointer',
                textAlign: 'left',
                width: 'fit-content',
              }}
            >
              {`+${remainder} more actor${remainder === 1 ? '' : 's'} → Network Logs`}
            </button>
          )}
        </div>
      )}
    </div>
  )
}
