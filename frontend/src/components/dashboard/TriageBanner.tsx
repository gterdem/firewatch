/**
 * TriageBanner — leads the dashboard with the posture-aware "N actors need
 * a BLOCK decision" / "N actors need review" alert (SIEM / ADR-0033 /
 * issue #159; posture-aware headline — issue #45, ADR-0072 D6).
 *
 * Issue #45 (ADR-0072 D6 / C-1 Phase-A reconciliation) — posture-aware
 * headline + queue-card vocabulary:
 *   - The headline VERB ("BLOCK" vs "review") is derived from the queued
 *     actors' escalation dispositions via `escalationCopy.ts`'s
 *     `triageHeadlineText` — never hard-coded "BLOCK" regardless of posture.
 *     A watch-only deployment (all queued dispositions
 *     not_blocked_passive/detected_no_action/block_status_unknown) gets a
 *     review verb; the word "block" never appears (must-NOT criterion).
 *   - Queue card actions: Investigate (the IP token, unchanged) / Expected —
 *     this is me / Harden (advice-only, ADR-0033 seam). Dismiss moved into an
 *     overflow menu on the chip (D6 maintainer ruling). False positive is
 *     NOT here — it targets a rule, not the actor (lives on the entity-panel
 *     detection row instead, per D6).
 *
 * ADR-0058 D2 (issue #649): banner-worthiness now also considers the escalation
 * axis. Tier 1 (allowed-through) and Tier 2 (block-status-unknown) actors surface
 * even when their numeric score is LOW or MEDIUM. Each chip shows:
 *   - the RULE-tagged justification line (ADR-0035)
 *   - a human-readable disposition + block-status label
 * The empty/calm state shows a 4-tier legend so analysts understand the model.
 *
 * ADR-0058 D2 (issue #649): banner-worthiness now also considers the escalation
 * axis. Tier 1 (allowed-through) and Tier 2 (block-status-unknown) actors surface
 * even when their numeric score is LOW or MEDIUM. Each chip shows:
 *   - the RULE-tagged justification line (ADR-0035)
 *   - a human-readable disposition + block-status label
 * The empty/calm state shows a 4-tier legend so analysts understand the model.
 *
 * Issue #728 — top-N + view-all + tier headers:
 *   - Shows top-N (TOP_ACTORS_DEFAULT = 10) loudest actors by default.
 *   - When more than TOP_N actors are pending, a "view all N" expander reveals
 *     the remaining actors WITHOUT introducing an inner scrollbar (house rule).
 *   - Actors grouped under tier-group headers ("Tier 2 — Flagged (84)").
 *   - Existing (tier asc, score desc) sort is preserved; top-N is the loudest slice.
 *
 * Issue #6 — self-explanatory tier copy: every label/description shown here
 * (chip labels, tier-group headers, the legend) is looked up from
 * `lib/escalationCopy.ts` — the single source of truth for tier wording. This
 * component owns ZERO copy strings of its own; rewording the four tiers is a
 * one-file edit in that module, not a hunt through this component.
 *
 * Issue #43 (ADR-0067 D2/D5) — the observed stratum: an actor whose verdict
 * carries `tier: null` / `disposition: "observed"` never renders as a chip
 * (unless the band axis independently qualifies it — unchanged). Instead,
 * when one or more such actors exist, the banner renders ONE aggregate
 * record line — "N detections on the record from M sources → Network Logs"
 * — built entirely from `deriveObservedRecord` (lib/triageBand.ts), which
 * emits engine integers only (ADR-0035 discipline: no attacker-controlled
 * text ever reaches this line). The line is shown in BOTH the active and
 * calm banner states, and the legend gains one "Observed" row.
 *
 * Issue #55 (ADR-0070 D1/D3/D5) — the attempts headline + pressure strip:
 * when `GET /banner/summary` reports one or more attempts in the state
 * window, `AttemptsHeadline` (components/dashboard/AttemptsHeadline.tsx)
 * renders "N hostile attempts from M actors — S succeeded · K need review"
 * plus a bounded top-N pressure strip, IN THE SAME SLOT the #43
 * ObservedRecordLine occupies — superseding it, not stacking alongside it.
 * When `attemptSummary` is null/absent or reports zero attempts, the #43
 * ObservedRecordLine renders unchanged (no regression to the pre-#55
 * calm-state behavior). This component never computes any of the #55
 * integers itself — `attemptSummary` arrives pre-assembled from the backend
 * (ADR-0070 D3 hard constraint: never count differently than the engine).
 *
 * EARS:
 *   - WHILE one or more actors need a decision → show count + actor chips.
 *   - WHERE banner renders an escalated actor → show justification + disposition.
 *   - WHILE none do → show calm/all-clear state + escalation-tier legend.
 *   - WHILE more than TOP_N actors pending → show top-N + "view all N" expander.
 *   - WHERE actors span multiple tiers → group under tier-group headers.
 *   - WHEN observedRecord is non-null → show the aggregate record line
 *     linking to Network Logs, in the active or calm state alike.
 *
 * Actor chips display each IP via ClickableIp (ADR-0037 / issue #204): clicking
 * or keyboard-activating the IP opens the entity slide-over for that actor, with
 * the dashboard remaining visible behind it.  No "Drill down" button — the IP
 * token IS the drill-down affordance (matches Elastic / Splunk / Sentinel UX).
 *
 * Expected / Harden / Dismiss (overflow) all call onAction(actor, verb) via the
 * action seam (ADR-0033). This component holds ZERO per-verb side-effect
 * logic — it only calls the seam; `HARDEN_ADVICE` copy is shown locally in a
 * popover, but the actual side effect (or lack thereof) lives in the seam.
 *
 * "Needs a decision" = threat_level is CRITICAL or HIGH, OR escalation tier 1/2,
 * AND the actor is not server-suppressed (ADR-0072 D3/D4 `isSuppressed` check —
 * `lib/triageDecisions.ts` — handled by the caller via `pendingActors`).
 *
 * SECURITY (ADR-0029 D3): source_ip and justification are attacker-influenced.
 * Rendered as text nodes only — never via dangerouslySetInnerHTML.
 * ClickableIp uses a <button> with a text child; justification is set as text
 * node content via React's default JSX rendering.
 *
 * ADR-0028 D6: all colors via --fw-* tokens; --fw-triage-active / --fw-triage-calm.
 *
 * House rule: no nested scrollbars (scroll-within-scroll) in the banner or legend.
 */

import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import type { ThreatScore, EscalationVerdict, BannerAttemptSummary } from '../../api/types'
import type { OnAction } from '../../lib/triageActions'
import type { ObservedRecordSummary } from '../../lib/triageBand'
import {
  TIER_COPY,
  OBSERVED_COPY,
  dispositionLabel,
  dispositionColor,
  blockStatusLabel,
  tierGroupLabel,
  triageHeadlineText,
} from '../../lib/escalationCopy'
import ClickableIp from '../entity/ClickableIp'
import { Popover } from '../ds/Popover'
import AttemptsHeadline from './AttemptsHeadline'
import { ExpectedButton, HardenButton, ChipOverflowMenu } from './TriageChipActions'

// ---------------------------------------------------------------------------
// Top-N constant (issue #728)
//
// By default the banner shows at most TOP_ACTORS_DEFAULT chips so the wall
// of 96+ actors is never dumped unread into the analyst's face.
// A "view all N" expander reveals the remainder without an inner scrollbar.
// ---------------------------------------------------------------------------

/** Number of actors shown by default before the "view all" expander. */
export const TOP_ACTORS_DEFAULT = 10

interface TriageBannerProps {
  /** Actors that still need a decision (dismissed actors excluded by caller). */
  pendingActors: ThreatScore[]
  /** The action seam — onAction(actor, verb). Never contains per-verb logic. */
  onAction: OnAction
  /**
   * Aggregate "on the record" summary for observed-stratum actors that did
   * NOT independently earn a banner slot (issue #43, ADR-0067 D5(2)). `null`/
   * `undefined` when there is nothing to report — no aggregate line renders.
   * Computed by `deriveObservedRecord` (lib/triageBand.ts); this component
   * never derives it — it only renders the two integers it is handed.
   */
  observedRecord?: ObservedRecordSummary | null
  /**
   * `GET /banner/summary` result (issue #55) — the attempts headline +
   * pressure strip source of truth. `null`/`undefined` (fetch not yet
   * resolved, or failed — non-fatal per ADR-0015) falls back to the #43
   * `observedRecord` line unchanged. When present with `attempt_count > 0`,
   * supersedes the #43 line in the same slot (see module doc above).
   */
  attemptSummary?: BannerAttemptSummary | null
}

// ---------------------------------------------------------------------------
// Tier-grouping helpers (issue #728)
//
// Actors arrive pre-sorted (tier asc, score desc) from deriveTriageActors.
// groupByTier preserves that order while collecting actors into per-tier
// buckets so TierGroup can render a header row before each bucket.
// ---------------------------------------------------------------------------

interface TierBucket {
  /** Escalation tier number (null for actors without an escalation verdict). */
  tier: number | null
  /** Human-readable label for the group header. */
  label: string
  /** All actors that belong to this tier, in their original sort order. */
  actors: ThreatScore[]
}

/**
 * Groups actors into tier buckets preserving the existing (tier asc, score desc)
 * order. Actors without an escalation verdict go into a bucket with tier = null.
 */
function groupByTier(actors: ThreatScore[]): TierBucket[] {
  const buckets: TierBucket[] = []
  const seen = new Map<number | null, TierBucket>()

  for (const actor of actors) {
    const tier = actor.escalation?.tier ?? null
    if (!seen.has(tier)) {
      const disposition = actor.escalation?.disposition
      const bucket: TierBucket = {
        tier,
        label: tierGroupLabel(tier, disposition),
        actors: [],
      }
      seen.set(tier, bucket)
      buckets.push(bucket)
    }
    seen.get(tier)!.actors.push(actor)
  }

  return buckets
}

export default function TriageBanner({
  pendingActors,
  onAction,
  observedRecord,
  attemptSummary,
}: TriageBannerProps) {
  const count = pendingActors.length

  // Issue #728: view-all expander state.
  // When collapsed only the top-N loudest actors are shown per tier.
  const [expanded, setExpanded] = useState(false)

  // Issue #55: the attempts headline supersedes the #43 ObservedRecordLine in
  // the SAME SLOT only when one or more attempts exist in the state window
  // (checked inline at each render slot below). A null/undefined
  // attemptSummary (fetch pending or failed — non-fatal per ADR-0015) or a
  // zero attempt_count falls back to the #43 line unchanged.

  if (count === 0) {
    // Calm / all-clear state — also show the 4-tier legend so analysts
    // understand escalation semantics (EARS: WHILE queue is empty, show legend).
    return (
      <div
        data-testid="triage-banner-calm"
        role="status"
        aria-label="All clear — no actors need a decision"
        style={{
          background: 'var(--fw-bg-card)',
          border: '1px solid var(--fw-border)',
          borderRadius: 8,
          padding: '10px 16px',
          marginBottom: 16,
        }}
      >
        {/* All-clear headline */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: 10,
            fontSize: 13,
            color: 'var(--fw-t2)',
            marginBottom: 12,
          }}
        >
          <span aria-hidden="true" style={{ fontSize: 16 }}>
            ✓
          </span>
          <span>All clear — no actors need a triage decision.</span>
        </div>

        {/* Issue #55: attempts headline + pressure strip supersedes the #43
            aggregate record line in this slot when attempts exist; otherwise
            the #43 line renders unchanged (EARS: calm state renders unchanged
            when no attempts exist). */}
        {attemptSummary != null && attemptSummary.attempt_count > 0 ? (
          <AttemptsHeadline summary={attemptSummary} />
        ) : (
          observedRecord != null && <ObservedRecordLine record={observedRecord} />
        )}

        {/* 4-tier escalation legend (ADR-0058 §4a) */}
        <EscalationLegend />
      </div>
    )
  }

  // Issue #728: slice to top-N when collapsed; otherwise show all.
  const visibleActors = expanded ? pendingActors : pendingActors.slice(0, TOP_ACTORS_DEFAULT)
  const hiddenCount = count - visibleActors.length
  const tierBuckets = groupByTier(visibleActors)
  const hasMultipleTiers = tierBuckets.length > 1 || tierBuckets.some((b) => b.tier != null)

  // Issue #45 (ADR-0072 D6 / C-1): the headline VERB is derived from the
  // queued actors' escalation dispositions — never hard-coded "BLOCK". See
  // `escalationCopy.ts`'s `triageHeadlineText` for the full derivation.
  const headlineText = triageHeadlineText(
    count,
    pendingActors.map((a) => a.escalation?.disposition),
  )

  return (
    <div
      data-testid="triage-banner-active"
      role="alert"
      aria-label={headlineText}
      style={{
        borderLeft: '4px solid var(--fw-triage-active)',
        background: 'var(--fw-bg-card)',
        border: '1px solid var(--fw-border)',
        borderRadius: 8,
        padding: '12px 16px',
        marginBottom: 16,
      }}
    >
      {/* Banner headline */}
      <div
        style={{
          fontSize: 13,
          fontWeight: 600,
          color: 'var(--fw-red)',
          marginBottom: 10,
          display: 'flex',
          alignItems: 'center',
          gap: 8,
        }}
        data-testid="triage-banner-headline"
      >
        <span aria-hidden="true">⚠</span>
        <span>{headlineText}</span>
      </div>

      {/* Actor chips — grouped by tier with headers (issue #728).
          No inner scrollbar: expander adds DOM rows, no overflow:auto/scroll.
          Actors without escalation get a flat chip row without a tier header. */}
      <div data-testid="triage-banner-chips">
        {hasMultipleTiers
          ? tierBuckets.map((bucket) => (
              <TierGroup
                key={bucket.tier ?? 'none'}
                bucket={bucket}
                onAction={onAction}
              />
            ))
          : tierBuckets.flatMap((bucket) =>
              bucket.actors.map((actor) => (
                <ActorChip key={actor.source_ip} actor={actor} onAction={onAction} />
              )),
            )
        }
      </div>

      {/* View-all expander — only shown when top-N truncation is active (issue #728).
          Adds remaining chips inline (no inner scrollbar — house rule). */}
      {count > TOP_ACTORS_DEFAULT && (
        <div style={{ marginTop: 8 }}>
          <button
            type="button"
            data-testid="triage-view-all"
            aria-expanded={expanded}
            onClick={() => { setExpanded((v) => !v) }}
            style={{
              background: 'none',
              border: '1px solid var(--fw-border)',
              borderRadius: 4,
              padding: '3px 10px',
              fontSize: 11,
              color: 'var(--fw-t2)',
              cursor: 'pointer',
            }}
          >
            {expanded
              ? 'Show fewer'
              : `View all ${count} actors (+${hiddenCount} hidden)`}
          </button>
        </div>
      )}

      {/* Issue #55: attempts headline + pressure strip supersedes the #43
          aggregate record line here too, when attempts exist — rendered
          alongside the active queue: the record stays honest about what
          exists below the bar even while the banner has chips to show. */}
      {attemptSummary != null && attemptSummary.attempt_count > 0 ? (
        <div style={{ marginTop: 8 }}>
          <AttemptsHeadline summary={attemptSummary} />
        </div>
      ) : (
        observedRecord != null && (
          <div style={{ marginTop: 8 }}>
            <ObservedRecordLine record={observedRecord} />
          </div>
        )
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// ObservedRecordLine — the ADR-0067 D5(2) aggregate safety net (issue #43)
//
// Renders exactly one honest sentence built from engine integers handed in
// via `observedRecord` (never derived here — see lib/triageBand.ts). Text
// nodes only (ADR-0029 D3); the link navigates to Network Logs (client-side
// route, no full page reload).
// ---------------------------------------------------------------------------

interface ObservedRecordLineProps {
  record: ObservedRecordSummary
}

function ObservedRecordLine({ record }: ObservedRecordLineProps) {
  const navigate = useNavigate()

  return (
    <div
      data-testid="triage-observed-record"
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 6,
        fontSize: 12,
        color: 'var(--fw-t3)',
        marginBottom: 12,
      }}
    >
      <span>
        {/* Text nodes only — both values are engine integers (ADR-0035 discipline,
            issue #43 hard constraint): a summed event count and a distinct
            source-type count, never attacker-controlled text. */}
        {record.eventCount} detection{record.eventCount === 1 ? '' : 's'} on the record from{' '}
        {record.sourceCount} source{record.sourceCount === 1 ? '' : 's'}
        {' → '}
      </span>
      <button
        type="button"
        data-testid="triage-observed-record-link"
        onClick={() => { navigate('/logs') }}
        style={{
          background: 'none',
          border: 'none',
          padding: 0,
          font: 'inherit',
          color: 'var(--fw-t1)',
          textDecoration: 'underline',
          cursor: 'pointer',
        }}
      >
        Network Logs
      </button>
    </div>
  )
}

// ---------------------------------------------------------------------------
// TierGroup — renders a tier-group header followed by its actor chips (issue #728)
//
// House rule: no inner scrollbar. New chips are appended to the DOM flow as
// normal block elements — no overflow:scroll/auto container is introduced.
// ---------------------------------------------------------------------------

interface TierGroupProps {
  bucket: TierBucket
  onAction: OnAction
}

function TierGroup({ bucket, onAction }: TierGroupProps) {
  return (
    <div
      data-testid="triage-tier-group"
      data-tier={bucket.tier ?? 'none'}
      style={{ marginBottom: 8 }}
    >
      {/* Tier-group header: "Tier N — disposition label (count)" */}
      <div
        data-testid="triage-tier-header"
        style={{
          fontSize: 11,
          fontWeight: 600,
          color: 'var(--fw-t3)',
          textTransform: 'uppercase',
          letterSpacing: '0.04em',
          marginBottom: 4,
        }}
      >
        {bucket.label}
        <span
          style={{
            marginLeft: 6,
            fontWeight: 400,
            color: 'var(--fw-t3)',
          }}
        >
          ({bucket.actors.length})
        </span>
      </div>

      {/* Chips for this tier */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
        {bucket.actors.map((actor) => (
          <ActorChip key={actor.source_ip} actor={actor} onAction={onAction} />
        ))}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// EscalationLegend — teaches the 4-tier model in the empty/calm state
//
// No inner scrollbar (house rule — scroll-within-scroll forbidden).
// Colors via --fw-* tokens only (ADR-0028 D6).
// ---------------------------------------------------------------------------

function EscalationLegend() {
  return (
    <div data-testid="escalation-legend" aria-label="Escalation tier legend">
      <div
        style={{
          fontSize: 11,
          fontWeight: 600,
          color: 'var(--fw-t3)',
          textTransform: 'uppercase',
          letterSpacing: '0.05em',
          marginBottom: 8,
        }}
      >
        Escalation tiers — how FireWatch prioritises alerts
      </div>
      <div
        style={{
          display: 'flex',
          flexDirection: 'column',
          gap: 6,
        }}
      >
        {TIER_COPY.map((row) => (
          <div
            key={row.tier}
            data-testid={`legend-tier-${row.tier}`}
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: 8,
              padding: '6px 8px',
              borderRadius: 5,
              background: 'var(--fw-bg-input)',
              border: '1px solid var(--fw-border-l)',
            }}
          >
            {/* Tier badge */}
            <span
              aria-label={`Tier ${row.tier}`}
              style={{
                flexShrink: 0,
                fontSize: 10,
                fontWeight: 700,
                color: row.color,
                background: 'transparent',
                border: `1px solid ${row.color}`,
                borderRadius: 3,
                padding: '1px 5px',
                lineHeight: 1.6,
                minWidth: 44,
                textAlign: 'center',
              }}
            >
              {/* Text node only — no dangerouslySetInnerHTML (ADR-0029 D3) */}
              {`Tier ${row.tier}`}
            </span>

            <div style={{ flex: 1, minWidth: 0 }}>
              {/* Disposition label */}
              <div
                style={{
                  fontSize: 12,
                  fontWeight: 600,
                  color: row.color,
                  marginBottom: 2,
                }}
              >
                {row.label}
              </div>
              {/* Human-readable explanation */}
              <div
                style={{
                  fontSize: 11,
                  color: 'var(--fw-t3)',
                  lineHeight: 1.4,
                }}
              >
                {row.description}
              </div>
            </div>

            {/* Block status badge */}
            <span
              data-testid={`legend-block-status-${row.tier}`}
              style={{
                flexShrink: 0,
                fontSize: 10,
                color: 'var(--fw-t3)',
                border: '1px solid var(--fw-border-l)',
                borderRadius: 3,
                padding: '1px 5px',
                lineHeight: 1.6,
                whiteSpace: 'nowrap',
              }}
            >
              {blockStatusLabel(row.blockStatus)}
            </span>
          </div>
        ))}

        {/* Observed-stratum legend row (issue #43, ADR-0067 D2) — deliberately NOT
            a 5th tier: no tier number, no fixed block-status badge (an observed
            verdict's block_status reflects whichever truthful state applies).
            Copy sourced from OBSERVED_COPY — this component owns zero copy of
            its own (issue #6 discipline). */}
        <div
          data-testid="legend-tier-observed"
          style={{
            display: 'flex',
            alignItems: 'flex-start',
            gap: 8,
            padding: '6px 8px',
            borderRadius: 5,
            background: 'var(--fw-bg-input)',
            border: '1px solid var(--fw-border-l)',
          }}
        >
          {/* "Observed" badge — no tier number (not a 5th tier, ADR-0067 D2) */}
          <span
            aria-label="Observed"
            style={{
              flexShrink: 0,
              fontSize: 10,
              fontWeight: 700,
              color: OBSERVED_COPY.color,
              background: 'transparent',
              border: `1px solid ${OBSERVED_COPY.color}`,
              borderRadius: 3,
              padding: '1px 5px',
              lineHeight: 1.6,
              minWidth: 44,
              textAlign: 'center',
            }}
          >
            {/* Text node only — no dangerouslySetInnerHTML (ADR-0029 D3) */}
            {OBSERVED_COPY.shortLabel}
          </span>

          <div style={{ flex: 1, minWidth: 0 }}>
            <div
              style={{
                fontSize: 12,
                fontWeight: 600,
                color: OBSERVED_COPY.color,
                marginBottom: 2,
              }}
            >
              {OBSERVED_COPY.label}
            </div>
            <div
              style={{
                fontSize: 11,
                color: 'var(--fw-t3)',
                lineHeight: 1.4,
              }}
            >
              {OBSERVED_COPY.description}
            </div>
          </div>
        </div>

        {/* Explanatory note about partial actors — not a 5th tier row (ADR-0058 Amendment 1 A4).
            Text node only — ADR-0029 D3. No overflow:scroll — house rule. */}
        <div
          data-testid="legend-partial-note"
          style={{
            fontSize: 11,
            color: 'var(--fw-t3)',
            lineHeight: 1.5,
            paddingTop: 4,
            borderTop: '1px solid var(--fw-border-l)',
            marginTop: 2,
          }}
        >
          {'An actor can be '}
          <em>partial</em>
          {': some events were blocked, some are unconfirmed — it’s queued by its loudest events.'}
        </div>

        {/* Why-you-don't-need-to-tune-this note — two-axis model, ADR-0059 D2 (issue #6).
            Text node only — ADR-0029 D3. */}
        <div
          data-testid="legend-zero-tuning-note"
          style={{
            fontSize: 11,
            color: 'var(--fw-t3)',
            lineHeight: 1.5,
            paddingTop: 4,
          }}
        >
          {'These four labels apply automatically — there is no threshold to tune and no way to '}
          {'silence a breach: Tier 1 and Tier 2 always surface here, regardless of score.'}
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// ActorChip — one chip per pending actor
//
// The IP token (ClickableIp) is the drill-down affordance (ADR-0037 / #204).
// Clicking or keyboard-activating it opens the entity slide-over in place —
// no route navigation, no "Drill down" button.
//
// When the actor carries an escalation verdict, the chip also shows:
//   - the RULE-tagged justification (ADR-0035)
//   - the human-readable disposition + block-status label
//
// SECURITY (ADR-0029 D3): justification and source_ip are rendered as text
// nodes only — React's default JSX text rendering never calls dangerouslySetInnerHTML.
// ---------------------------------------------------------------------------

interface ActorChipProps {
  actor: ThreatScore
  onAction: OnAction
}

function ActorChip({ actor, onAction }: ActorChipProps) {
  const esc: EscalationVerdict | null | undefined = actor.escalation

  return (
    <div
      data-testid="triage-actor-chip"
      style={{
        display: 'inline-flex',
        flexDirection: 'row',
        alignItems: 'center',
        gap: 6,
        background: 'var(--fw-bg-input)',
        border: '1px solid var(--fw-border-l)',
        borderRadius: 6,
        padding: '5px 8px',
        fontSize: 12,
      }}
    >
      {/* IP address — ClickableIp opens the entity slide-over on click/Enter/Space.
          Attacker-controlled value rendered as text node only (ADR-0029 D3).
          The token's own data-testid is "clickable-ip" (ADR-0037 contract).
          Kept independent of the popover — IP click is a separate affordance. */}
      <ClickableIp
        value={actor.source_ip}
        style={{ fontSize: 11 }}
        aria-label={`Investigate ${actor.source_ip}`}
      />

      {/* Escalation tier badge — only when a verdict is present */}
      {esc != null && (
        <span
          data-testid="triage-chip-tier"
          aria-label={`Tier ${esc.tier} escalation`}
          style={{
            fontSize: 10,
            fontWeight: 700,
            color: dispositionColor(esc.disposition),
            border: `1px solid ${dispositionColor(esc.disposition)}`,
            borderRadius: 3,
            padding: '1px 5px',
            lineHeight: 1.5,
            whiteSpace: 'nowrap',
          }}
        >
          {/* Text node only — ADR-0029 D3 */}
          {`T${esc.tier}`}
        </span>
      )}

      {/* Disposition label — popover trigger (only when verdict present).
          Clicking opens the popover with block-status + full justification.
          The Popover primitive supplies aria-haspopup/aria-expanded and keyboard operability.
          ADR-0057: reuse ds/Popover; ADR-0029 D3: text nodes only inside. */}
      {esc != null && (
        <Popover
          trigger={
            <span
              style={{
                fontSize: 11,
                fontWeight: 600,
                color: dispositionColor(esc.disposition),
                cursor: 'pointer',
              }}
            >
              {/* Text node only — ADR-0029 D3 */}
              {dispositionLabel(esc.disposition)}
            </span>
          }
          triggerAriaLabel={`Show details for ${dispositionLabel(esc.disposition)}`}
          data-testid="triage-chip-disposition"
          contentTestId="triage-chip-disposition-popover"
          preferAbove={false}
        >
          {/* Popover body: block-status framing + full justification.
              All strings are operator-rule text (ADR-0058) or derived labels —
              rendered as text nodes only (ADR-0029 D3). */}
          <div style={{ padding: '8px 12px', display: 'flex', flexDirection: 'column', gap: 6 }}>
            {/* Block-status framing: "<disposition> · <block status>" */}
            <div
              data-testid="triage-chip-block-status"
              style={{
                fontSize: 11,
                fontWeight: 600,
                color: dispositionColor(esc.disposition),
              }}
            >
              {dispositionLabel(esc.disposition)}
              <span style={{ fontWeight: 400, color: 'var(--fw-t3)' }}>
                {' · '}
                {blockStatusLabel(esc.block_status, esc.disposition_counts)}
              </span>
            </div>

            {/* Per-class count breakdown — only when block_status is "partial" and counts
                are present (ADR-0058 Amendment 1 A2). Text nodes only (ADR-0029 D3). */}
            {esc.block_status === 'partial' && esc.disposition_counts != null && (
              <div
                data-testid="triage-chip-disposition-counts"
                style={{
                  fontSize: 11,
                  color: 'var(--fw-t3)',
                  lineHeight: 1.5,
                }}
              >
                <span>{esc.disposition_counts.blocked}</span>
                {' blocked · '}
                <span>{esc.disposition_counts.alert_unknown}</span>
                {' unconfirmed · '}
                <span>{esc.disposition_counts.allowed}</span>
                {' got through'}
              </div>
            )}

            {/* Full RULE-tagged justification — ADR-0035; text node only (ADR-0029 D3) */}
            <div
              data-testid="triage-chip-justification"
              style={{
                fontSize: 11,
                color: 'var(--fw-t2)',
                lineHeight: 1.4,
                wordBreak: 'break-word',
              }}
            >
              {esc.justification}
            </div>
          </div>
        </Popover>
      )}

      {/* Queue card actions (issue #45, ADR-0072 D6 maintainer ruling):
          Expected / Harden are visible buttons; Dismiss moves into the
          overflow menu. False positive is intentionally NOT here — it
          targets a rule, not the actor (entity-panel detection row instead).
          marginLeft:auto pushes this action cluster to the right.
          Behavior lives in TriageChipActions.tsx (decomposition — this
          component owns the chip LAYOUT, not the action cluster's logic). */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginLeft: 'auto' }}>
        <ExpectedButton actor={actor} onAction={onAction} />
        <HardenButton actor={actor} onAction={onAction} />
        <ChipOverflowMenu actor={actor} onAction={onAction} />
      </div>
    </div>
  )
}
