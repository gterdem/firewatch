/**
 * TriageBanner — leads the dashboard with the "N actors need a BLOCK decision"
 * alert (SIEM / ADR-0033 / issue #159).
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
 *   - Actors grouped under tier-group headers ("Tier 2 — Unconfirmed (84)").
 *   - Existing (tier asc, score desc) sort is preserved; top-N is the loudest slice.
 *
 * Issue #6 — self-explanatory tier copy: every label/description shown here
 * (chip labels, tier-group headers, the legend) is looked up from
 * `lib/escalationCopy.ts` — the single source of truth for tier wording. This
 * component owns ZERO copy strings of its own; rewording the four tiers is a
 * one-file edit in that module, not a hunt through this component.
 *
 * EARS:
 *   - WHILE one or more actors need a decision → show count + actor chips.
 *   - WHERE banner renders an escalated actor → show justification + disposition.
 *   - WHILE none do → show calm/all-clear state + escalation-tier legend.
 *   - WHILE more than TOP_N actors pending → show top-N + "view all N" expander.
 *   - WHERE actors span multiple tiers → group under tier-group headers.
 *
 * Actor chips display each IP via ClickableIp (ADR-0037 / issue #204): clicking
 * or keyboard-activating the IP opens the entity slide-over for that actor, with
 * the dashboard remaining visible behind it.  No "Drill down" button — the IP
 * token IS the drill-down affordance (matches Elastic / Splunk / Sentinel UX).
 *
 * Dismiss chips call onAction(actor, 'dismiss') via the action seam (ADR-0033).
 * This component holds ZERO per-verb side-effect logic — it only calls the seam.
 *
 * "Needs a decision" = threat_level is CRITICAL or HIGH, OR escalation tier 1/2,
 * AND the actor has not been dismissed (isDismissed check handled by caller via
 * `pendingActors`).
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
import type { ThreatScore, EscalationVerdict } from '../../api/types'
import type { OnAction } from '../../lib/triageActions'
import {
  TIER_COPY,
  dispositionLabel,
  dispositionColor,
  blockStatusLabel,
  tierGroupLabel,
} from '../../lib/escalationCopy'
import ClickableIp from '../entity/ClickableIp'
import { Popover } from '../ds/Popover'

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

export default function TriageBanner({ pendingActors, onAction }: TriageBannerProps) {
  const count = pendingActors.length

  // Issue #728: view-all expander state.
  // When collapsed only the top-N loudest actors are shown per tier.
  const [expanded, setExpanded] = useState(false)

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

  return (
    <div
      data-testid="triage-banner-active"
      role="alert"
      aria-label={`${count} actor${count === 1 ? '' : 's'} need a block decision`}
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
        <span>
          {count} actor{count === 1 ? '' : 's'} need{count === 1 ? 's' : ''} a BLOCK decision
        </span>
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

      {/* Dismiss — icon button (✕); marginLeft:auto pushes it to the right.
          aria-label carries the IP so screen readers announce the target.
          Component holds ZERO per-verb side-effect logic — calls seam only. */}
      <button
        type="button"
        data-testid="triage-chip-dismiss"
        aria-label={`Dismiss ${actor.source_ip}`}
        onClick={() => onAction(actor, 'dismiss')}
        style={{
          background: 'none',
          border: '1px solid var(--fw-border)',
          borderRadius: 4,
          padding: '1px 5px',
          fontSize: 10,
          color: 'var(--fw-t3)',
          cursor: 'pointer',
          marginLeft: 'auto',
          lineHeight: 1.5,
        }}
      >
        {/* ✕ icon — aria-label above describes the action (no visible text needed) */}
        ✕
      </button>
    </div>
  )
}
