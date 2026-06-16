/**
 * ScoreBadge — score + canonical band label together (ADR-0036 D1).
 *
 * Default variant renders: `Risk 100 · CRITICAL` (format: "Risk {score} · {BAND}").
 * Compact variant renders:  `100` — the severity-colored numeric chip only, for use
 * in dense table cells where the full label (~130 px nowrap) would clip the layout.
 * Band color is always derived from the single ADR-0036 banding function — no
 * re-derivation between variants (issue #263).
 *
 * Band-color contract (ADR-0036):
 *   - Color derives from `threat_level` (the backend's canonical field), NEVER
 *     from re-computing thresholds against the raw score number.
 *   - The known ≥70/≥40 drift in `AiSidebar.scoreColor` is a defect; consumer
 *     issues migrate call sites to ScoreBadge. This component does it correctly.
 *   - `threat_level` is required; if omitted or unknown, the band is normalised
 *     to 'LOW' (safe under-state) rather than crashing.
 *
 * "Why this score" popover (ADR-0036 D3, issue #210):
 *   - When `scoreBreakdown` is provided and non-empty, the WHOLE badge becomes a
 *     keyboard-accessible button (issue #330, part-4 P1). The `?` glyph stays as
 *     a visual hint inside. Clicking/pressing Enter/Space anywhere on the badge
 *     opens the ScoreBreakdownPopover.
 *   - The whole-badge trigger is discoverable via `cursor: pointer` + an amber
 *     border-glow on hover/focus (DS tokens: --fw-accent) + the native tooltip
 *     "Click for score breakdown" (HTML title attribute — shown on hover by the
 *     browser). Precedent: Elastic EUI whole-element-interactive badge.
 *   - The popover is dismissed by Esc, clicking the trigger again (toggle), or
 *     clicking outside the badge+popover. Moving the mouse off the badge does NOT
 *     close it — the popover is portaled above the badge and the pointer naturally
 *     leaves the badge when travelling to the popover (WCAG 1.4.13 hoverable/persistent).
 *   - When `scoreBreakdown` is absent or empty, NO trigger is rendered (graceful
 *     degradation for older cached responses — EARS criterion 2).
 *   - The legacy `onBreakdownClick` prop is preserved unchanged so existing callers
 *     (if any) are not broken. It is independent of `scoreBreakdown`.
 *   - In the compact variant the whole-badge trigger and popover remain fully
 *     functional (issue #263 EARS criterion 1).
 *
 * Whole-badge button semantics (issue #330):
 *   - When `scoreBreakdown` is non-empty, the outer element is rendered as a
 *     `<button>` (not a `<span>`). `aria-label="Why this score?"` is on the button.
 *     `aria-expanded` and `aria-controls` track popover state.
 *   - When `scoreBreakdown` is absent/empty (purely presentational), the outer
 *     element stays `<span role="img">` — no interaction, no tab stop.
 *   - Single accessible button, one tab stop. The `?` glyph is a `<span aria-hidden>`
 *     inside the button — a visual affordance only.
 *
 * Backward compatibility:
 *   - `variant` defaults to `'default'` — existing call sites unaffected.
 *   - Both `scoreBreakdown` and `onBreakdownClick` are optional — existing ScoreBadge
 *     call sites that pass neither remain purely presentational with no behavior change.
 *
 * XSS safety (ADR-0029 D3):
 *   - `score` is rendered as a text node via React (never innerHTML).
 *   - `threat_level` is normalised to one of four static band labels before render.
 *   - Breakdown labels are forwarded to ScoreBreakdownPopover which renders them
 *     as text nodes only.
 *
 * Accessibility:
 *   - Purely presentational (no scoreBreakdown): role="img" with aria-label describing
 *     the full value. aria-label always includes both the score and the band regardless
 *     of variant, so screen readers announce the full context even in compact mode.
 *   - When the badge is the breakdown trigger: role="button" (implicit from <button>),
 *     aria-label leads with the score + band then the action (WCAG 2.5.3 Label-in-Name),
 *     aria-expanded tracks open state, aria-controls points to the popover id.
 *
 * Props:
 *   score            — numeric risk score (0–100).
 *   threatLevel      — backend `threat_level` field ('CRITICAL'|'HIGH'|'MEDIUM'|'LOW').
 *   variant          — 'default' (verbose "Risk N · BAND") or 'compact' (numeric chip
 *                      only). Defaults to 'default'. Use 'compact' in dense table cells.
 *   scoreBreakdown   — optional array from ThreatScore.score_breakdown (issue #209).
 *                      When provided and non-empty, the whole badge is the trigger
 *                      that opens the ScoreBreakdownPopover (issue #330).
 *   onBreakdownClick — legacy optional click handler (preserved for backward compat).
 *   className        — optional extra CSS classes.
 */

import { useId, useCallback, useState } from 'react'
import type React from 'react'
import type { HTMLAttributes } from 'react'
import {
  normaliseThreatLevel,
  severityFgToken,
  severityBgToken,
  severityBorderToken,
} from '../../../lib/provenance'
import type { SeverityBand } from '../../../lib/provenance'
import type { ScoreBreakdownItem } from '../../../api/types'
import { ScoreBreakdownPopover } from './ScoreBreakdownPopover'
import { useDismissableDisclosure } from '../core/useDismissableDisclosure'

export type { SeverityBand }

/** Render mode for ScoreBadge.
 *  - 'default'  — verbose "Risk N · BAND" label; for headers, banners, slide-over.
 *  - 'compact'  — numeric chip only (e.g. "100"); for dense table cells where the
 *                 ~130 px nowrap default would clip the layout (issue #263).
 */
export type ScoreBadgeVariant = 'default' | 'compact'

export interface ScoreBadgeProps extends Omit<HTMLAttributes<HTMLSpanElement>, 'children'> {
  /**
   * Numeric risk score (0–100). Rendered as a text node — never interpolated
   * into HTML markup.
   */
  score: number
  /**
   * Backend `threat_level` field. The band label and color are derived from
   * this value — not recomputed from the score number (ADR-0036 D1).
   * Case-insensitive; unknown values fall back to 'LOW'.
   */
  threatLevel: string
  /**
   * Render variant:
   *   - 'default' (the default) — "Risk N · BAND" verbose form.
   *   - 'compact' — numeric chip only; identical band color; whole-badge trigger still works.
   * Use 'compact' in dense table cells to recover ~80 px per row.
   */
  variant?: ScoreBadgeVariant
  /**
   * Additive contributing factors from ThreatScore.score_breakdown (issue #209).
   * When provided and non-empty, the WHOLE badge becomes a clickable trigger that
   * opens the ScoreBreakdownPopover (issue #330). The `?` glyph remains as a
   * visual hint inside. When absent or empty, the badge is purely presentational
   * (graceful degradation — ADR-0036 D3 / #210 EARS 2).
   */
  scoreBreakdown?: ScoreBreakdownItem[]
  /**
   * Legacy optional "why this score" click handler — preserved for backward
   * compatibility. Independent of scoreBreakdown: both can coexist.
   * When provided without scoreBreakdown, a small "?" trigger is appended inside
   * the badge wrapper (legacy path, unchanged).
   */
  onBreakdownClick?: () => void
  /** Optional extra CSS classes on the outer wrapper. */
  className?: string
}

export function ScoreBadge({
  score,
  threatLevel,
  variant = 'default',
  scoreBreakdown,
  onBreakdownClick,
  className = '',
  style,
  ...rest
}: ScoreBadgeProps) {
  const band: SeverityBand = normaliseThreatLevel(threatLevel)

  const fg = severityFgToken(band)
  const bg = severityBgToken(band)
  const border = severityBorderToken(band)

  const popoverId = useId()

  // Whether the breakdown popover trigger should be shown.
  const hasBreakdown =
    scoreBreakdown !== undefined && scoreBreakdown !== null && scoreBreakdown.length > 0

  // Hover / focus state for the amber border-glow affordance (issue #330).
  // React state is used because inline styles cannot address :hover/:focus-visible.
  const [isHovered, setIsHovered] = useState(false)
  const [isFocused, setIsFocused] = useState(false)

  // Disclosure state — routes through useDismissableDisclosure (#327):
  //   outside-click dismiss, Esc dismiss + focus return, single-open invariant.
  // triggerRef is attached directly to the <button> so the hook can detect
  // "inside trigger" clicks for the re-click toggle, AND restores focus on Esc
  // (since returnFocusRef is not provided the hook defaults to triggerRef).
  // See AiEnginePill.tsx ~L109 for the same wiring pattern (issue #356).
  // contentRef is forwarded to ScoreBreakdownPopover so outside-click detection
  // works correctly for the portal-rendered popover div.
  const {
    open: popoverOpen,
    triggerRef: disclosureTriggerRef,
    contentRef: popoverContentRef,
    triggerProps: disclosureTriggerProps,
    close: disclosureClose,
  } = useDismissableDisclosure()

  const handleTriggerClick = useCallback(() => {
    // useDismissableDisclosure's onClick handler toggles open; we also need to
    // fire the legacy handler when provided.
    onBreakdownClick?.()
  }, [onBreakdownClick])

  const handleClose = useCallback(() => {
    disclosureClose()
  }, [disclosureClose])

  // Update hover state on mouse-leave. Do NOT close the popover here — the
  // popover is portaled above the badge so the pointer naturally crosses the
  // badge boundary when travelling to the popover content. Closing on mouseleave
  // causes instant-close before the user can read the breakdown (issue #356).
  // Dismiss is handled exclusively by: second click, outside-click, and Esc
  // (all owned by useDismissableDisclosure).
  const handleMouseLeave = useCallback(() => {
    setIsHovered(false)
  }, [])

  // When only onBreakdownClick is provided (legacy, no scoreBreakdown), show
  // the trigger button with the legacy click handler only.
  const showLegacyTrigger = !hasBreakdown && onBreakdownClick !== undefined

  const isCompact = variant === 'compact'

  // Shared inline style for the outer badge element.
  // When hovered or focused AND hasBreakdown: add amber border-glow (--fw-accent).
  const showGlow = hasBreakdown && (isHovered || isFocused)
  const badgeStyle = {
    display: 'inline-flex',
    alignItems: 'center',
    gap: 4,
    padding: isCompact ? '1px 6px' : '1px 8px',
    borderRadius: 'var(--fw-r-md)',
    fontSize: 'var(--fw-fs-2xs)',
    fontWeight: 'var(--fw-fw-bold)',
    fontFamily: 'var(--fw-font-mono)',
    letterSpacing: 'var(--fw-ls-tight)',
    border: '1px solid',
    lineHeight: 1.6,
    whiteSpace: 'nowrap' as const,
    background: bg,
    color: fg,
    borderColor: border,
    position: 'relative' as const,
    // Affordance: amber glow on hover/focus when interactive (issue #330, ADR-0028 D6).
    // --fw-accent is the FireWatch signature amber (index.css).
    ...(showGlow && { boxShadow: '0 0 0 2px var(--fw-accent)' }),
    ...style,
  }

  // Visual content shared by both variants — rendered inside the outer element.
  const badgeContent = (
    <>
      {isCompact ? (
        /* Compact — numeric chip only: just the score number */
        <span>{score}</span>
      ) : (
        /* Default — verbose: "Risk N · BAND" */
        <>
          <span style={{ fontFamily: 'var(--fw-font-mono)' }}>
            Risk{' '}{score}
          </span>
          <span aria-hidden="true" style={{ opacity: 0.6 }}>·</span>
          <span>{band}</span>
        </>
      )}

      {/* "?" visual hint — shown only in the default (verbose) variant.
          In compact variant the score number is already minimal; appending "?"
          produces an awkward "2 ?" at low scores (issue #577). The badge button
          itself carries aria-label so screen readers get the full context in
          both variants. Sighted-user discoverability in compact mode comes from
          cursor:pointer + amber border-glow on hover/focus (issue #330). */}
      {hasBreakdown && !isCompact && (
        <span
          aria-hidden="true"
          style={{
            marginLeft: 2,
            color: fg,
            fontSize: 'var(--fw-fs-2xs)',
            fontFamily: 'var(--fw-font-ui)',
            fontWeight: 'var(--fw-fw-semibold)',
            lineHeight: 1,
            opacity: 0.75,
          }}
        >
          ?
        </span>
      )}
    </>
  )

  // ---------------------------------------------------------------------------
  // Interactive path: whole badge is the button (hasBreakdown=true, issue #330)
  // ---------------------------------------------------------------------------
  if (hasBreakdown) {
    return (
      <>
        <button
          ref={disclosureTriggerRef as React.RefObject<HTMLButtonElement>}
          type="button"
          aria-label={`Risk score ${score}, severity ${band} — show score breakdown`}
          aria-expanded={popoverOpen}
          aria-controls={popoverId}
          title="Click for score breakdown"
          data-band={band}
          data-score={score}
          data-variant={variant}
          className={`fw-score-badge ${className}`}
          onMouseEnter={() => setIsHovered(true)}
          onMouseLeave={handleMouseLeave}
          onFocus={() => setIsFocused(true)}
          onBlur={() => setIsFocused(false)}
          {...disclosureTriggerProps}
          onClick={(e) => {
            // Run the disclosure toggle (single-open + outside-click wiring) first,
            // then call the legacy handler if provided.
            disclosureTriggerProps.onClick(e)
            handleTriggerClick()
          }}
          style={{
            cursor: 'pointer',
            textDecoration: 'none',
            textAlign: 'left' as const,
            ...badgeStyle,
          }}
          {...rest}
        >
          {badgeContent}
        </button>

        {/* Breakdown popover — portal to document.body via triggerRef (#266 fix).
            contentRef wires the portal into useDismissableDisclosure's outside-click
            detection (#327 single-open invariant). */}
        <ScoreBreakdownPopover
          id={popoverId}
          items={scoreBreakdown}
          open={popoverOpen}
          onClose={handleClose}
          triggerRef={disclosureTriggerRef}
          contentRef={popoverContentRef}
        />
      </>
    )
  }

  // ---------------------------------------------------------------------------
  // Presentational path: outer span (no scoreBreakdown, backward compat)
  // ---------------------------------------------------------------------------
  return (
    <span
      role="img"
      aria-label={`Risk score ${score}, severity ${band}`}
      data-band={band}
      data-score={score}
      data-variant={variant}
      className={`fw-score-badge ${className}`}
      style={badgeStyle}
      {...rest}
    >
      {isCompact ? (
        /* Compact — numeric chip only: just the score number */
        <span>{score}</span>
      ) : (
        /* Default — verbose: "Risk N · BAND" */
        <>
          <span style={{ fontFamily: 'var(--fw-font-mono)' }}>
            Risk{' '}{score}
          </span>
          <span aria-hidden="true" style={{ opacity: 0.6 }}>·</span>
          <span>{band}</span>
        </>
      )}

      {/* Legacy trigger (onBreakdownClick without scoreBreakdown) */}
      {showLegacyTrigger && (
        <button
          type="button"
          aria-label="Why this score?"
          onClick={onBreakdownClick}
          style={{
            marginLeft: 2,
            background: 'transparent',
            border: 'none',
            color: fg,
            cursor: 'pointer',
            fontSize: 'var(--fw-fs-2xs)',
            fontFamily: 'var(--fw-font-ui)',
            fontWeight: 'var(--fw-fw-semibold)',
            lineHeight: 1,
            padding: '0 2px',
            opacity: 0.75,
          }}
        >
          ?
        </button>
      )}
    </span>
  )
}
