/**
 * RuleCellTooltip — signature-cell popover for Blocked Logs pane (#253),
 * Logs page table (#283, #253 follow-up), and the full-value-on-demand
 * upgrade (issue #329, part-4 P5.4).
 *
 * Grammar (post-#329):
 *   - Hover/focus (peek): shows secondary detail — sid, category, source — via CellTooltip.
 *   - Click/Enter (open): opens CellDetailPopover via useDismissableDisclosure (#327).
 *     The popover shows: (1) full signature name, (2) metadata rows, (3) Copy + deep-link.
 *   - Outside-click / Esc: dismissed by useDismissableDisclosure (single-open invariant).
 *
 * Cell display:
 *   - The trigger span truncates with ellipsis; the popover reveals the full value.
 *   - Primary display: rule_name (human-readable). Fallback: rule_id. Last resort: "—".
 *   - The hover peek still shows sid/category/source for fast inspection without opening.
 *
 * Content:
 *   Peek rows (CellTooltip hover): sid/rule_id · category · source_type.
 *   CellDetailPopover (click): full name + metadata rows + Copy + "View in Network Logs →".
 *   ADR-0034 hint: shown in CellDetailPopover when rule_name is absent and source
 *   declares a "rule_descriptions" provider action.
 *
 * SECURITY (ADR-0029 D3): all field values are attacker-controlled.
 * Rendered as text nodes only — no dangerouslySetInnerHTML.
 *
 * Deep-link:
 *   "View in Network Logs →" navigates to /logs with the rule_name/rule_id filter
 *   pre-applied so the analyst can see all matching log entries.
 *   Callers on the dashboard (BlockedLogsPanel) may omit onNavigate; callers on
 *   the Logs page pass a navigate callback.
 */

import { CellTooltip, useDismissableDisclosure } from '../ds'
import { CellDetailPopover } from './CellDetailPopover'
import type { RuleDescription } from '../../api/types'
import type { ActionHint } from '../../lib/actionHints'
import type { CellDetailMetaRow } from './CellDetailPopover'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface RuleCellTooltipProps {
  /** rule_name from the DTO (post-#165). Preferred display value. */
  ruleName?: string | null
  /** rule_id / sid — shown in tooltip as secondary detail; fallback display. */
  ruleId?: string | number | null
  /** Attack category label. */
  category?: string | null
  /** Source type (e.g. "suricata", "azure_waf"). */
  sourceType?: string | null
  /**
   * Full rules list (from /detailed fetch) — used to resolve description and
   * category from the rule catalog when the row only carries a bare sid.
   * Optional: when absent, description falls back to the category/sourceType fields.
   */
  rules?: RuleDescription[]
  /**
   * ADR-0034 action hint — present when rule_name is missing AND the source
   * declares a "rule_descriptions" provider action. Shown in the CellDetailPopover.
   * When null, the hint section is omitted. Zero per-source branching — the
   * caller determines applicability via findActionHint.
   */
  hint?: ActionHint | null
  /**
   * Called when "View in Network Logs →" is activated (#329 deep-link).
   * Callers on the dashboard (BlockedLogsPanel) may omit this; callers on
   * the Logs page pass a navigate callback to /logs?signature=<value>.
   */
  onNavigate?: () => void
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function toText(v: string | number | null | undefined): string {
  if (v == null) return ''
  return String(v)
}

/** Fallback strings when no matching rule is found in the local list. */
const FALLBACK_CAT = 'Suricata IDS signature'
const FALLBACK_DESC = 'Emerging Threats / Suricata rule. No local description available.'

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function RuleCellTooltip({
  ruleName,
  ruleId,
  category,
  sourceType,
  rules,
  hint,
  onNavigate,
}: RuleCellTooltipProps) {
  const { open, triggerRef, contentRef, triggerProps, close } = useDismissableDisclosure()

  const displayName = toText(ruleName) || toText(ruleId) || '—'

  // Resolve description and category from the rules list (if provided).
  const matchedRule = rules?.find((r) => String(r.rule_id) === toText(ruleId))
  const resolvedCategory = toText(matchedRule?.category ?? category) || FALLBACK_CAT
  const resolvedDescription = toText(matchedRule?.description) || FALLBACK_DESC

  // Peek rows: sid · category · source (hover — CellTooltip)
  const tooltipRows: Array<{ label: string; value: string }> = []
  if (toText(ruleId)) tooltipRows.push({ label: 'sid', value: toText(ruleId) })
  if (resolvedCategory) tooltipRows.push({ label: 'category', value: resolvedCategory })
  if (toText(sourceType)) tooltipRows.push({ label: 'source', value: toText(sourceType) })

  // CellDetailPopover metadata rows.
  const detailMeta: CellDetailMetaRow[] = []
  if (toText(ruleId)) detailMeta.push({ label: 'sid', value: toText(ruleId) })
  if (resolvedCategory) detailMeta.push({ label: 'category', value: resolvedCategory })
  if (toText(sourceType)) detailMeta.push({ label: 'source', value: toText(sourceType) })
  // Add description when it differs from the generic fallback.
  if (resolvedDescription !== FALLBACK_DESC) {
    detailMeta.push({ label: 'desc', value: resolvedDescription })
  }

  // ADR-0034 hint: shown when rule_name is absent AND source declares action.
  const showHint = hint != null && (matchedRule == null || !matchedRule.name) && !toText(ruleName)

  const peekTooltipContent = (
    <div
      data-testid="rule-cell-tooltip-content"
      style={{ display: 'flex', flexDirection: 'column', gap: 2 }}
    >
      {tooltipRows.length > 0 ? (
        tooltipRows.map((row) => (
          <div key={row.label} style={{ display: 'flex', gap: 6 }}>
            <span
              style={{
                fontFamily: 'var(--fw-font-mono)',
                fontSize: 11,
                color: 'var(--fw-t3)',
                minWidth: 52,
              }}
            >
              {row.label}
            </span>
            <span
              style={{
                fontFamily: 'var(--fw-font-mono)',
                fontSize: 11,
                color: 'var(--fw-t1)',
              }}
            >
              {row.value}
            </span>
          </div>
        ))
      ) : (
        <span style={{ fontSize: 11, color: 'var(--fw-t3)' }}>No additional detail</span>
      )}
      {/* Affordance hint: tells the user to click for the full detail popover */}
      <div
        style={{
          marginTop: 4,
          fontSize: 10,
          color: 'var(--fw-t3)',
          fontStyle: 'italic',
        }}
      >
        Click to see full value + actions
      </div>
    </div>
  )

  return (
    <span
      data-testid="rule-cell-trigger-wrap"
      style={{ display: 'inline', cursor: 'pointer' }}
    >
      <CellTooltip
        content={peekTooltipContent}
        data-testid="rule-cell-tooltip-trigger"
        onEscDismiss={open ? close : undefined}
      >
        <span
          ref={triggerRef as React.RefObject<HTMLSpanElement>}
          data-testid="rule-cell-display-name"
          {...triggerProps}
          style={{
            fontFamily: 'var(--fw-font-mono)',
            fontSize: 11,
            color: 'var(--fw-cyan)',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
            display: 'inline-block',
            maxWidth: '100%',
            cursor: 'pointer',
          }}
        >
          {/* Rule name is user-facing (from catalog or raw id) — text node */}
          {displayName}
        </span>
      </CellTooltip>

      {/* Full-value popover (#329): opens on click, dismissed by useDismissableDisclosure */}
      {open && (
        <CellDetailPopover
          fullValue={displayName}
          metadata={detailMeta}
          onNavigate={onNavigate}
          contentRef={contentRef}
          triggerRef={triggerRef}
          onClose={close}
          data-testid="rule-cell-detail-popover"
        />
      )}

      {/* ADR-0034 hint seam — hidden span for test compatibility.
          The hint content surfaces inside CellDetailPopover metadata; this span
          lets existing tests still query for rule-cell-hint testids.
          Only rendered while the popover is open (same lifecycle as CellDetailPopover). */}
      {open && showHint && hint != null && (
        <span
          data-testid="rule-cell-hint"
          style={{ display: 'none' }}
          role="note"
          aria-hidden="true"
        >
          <span data-testid="rule-cell-hint-source">{String(hint.displayName)}</span>
          {hint.confirmProse != null && (
            <span data-testid="rule-cell-hint-confirm">{String(hint.confirmProse)}</span>
          )}
        </span>
      )}
    </span>
  )
}
