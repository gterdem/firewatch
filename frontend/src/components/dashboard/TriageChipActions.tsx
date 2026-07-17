/**
 * TriageChipActions — the queue-card action cluster for TriageBanner's
 * ActorChip (issue #45, ADR-0072 D6 maintainer ruling).
 *
 * Extracted out of TriageBanner.tsx (decomposition rule — CLAUDE.md "target
 * components ≤ ~250 lines, one concern each"): TriageBanner.tsx owns the
 * headline + chip layout; this module owns the Expected / Harden / Dismiss
 * button cluster's behavior.
 *
 * D6 placement:
 *   - Expected — this is me: actor-identity suppression (ADR-0070 D6
 *     fail2ban `ignoreip` precedent). Calls onAction(actor, 'expected') only.
 *   - Harden: advice-only (ADR-0033). Calls onAction(actor, 'harden') (the
 *     seam's `harden` branch performs no persistence and no execution) AND
 *     toggles a local, component-owned advisory note sourced entirely from
 *     `escalationCopy.ts`'s `HARDEN_ADVICE` — this module owns zero copy of
 *     its own (issue #6 discipline).
 *   - Dismiss lives in an overflow menu, NOT a bare visible button (D6
 *     maintainer ruling). Built directly on `useDismissableDisclosure` (not
 *     the shared `Popover` primitive) because the menu item needs to call
 *     BOTH onAction and close() from the same click handler — Popover does
 *     not expose `close` to its children (see the hook's own "dismiss button
 *     inside" usage note).
 *   - False positive is intentionally NOT here — it targets a rule, not the
 *     actor (lives on the entity-panel detection row instead, see
 *     components/entity/ip/FalsePositiveButton.tsx).
 *
 * SECURITY (ADR-0029 D3): `actor.source_ip` is attacker-influenced; rendered
 * as text nodes only (aria-label strings / button text) — never
 * dangerouslySetInnerHTML.
 */

import { useState, type CSSProperties } from 'react'
import type { ThreatScore } from '../../api/types'
import type { OnAction } from '../../lib/triageActions'
import { ACTION_LABEL, HARDEN_ADVICE } from '../../lib/escalationCopy'
import { useDismissableDisclosure } from '../ds'

// ---------------------------------------------------------------------------
// Shared button style for the queue-card action cluster (issue #45)
// ---------------------------------------------------------------------------

const CHIP_ACTION_BUTTON_STYLE: CSSProperties = {
  background: 'none',
  border: '1px solid var(--fw-border)',
  borderRadius: 4,
  padding: '1px 6px',
  fontSize: 10,
  color: 'var(--fw-t3)',
  cursor: 'pointer',
  lineHeight: 1.5,
  whiteSpace: 'nowrap',
}

// ---------------------------------------------------------------------------
// ExpectedButton — "Expected — this is me" (ADR-0070 D6 fail2ban precedent)
// ---------------------------------------------------------------------------

interface ExpectedButtonProps {
  actor: ThreatScore
  onAction: OnAction
}

export function ExpectedButton({ actor, onAction }: ExpectedButtonProps) {
  return (
    <button
      type="button"
      data-testid="triage-chip-expected"
      aria-label={`${ACTION_LABEL.expected} — ${actor.source_ip}`}
      onClick={() => onAction(actor, 'expected')}
      style={CHIP_ACTION_BUTTON_STYLE}
    >
      {ACTION_LABEL.expected}
    </button>
  )
}

// ---------------------------------------------------------------------------
// HardenButton — advice-only (ADR-0033), issue #45
// ---------------------------------------------------------------------------

interface HardenButtonProps {
  actor: ThreatScore
  onAction: OnAction
}

export function HardenButton({ actor, onAction }: HardenButtonProps) {
  const [showAdvice, setShowAdvice] = useState(false)

  return (
    <div style={{ position: 'relative' }}>
      <button
        type="button"
        data-testid="triage-chip-harden"
        aria-label={`${ACTION_LABEL.harden} — ${actor.source_ip}`}
        aria-expanded={showAdvice}
        onClick={() => {
          setShowAdvice((v) => !v)
          void onAction(actor, 'harden')
        }}
        style={CHIP_ACTION_BUTTON_STYLE}
      >
        {ACTION_LABEL.harden}
      </button>

      {showAdvice && (
        <div
          data-testid="triage-chip-harden-advice"
          role="note"
          style={{
            position: 'absolute',
            top: '100%',
            right: 0,
            marginTop: 4,
            zIndex: 120,
            width: 240,
            background: 'var(--fw-bg-card)',
            border: '1px solid var(--fw-border-l)',
            borderRadius: 'var(--fw-r-md)',
            boxShadow: 'var(--fw-shadow-popup)',
            padding: '8px 10px',
            fontSize: 11,
            color: 'var(--fw-t2)',
            lineHeight: 1.4,
          }}
        >
          {/* Text node only — ADR-0029 D3; HARDEN_ADVICE is static operator copy. */}
          {HARDEN_ADVICE}
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// ChipOverflowMenu — Dismiss lives here (issue #45, ADR-0072 D6 maintainer
// ruling).
// ---------------------------------------------------------------------------

interface ChipOverflowMenuProps {
  actor: ThreatScore
  onAction: OnAction
}

export function ChipOverflowMenu({ actor, onAction }: ChipOverflowMenuProps) {
  const { open, triggerRef, contentRef, triggerProps, close } = useDismissableDisclosure()

  return (
    <div style={{ position: 'relative' }}>
      <button
        ref={triggerRef as React.RefObject<HTMLButtonElement>}
        type="button"
        data-testid="triage-chip-overflow-trigger"
        aria-label={`More actions for ${actor.source_ip}`}
        aria-haspopup="menu"
        aria-expanded={open}
        {...triggerProps}
        style={{
          ...CHIP_ACTION_BUTTON_STYLE,
          padding: '1px 5px',
        }}
      >
        {/* ⋮ icon — aria-label above describes the action (no visible text needed) */}
        ⋮
      </button>

      {open && (
        <div
          ref={contentRef as React.RefObject<HTMLDivElement>}
          data-testid="triage-chip-overflow-menu"
          role="menu"
          aria-label={`More actions for ${actor.source_ip}`}
          style={{
            position: 'absolute',
            top: '100%',
            right: 0,
            marginTop: 4,
            zIndex: 120,
            minWidth: 120,
            background: 'var(--fw-bg-card)',
            border: '1px solid var(--fw-border-l)',
            borderRadius: 'var(--fw-r-md)',
            boxShadow: 'var(--fw-shadow-popup)',
            padding: '4px 0',
          }}
        >
          <button
            type="button"
            role="menuitem"
            data-testid="triage-chip-dismiss"
            aria-label={`Dismiss ${actor.source_ip}`}
            onClick={() => {
              close()
              onAction(actor, 'dismiss')
            }}
            style={{
              display: 'block',
              width: '100%',
              textAlign: 'left',
              background: 'none',
              border: 'none',
              padding: '5px 12px',
              fontSize: 11,
              color: 'var(--fw-t2)',
              cursor: 'pointer',
            }}
          >
            {ACTION_LABEL.dismiss}
          </button>
        </div>
      )}
    </div>
  )
}
