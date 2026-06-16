/**
 * ProvenanceChipLegend — first-appearance "what do these chips mean?" key
 * for the AI Engine page (MM #451).
 *
 * Shows a compact one-line legend under the page subtitle on first visit.
 * Dismissible: once dismissed it does not reappear within the same browser
 * session (sessionStorage, per EARS criterion).
 *
 * Copy (EARS-specified):
 *   "RULE = deterministic rule · AI = local model verdict · AI+RULE = both.
 *    Nothing here left your machine."
 *
 * Design constraints:
 *   - Zero layout cost beyond the legend row itself (chip styles are unchanged).
 *   - NOT a modal or nested scrollbar — a small inline row.
 *   - Keyboard-accessible dismiss (button with visible label).
 */

import { useState } from 'react'

const SESSION_KEY = 'fw-provenance-legend-dismissed'

/** Read dismissal state from sessionStorage (safe — returns false if unavailable). */
function isAlreadyDismissed(): boolean {
  try {
    return sessionStorage.getItem(SESSION_KEY) === 'true'
  } catch {
    return false
  }
}

/** Persist dismissal to sessionStorage (safe — no-op if unavailable). */
function persistDismissal(): void {
  try {
    sessionStorage.setItem(SESSION_KEY, 'true')
  } catch {
    // sessionStorage unavailable — dismiss is ephemeral (acceptable degradation).
  }
}

export function ProvenanceChipLegend() {
  const [dismissed, setDismissed] = useState<boolean>(isAlreadyDismissed)

  if (dismissed) return null

  function handleDismiss() {
    persistDismissal()
    setDismissed(true)
  }

  return (
    <div
      data-testid="provenance-legend"
      role="note"
      style={{
        display: 'flex',
        alignItems: 'center',
        gap: 8,
        padding: '5px 10px',
        borderRadius: 'var(--fw-r-sm)',
        background: 'var(--fw-bg-input)',
        border: '1px solid var(--fw-border)',
        fontSize: 'var(--fw-fs-xs)',
        color: 'var(--fw-t2)',
        fontFamily: 'var(--fw-font-ui)',
        lineHeight: 1.5,
      }}
    >
      <span
        data-testid="provenance-legend-text"
        style={{ flex: 1 }}
      >
        <strong style={{ color: 'var(--fw-t1)', fontWeight: 'var(--fw-fw-semibold)' }}>RULE</strong>
        {' = deterministic rule · '}
        <strong style={{ color: 'var(--fw-t1)', fontWeight: 'var(--fw-fw-semibold)' }}>AI</strong>
        {' = local model verdict · '}
        <strong style={{ color: 'var(--fw-t1)', fontWeight: 'var(--fw-fw-semibold)' }}>AI+RULE</strong>
        {' = both. Nothing here left your machine.'}
      </span>
      <button
        data-testid="provenance-legend-dismiss"
        onClick={handleDismiss}
        aria-label="Dismiss provenance legend"
        style={{
          background: 'none',
          border: 'none',
          cursor: 'pointer',
          padding: '0 2px',
          fontSize: 'var(--fw-fs-xs)',
          color: 'var(--fw-t3)',
          lineHeight: 1,
          borderRadius: 'var(--fw-r-xs)',
          flexShrink: 0,
        }}
      >
        ✕
      </button>
    </div>
  )
}
