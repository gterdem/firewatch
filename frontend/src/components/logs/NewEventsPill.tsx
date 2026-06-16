/**
 * NewEventsPill — deferred-load pill for the Network Logs page (ADR-0064 D4).
 *
 * Renders a single "N new events — click to load" pill when there are pending
 * new events.  The pill is the ONE page-level refresh control; clicking it fans
 * out to both the logs table AND the ERG (via the `onClick` handler in
 * LogsRoute).
 *
 * Design decisions:
 *  - Renders nothing (null) when count === 0 — no empty space is claimed.
 *  - Plain count integer only — never displays attacker-controlled text.
 *  - Styled to be non-intrusive: small pill sitting between the filter bar
 *    and the top-pairs panel; does not cover or obscure table rows.
 *
 * SECURITY (ADR-0029 D3): `count` is a plain JS number — never attacker-
 * controlled text. No user-supplied value is rendered in the pill label.
 */

import type { MouseEventHandler } from 'react'

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface NewEventsPillProps {
  /** Number of pending new events accumulated since the last pill click. */
  count: number
  /** Called when the analyst clicks the pill — fans out to table + ERG. */
  onClick: MouseEventHandler<HTMLButtonElement>
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

/**
 * A small deferred-load pill button.  Renders nothing when count is 0.
 *
 * Gmail/Twitter/X pattern (ADR-0064 D4): new data accumulates silently; the
 * analyst loads it on their own terms — never auto-injected mid-investigation.
 */
export default function NewEventsPill({ count, onClick }: NewEventsPillProps) {
  if (count === 0) return null

  return (
    <div
      style={{
        display: 'flex',
        justifyContent: 'center',
        marginBottom: 8,
      }}
      data-testid="new-events-pill-wrapper"
    >
      <button
        type="button"
        onClick={onClick}
        data-testid="new-events-pill"
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 6,
          padding: '4px 14px',
          background: 'var(--fw-accent)',
          color: 'var(--fw-on-accent)',
          border: 'none',
          borderRadius: 'var(--fw-r-full, 9999px)',
          fontFamily: 'var(--fw-font-ui)',
          fontSize: 'var(--fw-fs-sm)',
          fontWeight: 'var(--fw-fw-semibold)',
          cursor: 'pointer',
          boxShadow: '0 1px 4px rgba(0,0,0,0.18)',
          whiteSpace: 'nowrap',
          userSelect: 'none',
        }}
        aria-live="polite"
        aria-atomic="true"
      >
        {/* SECURITY: count is a plain integer — never attacker-controlled text */}
        {count} new event{count !== 1 ? 's' : ''} — click to load
      </button>
    </div>
  )
}
