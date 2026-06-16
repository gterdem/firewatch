/**
 * TopPairsPanel — ML-3 (#431, EARS-4), updated for #667 WS4a.
 *
 * Renders the top (source_ip → destination_ip) pairs from GET /logs/top-pairs.
 * Clicking a pair cross-filters the Logs table by applying both source IP and
 * destination IP filters (calls onSelectPair which updates the parent LogsFilter).
 *
 * #667: Shows the top 5 by default with a "View all" affordance that reveals
 * the rest (pairs 6–N) via an inline expand toggle. No nested scrollbar.
 *
 * SECURITY (ADR-0029 D3): source_ip and destination_ip are attacker-controlled
 * telemetry — rendered as React text nodes only, never via dangerouslySetInnerHTML.
 *
 * Modular/source-agnostic: no per-source branching — canonical fields for all sources.
 */

import { useState } from 'react'
import type { TopPairsRow } from '../../api/types'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Number of pairs shown by default before the "View all" affordance. */
const DEFAULT_TOP_N = 5

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface TopPairsPanelProps {
  /** Top pairs list from GET /logs/top-pairs. */
  pairs: TopPairsRow[]
  /** Called when user clicks a pair row to cross-filter the table. */
  onSelectPair: (sourceIp: string, destinationIp: string) => void
  /** Loading state — show skeleton when true. */
  loading?: boolean
}

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

/** Shared cell style. */
const CELL: React.CSSProperties = {
  padding: '5px 10px',
  fontSize: 'var(--fw-fs-sm)',
  fontFamily: 'var(--fw-font-mono)',
  color: 'var(--fw-t1)',
  borderBottom: '1px solid var(--fw-border)',
  whiteSpace: 'nowrap',
  overflow: 'hidden',
  textOverflow: 'ellipsis',
  verticalAlign: 'middle',
}

const HEADER: React.CSSProperties = {
  padding: '6px 10px',
  textAlign: 'left',
  fontWeight: 'var(--fw-fw-semibold)',
  fontSize: 'var(--fw-fs-2xs)',
  color: 'var(--fw-t3)',
  textTransform: 'uppercase',
  letterSpacing: 'var(--fw-ls-table)',
  borderBottom: '1px solid var(--fw-border)',
  whiteSpace: 'nowrap',
  background: 'var(--fw-bg-card)',
}

// ---------------------------------------------------------------------------
// PairsTable — renders a slice of pair rows
// ---------------------------------------------------------------------------

function PairsTable({
  pairs,
  onSelectPair,
}: {
  pairs: TopPairsRow[]
  onSelectPair: (src: string, dst: string) => void
}) {
  return (
    <div style={{ overflowX: 'auto' }}>
      <table
        style={{
          width: '100%',
          borderCollapse: 'collapse',
          tableLayout: 'fixed',
          fontFamily: 'var(--fw-font-mono)',
        }}
      >
        <thead>
          <tr>
            <th style={HEADER}>Source IP</th>
            <th style={HEADER}>Destination IP</th>
            {/* #566: right-align + 16px trailing gutter so value doesn't touch card border */}
            <th style={{ ...HEADER, textAlign: 'right', paddingRight: 16, width: 72 }}>Events</th>
          </tr>
        </thead>
        <tbody>
          {pairs.map((row, idx) => (
            <tr
              key={`${row.source_ip}-${row.destination_ip}-${idx}`}
              style={{ cursor: 'pointer', background: 'transparent' }}
              className="fw-log-row"
              data-testid="top-pairs-row"
              onClick={() => onSelectPair(row.source_ip, row.destination_ip)}
              tabIndex={0}
              role="button"
              aria-label={`Filter by ${row.source_ip} → ${row.destination_ip}`}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault()
                  onSelectPair(row.source_ip, row.destination_ip)
                }
              }}
            >
              {/* SECURITY: attacker-controlled fields — text nodes only */}
              <td style={CELL}>{String(row.source_ip)}</td>
              <td style={CELL}>{String(row.destination_ip)}</td>
              {/* #566: explicit paddingRight:16 so the count doesn't press the card border */}
              <td
                style={{
                  ...CELL,
                  textAlign: 'right',
                  paddingRight: 16,
                  color: 'var(--fw-t3)',
                  fontVariantNumeric: 'tabular-nums',
                }}
              >
                {row.count.toLocaleString()}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function TopPairsPanel({
  pairs,
  onSelectPair,
  loading = false,
}: TopPairsPanelProps) {
  // Whether the "View all" expanded section is visible (#667).
  const [expanded, setExpanded] = useState(false)

  // Split into top-5 and remainder
  const topFive = pairs.slice(0, DEFAULT_TOP_N)
  const rest = pairs.slice(DEFAULT_TOP_N)
  const hasMore = rest.length > 0

  return (
    <div
      data-testid="top-pairs-panel"
      style={{
        background: 'var(--fw-bg-card)',
        border: '1px solid var(--fw-border)',
        borderRadius: 8,
        overflow: 'hidden',
        marginBottom: 12,
      }}
    >
      {/* Panel header */}
      <div
        style={{
          padding: '8px 12px',
          borderBottom: '1px solid var(--fw-border)',
          display: 'flex',
          alignItems: 'center',
          gap: 8,
        }}
      >
        <span
          style={{
            fontFamily: 'var(--fw-font-ui)',
            fontSize: 'var(--fw-fs-sm)',
            fontWeight: 'var(--fw-fw-semibold)',
            color: 'var(--fw-t1)',
          }}
        >
          Top Source → Destination Pairs
        </span>
        <span
          style={{
            fontFamily: 'var(--fw-font-mono)',
            fontSize: 'var(--fw-fs-2xs)',
            color: 'var(--fw-t3)',
          }}
        >
          click to filter
        </span>
      </div>

      {loading ? (
        <div
          data-testid="top-pairs-loading"
          style={{
            padding: '12px 16px',
            fontFamily: 'var(--fw-font-ui)',
            fontSize: 'var(--fw-fs-sm)',
            color: 'var(--fw-t3)',
          }}
        >
          Loading…
        </div>
      ) : pairs.length === 0 ? (
        <div
          data-testid="top-pairs-empty"
          style={{
            padding: '12px 16px',
            fontFamily: 'var(--fw-font-ui)',
            fontSize: 'var(--fw-fs-sm)',
            color: 'var(--fw-t3)',
          }}
        >
          No pairs with destination IP data
        </div>
      ) : (
        <>
          {/* Top 5 rows — always visible */}
          <PairsTable pairs={topFive} onSelectPair={onSelectPair} />

          {/* "View all" toggle and expanded section (#667).
              Inline expand — no nested scrollbar (ADR requirement). */}
          {hasMore && (
            <>
              <div
                style={{
                  padding: '6px 12px',
                  borderTop: '1px solid var(--fw-border)',
                }}
              >
                <button
                  type="button"
                  data-testid="top-pairs-view-all-btn"
                  onClick={() => setExpanded((prev) => !prev)}
                  aria-expanded={expanded}
                  style={{
                    background: 'none',
                    border: 'none',
                    padding: 0,
                    cursor: 'pointer',
                    fontFamily: 'var(--fw-font-ui)',
                    fontSize: 'var(--fw-fs-2xs)',
                    color: 'var(--fw-accent)',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 4,
                  }}
                >
                  {expanded
                    ? `Show less ▲`
                    : `View all ${pairs.length} pairs ▼`}
                </button>
              </div>

              {/* Expanded rows — rest of pairs beyond top 5 */}
              {expanded && (
                <div data-testid="top-pairs-expanded">
                  <PairsTable pairs={rest} onSelectPair={onSelectPair} />
                </div>
              )}
            </>
          )}
        </>
      )}
    </div>
  )
}
