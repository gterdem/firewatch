/**
 * AsnPanel — ranked ASN list for the "ASN" threat-intelligence lens (issue #533, A2).
 *
 * EARS-2: Ranked top-N list beside the map.
 *   Each row: AS number, AS name, event count, distinct-IP count, blocked %.
 *   Data from GET /analytics/asn (store.get_analytics_asn).
 *
 * EARS-3: Bounded-height — top-N visible rows + "View all / Show less" toggle.
 *   NO inner scrollbar within the card (ADR-0043 D3).
 *
 * EARS-4: Click-to-pivot — clicking the AS{n} label navigates to /logs?q=AS{n}
 *   so the analyst reaches Network Logs filtered to that ASN.
 *
 * EARS-5: Click-to-narrate — "Narrate" button reuses ML-7 narration path
 *   (fetchAsnNarration → GET /analytics/asn/{asn}/narration).
 *   Shows ADR-0035 ProvenanceChip; degrades to rule-only when LLM offline.
 *
 * EARS-6: Zero-egress — all data is on-box (ADR-0022/0047).
 * EARS-7: Pivot/narrate only — no auto-block (ADR-0033 SIEM-now boundary).
 *
 * SECURITY (ADR-0029 D3):
 *   asn, as_name, blocked_pct are API-sourced from attacker-influenced GeoIP data.
 *   All rendered as text nodes — never via dangerouslySetInnerHTML.
 *
 * Generic, no per-source code — any ASN in the data appears here automatically.
 */

import { useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { ProvenanceChip, Spinner } from '../ds'
import { fetchAsnNarration } from '../../api/analytics'
import type { AsnRow, AsnNarrationResult } from '../../api/types'
import LoadingState from '../states/LoadingState'
import ErrorState from '../states/ErrorState'
import EmptyState from '../states/EmptyState'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_VISIBLE = 5

// ---------------------------------------------------------------------------
// Helper — format an ASN label safely (text only, no attacker data)
// ---------------------------------------------------------------------------

function asnLabel(row: AsnRow): string {
  if (row.asn !== null && row.asn !== undefined) {
    return `AS${row.asn}`
  }
  return 'Unresolved ASN'
}

// ---------------------------------------------------------------------------
// Narration state machine (per-row)
// ---------------------------------------------------------------------------

type NarrationState =
  | { phase: 'idle' }
  | { phase: 'loading' }
  | { phase: 'done'; result: AsnNarrationResult }
  | { phase: 'error'; message: string }

// ---------------------------------------------------------------------------
// AsnRowItem — one ranked row with inline narration
// ---------------------------------------------------------------------------

interface AsnRowItemProps {
  row: AsnRow
  rank: number
  aiAvailable: boolean
  onPivot: (row: AsnRow) => void
}

function AsnRowItem({ row, rank, aiAvailable, onPivot }: AsnRowItemProps) {
  const [narration, setNarration] = useState<NarrationState>({ phase: 'idle' })

  const handleNarrate = useCallback(async () => {
    if (row.asn === null) return
    setNarration({ phase: 'loading' })
    try {
      const result = await fetchAsnNarration(row.asn, aiAvailable)
      setNarration({ phase: 'done', result })
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to fetch narration'
      setNarration({ phase: 'error', message: msg })
    }
  }, [row.asn, aiAvailable])

  const handleReset = useCallback(() => setNarration({ phase: 'idle' }), [])

  return (
    <li
      data-testid="asn-row"
      data-asn={row.asn ?? 'unresolved'}
      style={{
        padding: '10px 0',
        borderBottom: '1px solid var(--fw-border)',
      }}
    >
      {/* Header row: rank + ASN label + name + stats + Narrate button */}
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
        {/* Rank badge */}
        <span
          style={{
            fontSize: 'var(--fw-fs-2xs)',
            color: 'var(--fw-t3)',
            minWidth: 18,
            textAlign: 'right',
            paddingTop: 2,
            flexShrink: 0,
          }}
          aria-hidden="true"
        >
          {rank}
        </span>

        {/* Main info */}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            {/* ASN label — EARS-4: click to pivot into Network Logs */}
            <button
              type="button"
              data-testid="asn-pivot-btn"
              onClick={() => onPivot(row)}
              aria-label={`View Network Logs filtered to ${asnLabel(row)}`}
              style={{
                fontSize: 'var(--fw-fs-xs)',
                fontFamily: 'var(--fw-font-mono)',
                fontWeight: 'var(--fw-fw-semibold)',
                color: 'var(--fw-accent)',
                background: 'none',
                border: 'none',
                padding: 0,
                cursor: 'pointer',
                textDecoration: 'underline',
                textDecorationColor: 'rgba(245,158,11,0.4)',
              }}
            >
              {/* asnLabel returns "AS{n}" or literal "Unresolved ASN" — no attacker data */}
              {asnLabel(row)}
            </button>

            {/* AS name — SECURITY: text node only (ADR-0029 D3, attacker-influenced GeoIP) */}
            <span
              style={{
                fontSize: 'var(--fw-fs-xs)',
                color: 'var(--fw-t1)',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }}
              data-testid="asn-name"
            >
              {row.as_name ?? '—'}
            </span>
          </div>

          {/* Stats row */}
          <div
            style={{
              display: 'flex',
              gap: 16,
              marginTop: 4,
              fontSize: 'var(--fw-fs-2xs)',
              color: 'var(--fw-t2)',
              flexWrap: 'wrap',
            }}
          >
            <span data-testid="asn-events">
              <strong style={{ color: 'var(--fw-t1)' }}>{row.total_events.toLocaleString()}</strong>{' '}
              events
            </span>
            <span data-testid="asn-ips">
              <strong style={{ color: 'var(--fw-t1)' }}>{row.distinct_ips}</strong>{' '}
              IP{row.distinct_ips === 1 ? '' : 's'}
            </span>
            <span
              data-testid="asn-blocked-pct"
              style={{ color: row.blocked_pct >= 50 ? 'var(--fw-red)' : 'var(--fw-t2)' }}
            >
              <strong style={{ color: row.blocked_pct >= 50 ? 'var(--fw-red)' : 'var(--fw-t1)' }}>
                {row.blocked_pct}%
              </strong>{' '}
              blocked
            </span>
          </div>
        </div>

        {/* Narrate affordance — only for resolved ASNs (null asn has no narration route).
            Shows the button in idle/loading/error; hides when done (result shown below). */}
        {row.asn !== null && narration.phase !== 'done' && (
          <div style={{ flexShrink: 0 }}>
            {narration.phase === 'idle' && (
              <button
                type="button"
                data-testid="asn-narrate-btn"
                onClick={handleNarrate}
                style={{
                  fontSize: 'var(--fw-fs-2xs)',
                  fontFamily: 'var(--fw-font-ui)',
                  fontWeight: 'var(--fw-fw-semibold)',
                  color: 'var(--fw-accent)',
                  background: 'rgba(245,158,11,0.07)',
                  border: '1px solid rgba(245,158,11,0.22)',
                  borderRadius: 'var(--fw-r-xs)',
                  padding: '3px 10px',
                  cursor: 'pointer',
                }}
              >
                Narrate
                {!aiAvailable && (
                  <span
                    style={{
                      marginLeft: 5,
                      color: 'var(--fw-t3)',
                      fontWeight: 'var(--fw-fw-regular)',
                    }}
                  >
                    (rules)
                  </span>
                )}
              </button>
            )}

            {narration.phase === 'loading' && (
              <div
                style={{ display: 'flex', alignItems: 'center', gap: 6 }}
                data-testid="asn-narration-loading"
              >
                <Spinner label="Generating…" />
                <span style={{ fontSize: 'var(--fw-fs-2xs)', color: 'var(--fw-t3)' }}>
                  {aiAvailable ? 'Running…' : 'Building…'}
                </span>
              </div>
            )}

            {narration.phase === 'error' && (
              <span
                style={{ fontSize: 'var(--fw-fs-2xs)', color: 'var(--fw-red)' }}
                data-testid="asn-narration-error"
              >
                {narration.message}{' '}
                <button
                  type="button"
                  onClick={handleReset}
                  style={{
                    fontSize: 'var(--fw-fs-2xs)',
                    color: 'var(--fw-t2)',
                    background: 'none',
                    border: '1px solid var(--fw-border)',
                    borderRadius: 'var(--fw-r-xs)',
                    padding: '1px 6px',
                    cursor: 'pointer',
                  }}
                >
                  Retry
                </button>
              </span>
            )}
          </div>
        )}
      </div>

      {/* Narration result — rendered BELOW the row when done (no inner scroll) */}
      {narration.phase === 'done' && (
        <div
          data-testid="asn-narration-result"
          style={{ marginTop: 8, paddingLeft: 30 }}
        >
          {/* Header: provenance chip + rule-only notice */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
            <ProvenanceChip
              derivation={narration.result.provenance}
              data-testid="asn-narration-provenance"
            />
            {(narration.result.provenance === 'rule' ||
              narration.result.ai_status === 'unavailable' ||
              narration.result.ai_status === 'skipped') && (
              <span
                style={{ fontSize: 'var(--fw-fs-2xs)', color: 'var(--fw-t3)' }}
                data-testid="asn-narration-rule-only-notice"
              >
                Rules-only · AI offline
              </span>
            )}
          </div>

          {/* Narrative text — SECURITY: LLM text, text node only */}
          <p
            data-testid="asn-narration-text"
            style={{
              fontSize: 'var(--fw-fs-xs)',
              color: 'var(--fw-t1)',
              lineHeight: 1.5,
              margin: '0 0 4px 0',
              whiteSpace: 'pre-wrap',
            }}
          >
            {narration.result.narrative}
          </p>

          {/* Anti-fabrication: grounded-in fields */}
          {narration.result.collected_fields.length > 0 && (
            <div
              style={{ fontSize: 'var(--fw-fs-2xs)', color: 'var(--fw-t3)' }}
              data-testid="asn-narration-fields"
            >
              Grounded in: {narration.result.collected_fields.join(', ')}
            </div>
          )}

          {/* Re-explain button */}
          <button
            type="button"
            onClick={handleNarrate}
            data-testid="asn-narration-reset-btn"
            style={{
              marginTop: 4,
              fontSize: 'var(--fw-fs-2xs)',
              color: 'var(--fw-t3)',
              background: 'none',
              border: '1px solid var(--fw-border)',
              borderRadius: 'var(--fw-r-xs)',
              padding: '1px 6px',
              cursor: 'pointer',
            }}
          >
            Re-explain
          </button>
        </div>
      )}
    </li>
  )
}

// ---------------------------------------------------------------------------
// AsnPanel — main export
// ---------------------------------------------------------------------------

interface AsnPanelProps {
  rows: AsnRow[]
  loading: boolean
  error: string | null
  /** Whether the local AI engine is available (governs narrate button hint). */
  aiAvailable?: boolean
}

export default function AsnPanel({ rows, loading, error, aiAvailable = true }: AsnPanelProps) {
  const navigate = useNavigate()
  const [showAll, setShowAll] = useState(false)

  // EARS-4: navigate to /logs filtered to this ASN.
  // Uses ?q=AS{n} so the existing free-text filter picks it up.
  const handlePivot = useCallback(
    (row: AsnRow) => {
      const query = row.asn !== null ? `AS${row.asn}` : (row.as_name ?? '')
      if (!query) return
      navigate(`/logs?q=${encodeURIComponent(query)}`)
    },
    [navigate],
  )

  if (loading) {
    return (
      <div data-testid="asn-panel-loading">
        <LoadingState label="Loading ASN data…" />
      </div>
    )
  }

  if (error !== null) {
    return (
      <div data-testid="asn-panel-error">
        <ErrorState headline={error} subLine="ASN data unavailable." />
      </div>
    )
  }

  if (rows.length === 0) {
    return (
      <div data-testid="asn-panel-empty">
        <EmptyState
          icon={<span style={{ fontSize: '1.5rem' }}>&#128240;</span>}
          headline="No ASN data yet"
          subLine="ASN data appears once source traffic has been geo-enriched on-box."
        />
      </div>
    )
  }

  const visibleRows = showAll ? rows : rows.slice(0, DEFAULT_VISIBLE)

  return (
    <div data-testid="asn-panel" style={{ marginTop: 8 }}>
      <p
        style={{
          fontSize: 'var(--fw-fs-2xs)',
          color: 'var(--fw-t3)',
          marginBottom: 8,
          marginTop: 0,
        }}
      >
        Top Autonomous Systems by event volume. Click a row to filter Network Logs. Click
        &ldquo;Narrate&rdquo; for a local AI summary.
      </p>

      {/* EARS-3: Ranked list — no inner scrollbar; "View all / Show less" toggle */}
      <ul
        data-testid="asn-list"
        style={{ listStyle: 'none', margin: 0, padding: 0 }}
        aria-label="Ranked ASN list"
      >
        {visibleRows.map((row, i) => (
          <AsnRowItem
            key={row.asn ?? `unresolved-${i}`}
            row={row}
            rank={i + 1}
            aiAvailable={aiAvailable}
            onPivot={handlePivot}
          />
        ))}
      </ul>

      {/* View-all / show-less toggle (EARS-3: no inner scrollbar) */}
      {rows.length > DEFAULT_VISIBLE && (
        <button
          type="button"
          data-testid="asn-view-all-btn"
          onClick={() => setShowAll((v) => !v)}
          style={{
            marginTop: 10,
            fontSize: 'var(--fw-fs-xs)',
            color: 'var(--fw-accent)',
            background: 'none',
            border: 'none',
            cursor: 'pointer',
            padding: 0,
            fontFamily: 'var(--fw-font-ui)',
          }}
        >
          {showAll ? 'Show less' : `View all ${rows.length} ASNs`}
        </button>
      )}
    </div>
  )
}
