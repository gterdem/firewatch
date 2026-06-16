/**
 * EscalationPolicyTable — read-only view of the ESCALATION_POLICY registry (issue #650).
 *
 * Fetches GET /escalation/policy on mount.
 * Renders one row per registered detection rule:
 *   - rule_name   — SECURITY (ADR-0029 D3): operator-authored rule names are attacker-adjacent;
 *                   rendered as text nodes only, never via dangerouslySetInnerHTML.
 *   - severity    — declared severity (badge), or "—" when null/undeclared.
 *   - auto_escalate — clear badge/icon: "Auto-escalate" (active) or "—".
 *   - hit_count_24h — live rolling 24h count.
 *
 * READ-ONLY — the registry is finalized at import in the backend. No edit controls.
 *
 * States handled:
 *   loading  — spinner + accessible role="status" text.
 *   error    — error message in an accessible role="alert" region.
 *   empty    — "No detections registered" honest empty state.
 *   populated — table rows (pagination if long).
 *
 * Pagination: up to PAGE_SIZE rows per page to avoid nested scrollbars
 * (project convention — no scroll-within-scroll).
 *
 * ADR-0058 D1 / ADR-0059 D6: read-only policy registry surface.
 */

import { useState, useEffect } from 'react'
import { fetchEscalationPolicy, ApiError } from '../../api/client'
import type { PolicyRow } from '../../api/types'
import { Badge } from '../ds'
import type { BadgeTone } from '../ds'

const PAGE_SIZE = 10

// ---------------------------------------------------------------------------
// Severity badge
// ---------------------------------------------------------------------------

function severityTone(severity: string | null): BadgeTone {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL': return 'critical'
    case 'HIGH': return 'high'
    case 'MEDIUM': return 'medium'
    case 'LOW': return 'low'
    default: return 'neutral'
  }
}

// ---------------------------------------------------------------------------
// Table styles
// ---------------------------------------------------------------------------

const TABLE_STYLE: React.CSSProperties = {
  width: '100%',
  borderCollapse: 'collapse',
  fontFamily: 'var(--fw-font-ui)',
  fontSize: 'var(--fw-fs-sm)',
}

const TH_STYLE: React.CSSProperties = {
  textAlign: 'left',
  padding: '7px 10px',
  fontWeight: 'var(--fw-fw-semibold)' as React.CSSProperties['fontWeight'],
  fontSize: 'var(--fw-fs-xs)',
  color: 'var(--fw-t3)',
  textTransform: 'uppercase' as const,
  letterSpacing: '0.05em',
  borderBottom: '1px solid var(--fw-border)',
}

const TD_STYLE: React.CSSProperties = {
  padding: '7px 10px',
  borderBottom: '1px solid var(--fw-border-l)',
  color: 'var(--fw-t1)',
  verticalAlign: 'middle',
}

const EMPTY_STYLE: React.CSSProperties = {
  padding: 24,
  textAlign: 'center',
  color: 'var(--fw-t3)',
  fontSize: 'var(--fw-fs-sm)',
  fontFamily: 'var(--fw-font-ui)',
}

const PAGINATION_STYLE: React.CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'space-between',
  padding: '8px 10px',
  fontSize: 'var(--fw-fs-xs)',
  color: 'var(--fw-t3)',
  fontFamily: 'var(--fw-font-ui)',
  borderTop: '1px solid var(--fw-border-l)',
}

const PAGE_BTN_STYLE: React.CSSProperties = {
  padding: '3px 10px',
  border: '1px solid var(--fw-border)',
  borderRadius: 4,
  background: 'var(--fw-bg2)',
  color: 'var(--fw-t1)',
  fontFamily: 'var(--fw-font-ui)',
  fontSize: 'var(--fw-fs-xs)',
  cursor: 'pointer',
}

// ---------------------------------------------------------------------------
// Loading / error / empty states
// ---------------------------------------------------------------------------

function TableLoading() {
  return (
    <div
      role="status"
      data-testid="escalation-table-loading"
      style={{
        padding: 24,
        textAlign: 'center',
        color: 'var(--fw-t3)',
        fontSize: 'var(--fw-fs-sm)',
        fontFamily: 'var(--fw-font-ui)',
      }}
    >
      Loading detections…
    </div>
  )
}

function TableError({ message }: { message: string }) {
  return (
    <div
      role="alert"
      data-testid="escalation-table-error"
      style={{
        padding: 16,
        color: 'var(--fw-red)',
        fontSize: 'var(--fw-fs-sm)',
        fontFamily: 'var(--fw-font-ui)',
      }}
    >
      {message}
    </div>
  )
}

// ---------------------------------------------------------------------------
// PolicyRow component
// ---------------------------------------------------------------------------

function PolicyTableRow({ row }: { row: PolicyRow }) {
  return (
    <tr data-testid={`policy-row-${row.rule_name}`}>
      {/* SECURITY: render as text node — rule_name is operator-authored (ADR-0029 D3). */}
      <td style={TD_STYLE}>{row.rule_name}</td>
      <td style={TD_STYLE}>
        {row.severity ? (
          <Badge tone={severityTone(row.severity)} data-testid={`severity-badge-${row.rule_name}`}>
            {row.severity}
          </Badge>
        ) : (
          <span style={{ color: 'var(--fw-t3)' }}>—</span>
        )}
      </td>
      <td style={TD_STYLE}>
        {row.auto_escalate ? (
          <Badge tone="high" data-testid={`auto-escalate-badge-${row.rule_name}`}>
            Auto-escalate
          </Badge>
        ) : (
          <span style={{ color: 'var(--fw-t3)' }}>—</span>
        )}
      </td>
      <td style={{ ...TD_STYLE, textAlign: 'right' as const, fontVariantNumeric: 'tabular-nums' as const }}>
        {row.hit_count_24h}
      </td>
    </tr>
  )
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

export function EscalationPolicyTable() {
  const [rows, setRows] = useState<PolicyRow[] | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [page, setPage] = useState(0)

  useEffect(() => {
    let cancelled = false

    fetchEscalationPolicy()
      .then((resp) => {
        if (cancelled) return
        if (resp === null) {
          setError('Escalation policy service unavailable (503)')
        } else {
          setRows(resp.policy)
        }
        setLoading(false)
      })
      .catch((err: unknown) => {
        if (cancelled) return
        const msg =
          err instanceof ApiError
            ? `Failed to load escalation policy (${err.status})`
            : 'Failed to load escalation policy'
        setError(msg)
        setLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [])

  if (loading) return <TableLoading />
  if (error !== null) return <TableError message={error} />
  if (!rows || rows.length === 0) {
    return (
      <div style={EMPTY_STYLE} data-testid="escalation-table-empty">
        No detections are registered. Install a source plugin to populate the policy.
      </div>
    )
  }

  const totalPages = Math.ceil(rows.length / PAGE_SIZE)
  const pageRows = rows.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)

  return (
    <div data-testid="escalation-policy-table">
      <table style={TABLE_STYLE} aria-label="Escalation policy registry">
        <thead>
          <tr>
            <th style={TH_STYLE}>Detection rule</th>
            <th style={TH_STYLE}>Severity</th>
            <th style={TH_STYLE}>Auto-escalate</th>
            <th style={{ ...TH_STYLE, textAlign: 'right' as const }}>24h hits</th>
          </tr>
        </thead>
        <tbody>
          {pageRows.map((row) => (
            <PolicyTableRow key={row.rule_name} row={row} />
          ))}
        </tbody>
      </table>

      {totalPages > 1 && (
        <div style={PAGINATION_STYLE} data-testid="escalation-table-pagination">
          <span>
            Page {page + 1} of {totalPages}
          </span>
          <div style={{ display: 'flex', gap: 6 }}>
            <button
              type="button"
              style={PAGE_BTN_STYLE}
              onClick={() => setPage((p) => Math.max(0, p - 1))}
              disabled={page === 0}
              aria-label="Previous page"
              data-testid="escalation-table-prev"
            >
              Prev
            </button>
            <button
              type="button"
              style={PAGE_BTN_STYLE}
              onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
              disabled={page >= totalPages - 1}
              aria-label="Next page"
              data-testid="escalation-table-next"
            >
              Next
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
