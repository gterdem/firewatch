/**
 * CaseTimeline — displays the case's linked event/analysis references.
 *
 * ADR-0053 D2: timeline is assembled at read time from case_events (ADR-0041
 * discipline). Each row shows the ref_kind, ref_id, and timestamp. The
 * component self-fetches GET /cases/{id}/timeline on mount.
 *
 * EARS-2: timeline of related events/alerts assembled at read time.
 *
 * SECURITY (ADR-0029 D3): ref_id is stored attacker-derived data.
 * Rendered as text node only — never via dangerouslySetInnerHTML.
 */

import { useState, useEffect } from 'react'
import { getCaseTimeline } from '../../../api/cases'
import type { TimelineEntry } from '../../../api/cases'
import { Spinner } from '../../ds'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatDate(iso: string): string {
  try {
    return new Date(iso).toLocaleString(undefined, {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit',
    })
  } catch {
    return iso
  }
}

function kindLabel(refKind: string): string {
  switch (refKind) {
    case 'security_event': return 'Event'
    case 'ai_analysis':    return 'AI analysis'
    default:               return refKind
  }
}

// ---------------------------------------------------------------------------
// TimelineRow
// ---------------------------------------------------------------------------

function TimelineRow({ entry }: { entry: TimelineEntry }) {
  return (
    <div
      data-testid="timeline-entry"
      role="listitem"
      style={{
        display: 'flex',
        alignItems: 'flex-start',
        gap: 10,
        padding: '8px 0',
        borderBottom: '1px solid var(--fw-border)',
      }}
    >
      {/* Kind pill */}
      <span
        style={{
          flexShrink: 0,
          fontSize: 'var(--fw-fs-xs)',
          fontWeight: 'var(--fw-fw-medium)',
          color: 'var(--fw-t2)',
          background: 'var(--fw-bg-input)',
          border: '1px solid var(--fw-border-l)',
          borderRadius: 'var(--fw-r-sm)',
          padding: '1px 6px',
          fontFamily: 'var(--fw-font-ui)',
          textTransform: 'uppercase',
          letterSpacing: 'var(--fw-ls-tight)',
          lineHeight: 1.6,
          whiteSpace: 'nowrap',
        }}
      >
        {kindLabel(entry.ref_kind)}
      </span>

      {/* ref_id as text node (ADR-0029 D3) */}
      <span
        data-testid="timeline-ref-id"
        style={{
          fontFamily: 'var(--fw-font-mono)',
          fontSize: 'var(--fw-fs-sm)',
          color: 'var(--fw-t1)',
          flex: 1,
          wordBreak: 'break-all',
        }}
      >
        {entry.ref_id}
      </span>

      {/* timestamp */}
      <span
        style={{
          flexShrink: 0,
          fontSize: 'var(--fw-fs-xs)',
          color: 'var(--fw-t3)',
          fontFamily: 'var(--fw-font-ui)',
          whiteSpace: 'nowrap',
        }}
      >
        {formatDate(entry.created_at)}
      </span>
    </div>
  )
}

// ---------------------------------------------------------------------------
// CaseTimeline
// ---------------------------------------------------------------------------

export interface CaseTimelineProps {
  caseId: number
}

export function CaseTimeline({ caseId }: CaseTimelineProps) {
  const [entries, setEntries] = useState<TimelineEntry[] | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false

    // All setState calls in the async IIFE body to satisfy react-hooks/set-state-in-effect.
    void (async () => {
      if (!cancelled) {
        setLoading(true)
        setError(null)
      }
      try {
        const data = await getCaseTimeline(caseId)
        if (!cancelled) {
          setEntries(data?.entries ?? [])
          setLoading(false)
        }
      } catch {
        if (!cancelled) {
          setError('Could not load timeline.')
          setLoading(false)
        }
      }
    })()

    return () => { cancelled = true }
  }, [caseId])

  if (loading) {
    return <Spinner label="Loading timeline…" />
  }

  if (error !== null) {
    return (
      <p
        role="alert"
        style={{ color: 'var(--fw-red)', fontSize: 'var(--fw-fs-sm)' }}
      >
        {error}
      </p>
    )
  }

  if (!entries || entries.length === 0) {
    return (
      <p
        data-testid="timeline-empty"
        style={{
          color: 'var(--fw-t3)',
          fontSize: 'var(--fw-fs-sm)',
          fontStyle: 'italic',
        }}
      >
        No linked events yet. Link an event or analysis to populate the timeline.
      </p>
    )
  }

  return (
    <div
      data-testid="case-timeline"
      role="list"
      aria-label="Case timeline"
    >
      {entries.map((entry) => (
        <TimelineRow key={entry.id} entry={entry} />
      ))}
    </div>
  )
}
