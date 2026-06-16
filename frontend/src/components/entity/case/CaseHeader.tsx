/**
 * CaseHeader — title, status/disposition chip, and timestamps for a case file.
 *
 * ADR-0053 D2: "Header: case id, title, status/disposition chip
 * (true-positive / false-positive / benign / open), created/updated timestamps."
 *
 * Issue #757 (EARS-3): header leads with the title/subject; the numeric id is
 * shown as secondary metadata (dimmed mono, trailing on the title row).
 *
 * SECURITY (ADR-0029 D3): title and subject are operator text, rendered as
 * text nodes only — no dangerouslySetInnerHTML.
 */

import type { CaseFile, CaseDisposition } from '../../../api/cases'
import { Badge } from '../../ds'

// ---------------------------------------------------------------------------
// Disposition chip tone mapping
// ---------------------------------------------------------------------------

function dispositionTone(d: CaseDisposition): 'critical' | 'low' | 'medium' | 'neutral' {
  switch (d) {
    case 'true-positive':  return 'critical'
    case 'false-positive': return 'low'
    case 'benign':         return 'medium'
    case 'open':
    default:               return 'neutral'
  }
}

function dispositionLabel(d: CaseDisposition): string {
  switch (d) {
    case 'true-positive':  return 'True positive'
    case 'false-positive': return 'False positive'
    case 'benign':         return 'Benign'
    case 'open':           return 'Open'
    default:               return String(d)
  }
}

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

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export interface CaseHeaderProps {
  caseFile: CaseFile
}

export function CaseHeader({ caseFile }: CaseHeaderProps) {
  return (
    <div data-testid="case-header" style={{ marginBottom: 16 }}>
      {/* Title (primary) + Case ID (secondary metadata, trailing) — EARS-3 issue #757 */}
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginBottom: 4 }}>
        <h2
          data-testid="case-title"
          style={{
            fontSize: 'var(--fw-fs-h3)',
            fontWeight: 'var(--fw-fw-semibold)',
            color: 'var(--fw-t1)',
            margin: 0,
            lineHeight: 1.3,
          }}
        >
          {caseFile.title}
        </h2>
        <span
          data-testid="case-id"
          style={{
            fontSize: 'var(--fw-fs-xs)',
            color: 'var(--fw-t3)',
            fontFamily: 'var(--fw-font-mono)',
            flexShrink: 0,
          }}
        >
          #{caseFile.id}
        </span>
      </div>

      {/* Subject */}
      {caseFile.subject && (
        <p
          data-testid="case-subject"
          style={{
            fontSize: 'var(--fw-fs-sm)',
            color: 'var(--fw-t2)',
            fontFamily: 'var(--fw-font-mono)',
            margin: '0 0 8px',
          }}
        >
          {caseFile.subject}
        </p>
      )}

      {/* Disposition chip + timestamps */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        <Badge
          data-testid="case-disposition-chip"
          tone={dispositionTone(caseFile.disposition)}
        >
          {dispositionLabel(caseFile.disposition)}
        </Badge>
        <span
          style={{
            fontSize: 'var(--fw-fs-xs)',
            color: 'var(--fw-t3)',
            fontFamily: 'var(--fw-font-ui)',
          }}
        >
          Created {formatDate(caseFile.created_at)}
        </span>
        {caseFile.updated_at !== caseFile.created_at && (
          <span
            style={{
              fontSize: 'var(--fw-fs-xs)',
              color: 'var(--fw-t3)',
              fontFamily: 'var(--fw-font-ui)',
            }}
          >
            · Updated {formatDate(caseFile.updated_at)}
          </span>
        )}
      </div>
    </div>
  )
}
