/**
 * SourceDiagnosticsPanel — read-only diagnostics for a "went dark" source.
 *
 * Issue #139 / ADR-0032: the red/dark health dot is the entry point into this view.
 * Renders all supervisor diagnostic fields from GET /sources (InstanceStatus DTO):
 *   supervisor_state, attempt, total_crashes, total_dlq, dropped_count,
 *   last_success_at, last_sync_at, last_sync_ingested, last_sync_status, last_error.
 *
 * Rendered as an expand-on-red collapsible section inside SourceCard.
 * Healthy / idle sources show a collapsed "Diagnostics" disclosure with no alarm.
 * Red/backoff/parked sources expand automatically and surface the error.
 *
 * SECURITY: last_error is sanitized server-side (ADR-0029 D3, ADR-0031 §F).
 * All user-visible strings are rendered as text nodes — never via innerHTML.
 */

import { useState } from 'react'
import type { SourceInstance } from '../../api/types'
import { fmtTimestampNever } from '../../lib/time'

interface SourceDiagnosticsPanelProps {
  /** The live instance record from GET /sources, or null if no supervisor. */
  instance: SourceInstance | null
}

/** Supervisor states that indicate an error condition needing diagnostics. */
const ERROR_STATES = new Set(['backoff', 'parked', 'error', 'stopped'])

/** Map last_sync_status to a human-readable label. */
function syncStatusLabel(status: 'ok' | 'no_data' | 'error' | null | undefined): string {
  if (status == null) return '—'
  const map: Record<string, string> = {
    ok: 'OK',
    no_data: 'No data',
    error: 'Error',
  }
  return map[status] ?? String(status)
}

/**
 * DiagnosticsRow — one key/value row in the diagnostics table.
 * All values are cast to strings — never rendered as HTML.
 */
function DiagnosticsRow({
  label,
  value,
  testId,
  isError = false,
}: {
  label: string
  value: string
  testId: string
  isError?: boolean
}) {
  return (
    <div className="flex items-baseline gap-2 py-0.5" data-testid={testId}>
      <span
        className="text-xs text-muted-foreground whitespace-nowrap w-36 shrink-0"
        aria-label={label}
      >
        {label}
      </span>
      <span
        className={`text-xs font-mono break-all ${isError ? 'text-destructive' : ''}`}
      >
        {/* All values are cast to string — never innerHTML */}
        {value}
      </span>
    </div>
  )
}

export default function SourceDiagnosticsPanel({ instance }: SourceDiagnosticsPanelProps) {
  const isErrorState = instance != null && ERROR_STATES.has(instance.state)

  // Expand automatically when the source is in an error state (red dot entry point).
  const [open, setOpen] = useState(isErrorState)

  // Keep open state in sync when instance transitions into/out of error state.
  // We use a derived key so the disclosure opens automatically on state change.
  const shouldAutoOpen = isErrorState

  // Sync open state when error-condition changes (instance goes dark while panel is closed).
  // This is a controlled disclosure: if the source becomes red, auto-open.
  // If it recovers, leave open as-is (don't auto-close).
  const [prevShouldAutoOpen, setPrevShouldAutoOpen] = useState(shouldAutoOpen)
  if (shouldAutoOpen && !prevShouldAutoOpen) {
    setOpen(true)
    setPrevShouldAutoOpen(true)
  } else if (!shouldAutoOpen && prevShouldAutoOpen) {
    setPrevShouldAutoOpen(false)
    // Don't auto-close — leave the operator's current choice intact.
  }

  const handleToggle = () => setOpen((v) => !v)

  return (
    <div
      className="mt-3 border-t border-border/40 pt-2"
      data-testid="diagnostics-panel"
      data-state={isErrorState ? 'error' : 'ok'}
    >
      {/* Disclosure header */}
      <button
        type="button"
        className={`flex items-center gap-1.5 text-xs font-medium select-none cursor-pointer hover:opacity-80 transition-opacity ${
          isErrorState ? 'text-destructive' : 'text-muted-foreground'
        }`}
        aria-expanded={open}
        aria-controls="diagnostics-body"
        onClick={handleToggle}
        data-testid="diagnostics-toggle"
      >
        {/* Caret indicator */}
        <span
          className={`inline-block transition-transform ${open ? 'rotate-90' : ''}`}
          aria-hidden="true"
        >
          ›
        </span>
        {isErrorState ? 'Why did this source go dark?' : 'Diagnostics'}
        {isErrorState && instance?.last_error && (
          <span className="ml-1 text-destructive font-normal truncate max-w-xs">
            — {String(instance.last_error)}
          </span>
        )}
      </button>

      {/* Disclosure body */}
      {open && (
        <div
          id="diagnostics-body"
          className="mt-2 space-y-0.5 rounded border border-border/40 bg-muted/30 px-3 py-2"
          data-testid="diagnostics-body"
        >
          {instance == null ? (
            <p className="text-xs text-muted-foreground" data-testid="diagnostics-no-data">
              No supervisor data available. The supervisor may not be running.
            </p>
          ) : (
            <>
              <DiagnosticsRow
                label="Supervisor state"
                value={String(instance.state)}
                testId="diag-state"
                isError={isErrorState}
              />
              <DiagnosticsRow
                label="Attempt"
                value={String(instance.attempt)}
                testId="diag-attempt"
              />
              <DiagnosticsRow
                label="Total crashes"
                value={String(instance.total_crashes)}
                testId="diag-total-crashes"
              />
              <DiagnosticsRow
                label="DLQ count"
                value={String(instance.total_dlq)}
                testId="diag-total-dlq"
              />
              <DiagnosticsRow
                label="Dropped"
                value={String(instance.dropped_count)}
                testId="diag-dropped-count"
              />
              <DiagnosticsRow
                label="Last success"
                value={fmtTimestampNever(instance.last_success_at)}
                testId="diag-last-success"
              />
              <DiagnosticsRow
                label="Last sync"
                value={fmtTimestampNever(instance.last_sync_at)}
                testId="diag-last-sync-at"
              />
              <DiagnosticsRow
                label="Ingested (last)"
                value={String(instance.last_sync_ingested ?? 0)}
                testId="diag-last-sync-ingested"
              />
              <DiagnosticsRow
                label="Sync status"
                value={syncStatusLabel(instance.last_sync_status)}
                testId="diag-last-sync-status"
              />
              {instance.last_error != null && (
                <DiagnosticsRow
                  label="Last error"
                  value={String(instance.last_error)}
                  testId="diag-last-error"
                  isError
                />
              )}
            </>
          )}
        </div>
      )}
    </div>
  )
}
