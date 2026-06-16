/**
 * SourceActions — generic maintenance-action buttons + action status rows.
 *
 * Implements ADR-0034 / issue #169. This component is FULLY GENERIC:
 *   - Zero per-source branching. No type_key checks anywhere.
 *   - A source with no declared actions renders nothing (empty fragment).
 *   - Installing a plugin that declares actions ⇒ buttons appear automatically.
 *   - Uninstalling ⇒ buttons disappear with zero UI edits.
 *
 * Behavior per declared action:
 *   - One button rendered per action, labelled from declaration.
 *   - If the action has non-null `confirm`, a confirm dialog showing the
 *     declared prose (incl. size warnings) is shown BEFORE the POST fires.
 *     The POST NEVER fires automatically — manual-only (ADR-0034 §D.1).
 *   - Long-running actions show a spinner + disabled button while in flight.
 *   - 409 from the API renders as "already running" — no crash.
 *   - ok=false ActionResult → sanitized message text (never raw HTML).
 *   - Status row shows last_run_at date and a stale indicator (verbatim
 *     status_message) when stale === true.
 *   - 404 / 503 / malformed entries → graceful degrade (no buttons / null status).
 *
 * Security:
 *   - ActionResult.message, status_message, and status_detail are server-
 *     sanitized. All rendered as React text nodes — never dangerouslySetInnerHTML.
 *   - source_id / action_id are echoed in ActionResult; render as text only.
 *   - source_host is NOT present in responses (removed for security — ADR-0034).
 *
 * DS styling: Tailwind utility classes consistent with CollectControls.tsx.
 */

import { useState, useEffect, useCallback } from 'react'
import { fetchSourceActions, runSourceAction } from '../../api/sourceActions'
import { ApiError } from '../../api/client'
import type { ActionEntry, ActionResult } from '../../api/types'
import type { SourceActionDeclaration } from '../../schema/types'
import StagedDetailChecklist from './StagedDetailChecklist'

/**
 * Extended fetch timeout (ms) for long_running actions (e.g. ruleset download).
 * 120 s covers the declared ~40–60 MB download on a typical residential link.
 */
const LONG_RUNNING_TIMEOUT_MS = 120_000

interface SourceActionsProps {
  /** Source type key — used for the API call. */
  typeKey: string
  /** The source instance name — passed as ?source_id= to the actions API. */
  sourceId: string
  /**
   * Declared actions from the discovery response.
   * When empty, the component renders nothing.
   */
  declarations: SourceActionDeclaration[]
}

/**
 * Format a timestamp for display. Returns "Never" for null/falsy.
 *
 * R2 fix: ActionEntry.last_run_at arrives from the API as a Unix epoch float
 * (seconds, e.g. 1781162501.16).  new Date(value) treats a number as milliseconds,
 * so passing epoch seconds yields a 1970 date.  We detect numeric values and
 * multiply by 1000 to convert seconds → ms.  ISO string values such as
 * "2026-05-01T10:00:00Z" are passed through unchanged.
 */
function fmtDate(value: string | number | null): string {
  if (!value && value !== 0) return 'Never'
  try {
    const date = typeof value === 'number' ? new Date(value * 1000) : new Date(value)
    return date.toLocaleString()
  } catch {
    return String(value)
  }
}

/** Extract a sanitized UI message from an unknown thrown error. */
function extractErrorMessage(err: unknown, context: string): string {
  if (err instanceof ApiError) {
    const { status, detail } = err
    if (status === 409) {
      return 'An action is already running for this source. Try again later.'
    }
    if (typeof detail === 'string') return `${context} (${status}): ${detail}`
    if (
      detail != null &&
      typeof detail === 'object' &&
      'detail' in detail &&
      typeof (detail as Record<string, unknown>).detail === 'string'
    ) {
      return `${context} (${status}): ${String((detail as Record<string, unknown>).detail)}`
    }
    return `${context} failed (${status})`
  }
  return `${context} failed`
}

// ---------------------------------------------------------------------------
// ConfirmDialog — shown before POST fires for actions with `confirm` prose.
// ---------------------------------------------------------------------------

interface ConfirmDialogProps {
  label: string
  prose: string
  onConfirm: () => void
  onCancel: () => void
}

function ConfirmDialog({ label, prose, onConfirm, onCancel }: ConfirmDialogProps) {
  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label={`Confirm ${label}`}
      data-testid="action-confirm-dialog"
      style={{ position: 'fixed', inset: 0, zIndex: 300, background: 'rgba(0,0,0,0.45)' }}
      onClick={onCancel}
    >
      <div
        style={{
          position: 'absolute',
          top: '30%',
          left: '50%',
          transform: 'translateX(-50%)',
          background: 'var(--fw-bg-card)',
          border: '1px solid var(--fw-border-l)',
          borderRadius: 8,
          padding: '18px 20px',
          maxWidth: 440,
          width: '90vw',
          boxShadow: 'var(--fw-shadow-popup)',
          fontFamily: 'var(--fw-font-ui)',
          fontSize: 13,
        }}
        onClick={(e) => e.stopPropagation()}
      >
        <h4
          style={{
            fontSize: 14,
            fontWeight: 600,
            color: 'var(--fw-t1)',
            marginBottom: 10,
          }}
        >
          {/* label is from declaration — safe text node */}
          {String(label)}
        </h4>
        {/* prose is from declaration — safe text node, may contain size warnings */}
        <p
          data-testid="action-confirm-prose"
          style={{ color: 'var(--fw-t2)', lineHeight: 1.5, marginBottom: 16 }}
        >
          {String(prose)}
        </p>
        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <button
            type="button"
            data-testid="action-confirm-cancel"
            onClick={onCancel}
            className="inline-flex items-center rounded border px-3 py-1 text-sm hover:bg-muted transition-colors"
          >
            Cancel
          </button>
          <button
            type="button"
            data-testid="action-confirm-ok"
            onClick={onConfirm}
            className="inline-flex items-center rounded border border-amber-500 px-3 py-1 text-sm text-amber-600 hover:bg-amber-50 dark:hover:bg-amber-950 transition-colors"
          >
            {String(label)}
          </button>
        </div>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// ActionRow — one button + status row for a single declared action.
// ---------------------------------------------------------------------------

interface ActionRowProps {
  typeKey: string
  sourceId: string
  declaration: SourceActionDeclaration
  /** Live status from the initial fetch. Updated after a run. */
  entry: ActionEntry | null
  onRunComplete: () => void
}

function ActionRow({ typeKey, sourceId, declaration, entry, onRunComplete }: ActionRowProps) {
  const [busy, setBusy] = useState(false)
  const [showConfirm, setShowConfirm] = useState(false)
  const [result, setResult] = useState<ActionResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  // Derive display values from the latest ActionEntry (refreshed after run).
  const lastRunAt = entry?.last_run_at ?? null
  const stale = entry?.stale ?? null
  const statusMessage = entry?.status_message ?? null

  const doRun = useCallback(async () => {
    setBusy(true)
    setResult(null)
    setError(null)

    // For long_running actions, use an AbortController with an extended timeout
    // so the UI doesn't hang forever on a large download.
    let abortController: AbortController | null = null
    let timeoutHandle: ReturnType<typeof setTimeout> | null = null

    if (declaration.long_running) {
      abortController = new AbortController()
      timeoutHandle = setTimeout(() => abortController!.abort(), LONG_RUNNING_TIMEOUT_MS)
    }

    try {
      const actionResult = await runSourceAction(
        typeKey,
        sourceId,
        declaration.id,
        abortController?.signal,
      )
      setResult(actionResult)
      onRunComplete()
    } catch (err: unknown) {
      setError(extractErrorMessage(err, declaration.label))
    } finally {
      if (timeoutHandle !== null) clearTimeout(timeoutHandle)
      setBusy(false)
    }
  }, [typeKey, sourceId, declaration, onRunComplete])

  const handleClick = useCallback(() => {
    if (declaration.confirm) {
      setShowConfirm(true)
    } else {
      void doRun()
    }
  }, [declaration.confirm, doRun])

  const handleConfirmOk = useCallback(() => {
    setShowConfirm(false)
    void doRun()
  }, [doRun])

  const handleConfirmCancel = useCallback(() => {
    setShowConfirm(false)
  }, [])

  return (
    <div
      data-testid={`action-row-${declaration.id}`}
      className="mt-2 space-y-1.5"
    >
      {/* ── Action button ─────────────────────────────────────────────── */}
      <div className="flex items-center gap-2 flex-wrap">
        <button
          type="button"
          disabled={busy}
          aria-busy={busy}
          aria-label={String(declaration.label)}
          data-testid={`action-btn-${declaration.id}`}
          title={String(declaration.description)}
          onClick={handleClick}
          className="inline-flex items-center gap-1.5 rounded border px-3 py-1 text-sm disabled:opacity-50 hover:bg-muted transition-colors"
        >
          {busy && (
            <span
              className="inline-block w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin"
              aria-hidden="true"
            />
          )}
          {/* label is from declaration — safe text node */}
          {String(declaration.label)}
        </button>

        {/* In-progress indicator (visible while long_running action runs) */}
        {busy && declaration.long_running && (
          <span
            data-testid={`action-in-progress-${declaration.id}`}
            className="text-xs text-muted-foreground"
          >
            Downloading… this may take a minute.
          </span>
        )}
      </div>

      {/* ── Status row: last_run_at + status message ──────────────────── */}
      {/*
       * R3 fix: the status row was gated on (lastRunAt !== null || stale === true),
       * hiding the status_message for healthy entries (stale=null, stale=false).
       * A healthy catalog ("50723 rules loaded; downloaded 2026-06-11") has
       * stale=null but a non-null status_message — it must still be shown.
       *
       * New gate: show the row when lastRunAt is present OR status_message is
       * non-null (regardless of stale).  Style: stale=true → amber warning;
       * stale=false/null with a message → normal muted text.
       */}
      {(lastRunAt !== null || statusMessage !== null) && (
        <div
          data-testid={`action-status-row-${declaration.id}`}
          className="text-xs text-muted-foreground space-y-0.5"
        >
          {lastRunAt !== null && (
            <div>
              <span className="font-medium">Last run:</span>{' '}
              <span data-testid={`action-last-run-${declaration.id}`}>
                {fmtDate(lastRunAt)}
              </span>
            </div>
          )}
          {statusMessage !== null && (
            <div
              data-testid={`action-stale-${declaration.id}`}
              className={
                stale === true
                  ? 'text-amber-600 dark:text-amber-400 font-medium'
                  : 'text-muted-foreground'
              }
              role="status"
            >
              {/* statusMessage is server-sanitized — safe text node */}
              {String(statusMessage)}
            </div>
          )}
        </div>
      )}

      {/* ── Action result (success or plugin-level failure) ───────────── */}
      {result !== null && (
        <div
          data-testid={`action-result-${declaration.id}`}
          className={`text-xs rounded border px-3 py-2 ${
            result.ok
              ? 'border-green-300 bg-green-50 text-green-800 dark:bg-green-950 dark:text-green-200'
              : 'border-destructive bg-destructive/10 text-destructive'
          }`}
          role="status"
        >
          {/* result.message is server-sanitized — safe text node */}
          {String(result.message)}

          {/*
           * Staged-detail checklist (issue #691).
           * When result.detail contains stage_* keys, render a generic
           * pass/fail/skip checklist. Keyed on naming convention only —
           * no per-source branching (ADR-0034 / ADR-0010 modularity).
           * SECURITY (ADR-0029 D3): all values rendered as text nodes.
           */}
          <StagedDetailChecklist detail={result.detail} />
        </div>
      )}

      {/* ── API-level error (4xx / 5xx / network) ────────────────────── */}
      {error !== null && (
        <p
          data-testid={`action-error-${declaration.id}`}
          className="text-xs text-destructive"
          role="alert"
        >
          {/* extractErrorMessage produces a sanitized string */}
          {error}
        </p>
      )}

      {/* ── Confirm dialog (shown before POST for actions with prose) ─── */}
      {showConfirm && declaration.confirm !== null && (
        <ConfirmDialog
          label={declaration.label}
          prose={declaration.confirm}
          onConfirm={handleConfirmOk}
          onCancel={handleConfirmCancel}
        />
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// SourceActions: top-level — fetches live status, renders one ActionRow per
// declared action.
// ---------------------------------------------------------------------------

export default function SourceActions({
  typeKey,
  sourceId,
  declarations,
}: SourceActionsProps) {
  // Do nothing when there are no declared actions.
  if (declarations.length === 0) return null

  return (
    <SourceActionsInner
      typeKey={typeKey}
      sourceId={sourceId}
      declarations={declarations}
    />
  )
}

/**
 * Inner component — split out so the hook call is always at the top of the
 * render tree (React rules of hooks: no conditional hook calls).
 */
function SourceActionsInner({
  typeKey,
  sourceId,
  declarations,
}: SourceActionsProps) {
  const [entries, setEntries] = useState<ActionEntry[] | null>(null)
  const [loadError, setLoadError] = useState<string | null>(null)

  // Fetch live status on mount (and when typeKey/sourceId change).
  const loadEntries = useCallback(() => {
    let cancelled = false
    fetchSourceActions(typeKey, sourceId)
      .then((data) => {
        if (!cancelled) {
          setEntries(data)
          setLoadError(null)
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          // 404 / 503 → graceful degrade (no entries, no crash).
          if (err instanceof ApiError && (err.status === 404 || err.status === 503)) {
            setEntries([])
            setLoadError(null)
          } else {
            setEntries([])
            setLoadError(extractErrorMessage(err, 'Action status load'))
          }
        }
      })
    return () => {
      cancelled = true
    }
  }, [typeKey, sourceId])

  useEffect(loadEntries, [loadEntries])

  // After a run completes, refresh status from the server.
  const handleRunComplete = useCallback(() => {
    // Reload to pick up updated last_run_at / stale.
    fetchSourceActions(typeKey, sourceId)
      .then((data) => {
        setEntries(data)
      })
      .catch(() => {
        // Ignore refresh error — the run result is already shown.
      })
  }, [typeKey, sourceId])

  // Find the live entry for a given action id.
  function entryFor(actionId: string): ActionEntry | null {
    return entries?.find((e) => e.id === actionId) ?? null
  }

  return (
    <div
      data-testid="source-actions"
      className="mt-3 pt-2 border-t border-border/50 space-y-1"
    >
      <div className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-1">
        Maintenance
      </div>

      {loadError !== null && (
        <p className="text-xs text-destructive" role="alert" data-testid="source-actions-load-error">
          {loadError}
        </p>
      )}

      {declarations.map((decl) => (
        <ActionRow
          key={decl.id}
          typeKey={typeKey}
          sourceId={sourceId}
          declaration={decl}
          entry={entryFor(decl.id)}
          onRunComplete={handleRunComplete}
        />
      ))}
    </div>
  )
}
