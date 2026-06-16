/**
 * SourceCard (page-level) — DS SourceCard shell wrapping the rjsf config form.
 *
 * ADR-0062 changes (issues #701–#704):
 *
 * §B — Active toggle in header (relabel + relocate, NOT a new backend concept):
 *   - "Auto-sync" renamed to "Active". The toggle lives in the DS card header slot
 *     (role="switch", aria-checked) so it is always visible even when collapsed.
 *   - Active state = instance present in GET /sources (ADR-0031 §A: an _instances
 *     entry IS the registration + schedule state).
 *   - Reuses the existing PUT /sources/{type_key}/auto-sync enable/disable wiring
 *     verbatim. No new endpoint.
 *   - WHILE Active: the "Sync every [N] s" schedule sub-line is shown in CollectControls.
 *   - WHILE Inactive: the schedule sub-line is hidden.
 *
 * §A — Collapse by default, active-first layout:
 *   - Cards collapse to just their header by default.
 *   - Active cards start expanded; Inactive cards start collapsed.
 *   - Active-state source of truth: instance present in GET /sources.
 *   - SettingsList handles sort (active-first); this card handles defaultExpanded.
 *
 * §C — Real source_id in header (not "default" placeholder):
 *   - Renders instance.source_id (defaulting to type_key) in the header.
 *   - No per-source branching.
 *
 * §D — Humanize Test/Sync errors; never show raw status codes:
 *   - Test/Sync are disabled (not just hidden) on inactive sources.
 *   - CollectControls short-circuits before calling the endpoint.
 *
 * §E — "Off" (not "Stale") for inactive / never-run sources:
 *   - toStatusText returns "Off" when instance===null (no _instances entry).
 *   - "Stale" is reserved for Active + amber health (ADR-0032 Decision C).
 *
 * P5 (#116): composes the DS SourceCard shell (F3, ds/sources/SourceCard) with:
 *   - Header: source emoji glyph + display_name + SourceBadge + SourceHealth dot + version
 *   - Body: SourceConfigForm (rjsf, schema-driven — ADR-0010 / ADR-0028 D4)
 *   - Actions: CollectControls — flavor-driven collect controls (issue #138, ADR-0031)
 *   - Error/success rows: surfaced from SourceConfigForm callbacks
 *
 * ADR-0010 non-negotiable: per-source config fields render from config_schema() via rjsf.
 * Zero per-source frontend code for the form body or the collect controls.
 * Install a source → card appears; uninstall → gone.
 *
 * Collect controls are driven by `flavor` (from discovery) via CollectControls:
 *   pull → Sync now + Test + Active toggle + interval + last-sync info (ADR-0031)
 *   push → listener status only
 * No per-source-type branch exists here — flavor is the only discriminant.
 *
 * Source icons (emoji glyph, DS iconography spec, kit oracle Settings.jsx):
 *   azure_waf / waf → ☁️
 *   suricata / ids   → 🛰️
 *   syslog           → 📡
 *   file             → 📄
 *   unknown          → 📦 (neutral fallback — no UI edit needed for new plugins)
 *
 * Health dot in card header: driven by the server-computed `health` field from
 * GET /stats (ADR-0032 Decision C), supplied by the parent (SettingsList) via the
 * `serverHealth` prop.  This makes the card dot agree with the AppHeader dot for
 * the same source.  `last_success_at` is kept for human-readable caption text only;
 * it no longer determines dot color (ADR-0032 supersedes OD-2 recency rule).
 * 503 (no supervisor) handled gracefully — card still renders.
 *
 * Issue #315: supervisorOffline prop gates all per-source sub-requests.
 * When true: loadInstance is NOT called, CollectControls / SourceActions are
 * rendered in a disabled offline state. The config form remains accessible
 * (state-driven design — configuration is always editable, ADR-0035).
 * When the supervisor comes back online, the parent re-renders with
 * supervisorOffline=false and normal data loading resumes on that tick.
 *
 * Issue #491 (R7): parked/offline recovery banner.
 *   - WHILE a source is parked/backoff/error, a compact ParkedRecoveryBanner
 *     leads the card body (above the config form).
 *   - "Sync now to resume" calls syncSource — ADR-0023 §D (sync unparks the source).
 *   - "Why?" scrolls to the existing SourceDiagnosticsPanel (reuse, not rebuild).
 *   - Driven entirely by instance.state — zero per-source-type branching.
 *   - Supervisor-offline notice is ONE per card (in the actions slot), never per field.
 */

import { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import { SourceCard as DSSourceCard, SourceBadge, SourceHealth, Toast } from './ds'
import type { SourceCardStatus } from './ds'
import type { SourceHealthItem } from '../lib/sourceHealth'
import type { SourceTypeEntry } from '../schema/types'
import type { SourceInstance } from '../api/types'
import { fetchSources, syncSource, setAutoSync, getAutoSync } from '../api/sources'
import { ApiError } from '../api/client'
import SourceConfigForm from './SourceConfigForm'
import CollectControls from './sources/CollectControls'
import SourceActions from './sources/SourceActions'
import SourceDiagnosticsPanel from './sources/SourceDiagnosticsPanel'

interface SourceCardProps {
  source: SourceTypeEntry
  /**
   * When true, the supervisor is absent (GET /sources returned 503).
   * All per-source sub-requests (instance fetch, auto-sync, actions) are suppressed.
   * Action controls are visibly disabled with an offline label (ADR-0035 honesty).
   * The config form remains accessible — configuration does not require a running supervisor.
   */
  supervisorOffline?: boolean
  /**
   * Server-computed health value from GET /stats source_health[] (ADR-0032 Decision C).
   * Supplied by the parent (SettingsList via useSourceStatsHealth) so all cards share
   * one fetch instead of polling independently.
   *
   * Values: "ok" | "amber" | "red" | "not_configured"
   * null = stats not yet fetched or fetch failed — card renders a neutral/idle dot.
   *
   * The dot color is derived from this field via dotStateFromHealth() (same mapper
   * used by the AppHeader) so both dots always agree for a given source.
   */
  serverHealth?: string | null
  /**
   * Full SourceHealthItem from GET /stats for this source type.
   * Supplies event_count ("Events" field) and last_event_at ("Last event" field)
   * to the HealthCard popover, making them match the AppHeader values.
   * null = stats not yet fetched or fetch failed — card falls back to "—" / "Never".
   */
  serverHealthItem?: SourceHealthItem | null
}

/** Map type_key → DS emoji glyph (DS iconography spec, kit oracle Settings.jsx). */
function sourceIcon(typeKey: string): string {
  if (typeKey === 'azure_waf' || typeKey === 'waf') return '☁️'
  if (typeKey === 'suricata' || typeKey === 'ids') return '🛰️'
  if (typeKey === 'syslog') return '📡'
  if (typeKey === 'file') return '📄'
  return '📦'
}

/**
 * Map server health string → DS SourceCardStatus for the card shell chrome.
 * ADR-0032 Decision C: dot color is driven by server-computed health, not recency.
 * serverHealth=null means the stats fetch hasn't settled yet → neutral 'idle'.
 */
function toCardStatus(serverHealth: string | null): SourceCardStatus {
  switch (serverHealth) {
    case 'ok':
      return 'active'
    case 'amber':
      return 'syncing'
    case 'red':
      return 'error'
    case 'not_configured':
      return 'idle'
    default:
      // null (not yet fetched) or unknown value → neutral idle, never false-red
      return 'idle'
  }
}

/**
 * Threshold above which a secondsAgo value is treated as "never synced" rather
 * than a real recency value.  30 days (2,592,000 s) is a conservative sentinel:
 * any source that hasn't succeeded in 30+ days is effectively "never" from a
 * UX perspective, and epoch-fallback timestamps (1970-01-01) produce values in
 * the billions.  This prevents "Stale — 29689956m ago" (#573).
 */
const NEVER_SYNCED_THRESHOLD_S = 30 * 24 * 60 * 60 // 30 days in seconds

/**
 * Build status text for the card header.
 *
 * ADR-0062 §E: an inactive source (no _instances entry, instance===null) MUST
 * read "Off" — never "Stale". "Stale" is reserved for an ACTIVE source that ran
 * and whose freshness aged past the server boundary (ADR-0032 Decision C amber).
 *
 * ADR-0062 Amendment 1 §1 (issue #737): isActive is now tri-valued (boolean | null).
 * null = loading (GET /sources not yet resolved) → return "" so no committed "Off"
 * flickers in the header before the real value lands (bug 2a fix).
 *
 * ADR-0032 Decision C: the dot color AND the primary health label come from the
 * server health field.  `last_success_at` recency is kept as a human-readable
 * caption suffix ("11m ago" / "never") — it does NOT determine the label category.
 *
 * Supervisor error/backoff/parked states still surface from instance.state
 * because the server health field already reflects them (red/amber), but we add
 * the instance.state label for diagnostic context in the text.
 *
 * secondsAgo is pre-computed by the caller (useMemo) to keep Date.now() out of render.
 * isActive reflects auto_sync_enabled from GET /sources (ADR-0062 Amendment 1 §1).
 */
function toStatusText(
  instance: SourceInstance | null,
  secondsAgo: number | null,
  serverHealth: string | null,
  isActive: boolean | null,
): string {
  // Loading: GET /sources not yet settled — show nothing (no committed "Off" flicker).
  // Bug 2a fix: previously every card painted "Off" here then flipped after fetch resolved.
  if (isActive === null) return ''
  // ADR-0062 §E: inactive source → "Off" (never "Stale" for a never-run source)
  if (!isActive) return 'Off'

  // Supervisor error/backoff/parked: surface the state name first for clarity.
  // The server health will also be red/amber for these, but the state label
  // ("Error" / "Backoff" / "Parked") is more actionable at a glance.
  if (instance?.state === 'error') return 'Error'
  if (instance?.state === 'backoff') return 'Backoff'
  if (instance?.state === 'parked') return 'Parked'

  // Build the recency suffix — used only as a caption, not as the health label.
  let recencySuffix = ''
  if (secondsAgo !== null) {
    if (secondsAgo > NEVER_SYNCED_THRESHOLD_S) {
      recencySuffix = ' — never'
    } else if (secondsAgo < 60) {
      recencySuffix = ' — <1m ago'
    } else {
      recencySuffix = ` — ${Math.round(secondsAgo / 60)}m ago`
    }
  }

  // Primary label driven by server health (ADR-0032 Decision C).
  switch (serverHealth) {
    case 'ok':
      return `Active${recencySuffix}`
    case 'amber':
      // Amber = stale/quiet — but NOT "collector failure". Show "Stale" with recency.
      // ADR-0062 §E: "Stale" is only valid here because isActive=true (guarded above).
      return `Stale${recencySuffix}`
    case 'red':
      return 'Error'
    case 'not_configured':
      return 'Not configured'
    default:
      // null (stats not yet fetched) or unknown → show instance state if known, else generic.
      if (!instance) return 'No data'
      return 'Listening'
  }
}

/**
 * Fetch the SourceInstance for this type_key from GET /sources.
 * Returns the first matching instance, or null if not found / 503 (no supervisor).
 *
 * D1 fix (issue #195): the real GET /sources response uses `source_type` (not
 * `type_key`) as the discriminant field.  Matching on `type_key` always returns
 * undefined, making every action/sync call fall back to the type key as source_id
 * (causing 404 on action and 422 on sync).
 */
async function fetchInstanceForType(typeKey: string): Promise<SourceInstance | null> {
  try {
    const instances = await fetchSources()
    return instances.find((i) => i.source_type === typeKey) ?? null
  } catch (err) {
    // 503: supervisor not running (serve/static mode) → graceful no-status.
    if (err instanceof ApiError && err.status === 503) return null
    return null
  }
}

/** States that indicate a source has "gone dark" — the red dot entry point (ADR-0032). */
const DARK_STATES = new Set(['backoff', 'parked', 'error', 'stopped'])

/**
 * States that indicate a source is paused/failed and needs recovery guidance.
 * ADR-0035 honesty: lead the card body with a visible recovery banner for these states.
 * "stopped" is excluded — stopped is a clean shutdown, not a failure.
 */
const RECOVERY_STATES = new Set(['parked', 'backoff', 'error'])

interface ParkedRecoveryBannerProps {
  /** Source instance in a parked/backoff/error state. */
  instance: SourceInstance
  /** Source type key — passed to syncSource for ADR-0023 §D resume. */
  typeKey: string
  /**
   * Callback to scroll the SourceDiagnosticsPanel into view.
   * "Why?" leads to the existing panel — reuse, don't rebuild (issue #491).
   */
  onShowDiagnostics: () => void
}

/**
 * ParkedRecoveryBanner — compact status banner for a paused/failed source.
 *
 * Issue #491 (R7): WHILE instance.state is parked/backoff/error, this banner
 * renders at the TOP of the card body — before the config form — so the operator
 * immediately sees the recovery path without hunting below the form.
 *
 * "Sync now to resume" fires syncSource (the existing ADR-0023 §D unpark mechanism).
 * "Why?" scrolls to the existing SourceDiagnosticsPanel — zero new diagnostics surface.
 *
 * Driven by instance.state — zero per-source-type branching (ADR-0010 modularity).
 *
 * Security: all strings are text nodes; last_error is rendered from a text prop only.
 * Secrets never rendered here (no config values touched).
 */
function ParkedRecoveryBanner({ instance, typeKey, onShowDiagnostics }: ParkedRecoveryBannerProps) {
  const [syncing, setSyncing] = useState(false)
  const [syncOk, setSyncOk] = useState(false)
  const [syncErr, setSyncErr] = useState<string | null>(null)

  const handleSyncNow = useCallback(async () => {
    setSyncing(true)
    setSyncErr(null)
    setSyncOk(false)
    try {
      await syncSource(typeKey, instance.source_id)
      setSyncOk(true)
    } catch (err: unknown) {
      let msg = 'Sync failed'
      if (err instanceof ApiError) {
        const detail = err.detail
        if (typeof detail === 'string') msg = detail
        else if (detail && typeof detail === 'object' && 'detail' in detail) {
          const d = (detail as Record<string, unknown>).detail
          if (typeof d === 'string') msg = d
        }
      }
      setSyncErr(msg)
    } finally {
      setSyncing(false)
    }
  }, [typeKey, instance.source_id])

  const stateLabel =
    instance.state === 'parked'
      ? 'Paused'
      : instance.state === 'backoff'
        ? 'In backoff'
        : 'Error'

  return (
    <div
      role="status"
      aria-live="polite"
      data-testid="parked-recovery-banner"
      data-instance-state={instance.state}
      style={{
        marginBottom: 12,
        padding: '10px 14px',
        borderRadius: 'var(--fw-r-sm)',
        border: '1px solid var(--fw-border-l)',
        borderLeft: '3px solid var(--fw-amber)',
        background: 'var(--fw-bg-input)',
        fontFamily: 'var(--fw-font-ui)',
        fontSize: 'var(--fw-fs-sm)',
        color: 'var(--fw-t1)',
        display: 'flex',
        alignItems: 'center',
        gap: 10,
        flexWrap: 'wrap',
      }}
    >
      {/* State label + summary */}
      <span aria-hidden="true" style={{ fontSize: 14 }}>
        ⚠️
      </span>
      <span style={{ flex: 1, minWidth: 0 }}>
        <span
          style={{ fontWeight: 'var(--fw-fw-semibold)' }}
          data-testid="parked-recovery-state-label"
        >
          {stateLabel}
        </span>
        {' — last pull failed.'}
      </span>

      {/* "Sync now to resume" CTA */}
      <button
        type="button"
        onClick={handleSyncNow}
        disabled={syncing}
        data-testid="parked-recovery-sync-now"
        aria-label="Sync now to resume collection"
        aria-busy={syncing}
        style={{
          background: 'var(--fw-amber)',
          border: 'none',
          borderRadius: 'var(--fw-r-sm)',
          padding: '3px 10px',
          fontSize: 'var(--fw-fs-xs)',
          color: 'var(--fw-on-accent)',
          fontWeight: 'var(--fw-fw-semibold)',
          cursor: syncing ? 'not-allowed' : 'pointer',
          fontFamily: 'var(--fw-font-ui)',
          opacity: syncing ? 0.6 : 1,
          whiteSpace: 'nowrap',
          display: 'flex',
          alignItems: 'center',
          gap: 4,
        }}
      >
        {syncing && (
          <span
            className="inline-block w-3 h-3 border-2 border-current border-t-transparent rounded-full animate-spin"
            aria-hidden="true"
            style={{
              width: 10,
              height: 10,
              borderWidth: 2,
              borderStyle: 'solid',
              borderColor: 'currentColor',
              borderTopColor: 'transparent',
              borderRadius: '50%',
              display: 'inline-block',
              animation: 'spin 0.7s linear infinite',
            }}
          />
        )}
        Sync now to resume
      </button>

      {/* "Why?" — reveals/scrolls to existing SourceDiagnosticsPanel */}
      <button
        type="button"
        onClick={onShowDiagnostics}
        data-testid="parked-recovery-why"
        aria-label="Show source diagnostics"
        style={{
          background: 'none',
          border: '1px solid var(--fw-border-l)',
          borderRadius: 'var(--fw-r-sm)',
          padding: '3px 10px',
          fontSize: 'var(--fw-fs-xs)',
          color: 'var(--fw-t2)',
          cursor: 'pointer',
          fontFamily: 'var(--fw-font-ui)',
          whiteSpace: 'nowrap',
        }}
      >
        Why?
      </button>

      {/* Inline feedback for sync result */}
      {syncOk && (
        <span
          style={{ fontSize: 'var(--fw-fs-xs)', color: 'var(--fw-green)', width: '100%' }}
          data-testid="parked-recovery-sync-ok"
          role="status"
        >
          Sync started — collection resuming.
        </span>
      )}
      {syncErr !== null && (
        <span
          style={{ fontSize: 'var(--fw-fs-xs)', color: 'var(--fw-red)', width: '100%' }}
          data-testid="parked-recovery-sync-err"
          role="alert"
        >
          {/* syncErr is derived from server response text — render as text node */}
          {syncErr}
        </span>
      )}
    </div>
  )
}

/**
 * ActiveToggle — the in-header on/off switch for a pull source (ADR-0062 §B).
 *
 * Renders a WAI-ARIA switch (role="switch", aria-checked) for the Active state.
 * Calls PUT /sources/{type_key}/auto-sync enable/disable wiring verbatim.
 * When toggling ON: requires a valid interval (uses the autoSync interval or DEFAULT_INTERVAL).
 * When toggling OFF: calls setAutoSync({enabled:false}) — no interval_seconds.
 *
 * Pull-only: push sources have no Active toggle (ADR-0062 §B).
 */
/**
 * ADR-0062 Amendment 1 §1 (issue #737): isActive is now tri-valued (boolean | null).
 * null = GET /sources not yet settled — the toggle must be disabled with no committed
 * aria-checked (WAI-ARIA Switch loading pattern), so neither "On" nor "Off" is
 * announced to AT before the real value is known (bug 2a fix).
 */
interface ActiveToggleProps {
  typeKey: string
  /** null while GET /sources is in-flight; true/false once settled. */
  isActive: boolean | null
  onActiveChange: (newActive: boolean) => void
}

function ActiveToggle({ typeKey, isActive, onActiveChange }: ActiveToggleProps) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Treat the null (loading) and local-toggle-in-flight (loading=true) states
  // uniformly: the switch is disabled. Only toggle when we have a committed value.
  const isDisabled = loading || isActive === null

  const handleToggle = useCallback(async () => {
    // Guard: only toggle when we have a committed boolean value
    if (isActive === null) return
    setLoading(true)
    setError(null)
    const newEnabled = !isActive
    try {
      if (newEnabled) {
        // Enable: fetch current interval first for continuity, fallback to default
        let interval = 300
        try {
          const current = await getAutoSync(typeKey)
          interval = current.interval_seconds
        } catch {
          // Use default interval if getAutoSync fails
        }
        await setAutoSync(typeKey, { enabled: true, interval_seconds: interval })
      } else {
        // Disable: do NOT send interval_seconds (strict-bool contract #155 NB-1)
        await setAutoSync(typeKey, { enabled: false })
      }
      onActiveChange(newEnabled)
    } catch (err: unknown) {
      // ADR-0062 §D: never show raw status code for Active toggle failure
      if (err instanceof ApiError) {
        const detail = err.detail
        if (typeof detail === 'string') {
          setError(detail)
        } else {
          setError(newEnabled ? 'Failed to turn on source.' : 'Failed to turn off source.')
        }
      } else {
        setError(newEnabled ? 'Failed to turn on source.' : 'Failed to turn off source.')
      }
      // Do NOT flip toggle on error — keep previous state
    } finally {
      setLoading(false)
    }
  }, [isActive, typeKey, onActiveChange])

  return (
    <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      <button
        type="button"
        role="switch"
        /*
         * WAI-ARIA Switch loading pattern (issue #737):
         * WHILE isActive===null (loading): omit aria-checked (no committed value).
         * aria-busy signals AT that the state is in-flight.
         * ONCE resolved: set aria-checked to the committed boolean value.
         */
        {...(isActive !== null ? { 'aria-checked': isActive } : {})}
        aria-busy={isActive === null || loading}
        aria-label={
          isActive === null
            ? 'Loading source status'
            : isActive
              ? 'Deactivate this source'
              : 'Activate this source'
        }
        disabled={isDisabled}
        data-testid="active-toggle"
        onClick={handleToggle}
        style={{
          position: 'relative',
          display: 'inline-flex',
          height: 20,
          width: 36,
          borderRadius: 10,
          // Loading → neutral grey (no committed color); resolved → green/grey
          background: isActive === true ? 'var(--fw-green)' : 'var(--fw-t3)',
          border: 'none',
          cursor: isDisabled ? 'not-allowed' : 'pointer',
          opacity: isDisabled ? 0.6 : 1,
          transition: 'background 0.2s',
          padding: 0,
          flexShrink: 0,
        }}
      >
        <span
          style={{
            position: 'absolute',
            top: 2,
            // Loading → knob centered (neutral); resolved → left (off) or right (on)
            left: isActive === true ? 'calc(100% - 18px)' : 2,
            width: 16,
            height: 16,
            borderRadius: '50%',
            background: 'white',
            boxShadow: '0 1px 3px rgba(0,0,0,0.2)',
            transition: 'left 0.15s',
          }}
        />
      </button>
      <span
        style={{
          fontSize: 'var(--fw-fs-xs)',
          fontWeight: 'var(--fw-fw-medium)',
          color: isActive === true ? 'var(--fw-green)' : 'var(--fw-t3)',
          fontFamily: 'var(--fw-font-ui)',
        }}
        data-testid="active-toggle-label"
      >
        {isActive === null ? 'Loading…' : isActive ? 'Active' : 'Off'}
      </span>
      {error && (
        <span
          style={{ fontSize: 'var(--fw-fs-xs)', color: 'var(--fw-red)' }}
          role="alert"
          data-testid="active-toggle-error"
        >
          {/* error is derived from sanitized server text — render as text node */}
          {error}
        </span>
      )}
    </span>
  )
}

export default function SourceCard({
  source,
  supervisorOffline = false,
  serverHealth = null,
  serverHealthItem = null,
}: SourceCardProps) {
  const [sourceInstance, setSourceInstance] = useState<SourceInstance | null>(null)
  /** Ref to the diagnostics panel DOM node — used to scroll it into view on dot click and "Why?". */
  const diagnosticsRef = useRef<HTMLDivElement>(null)
  /**
   * instanceResolved: true once fetchInstanceForType has settled (null or a real instance).
   *
   * R1 fix (issue #195 re-verification): SourceActions must NOT mount until the
   * /sources fetch has completed.  Before this guard, SourceActions mounted immediately
   * with sourceId = source.type_key (the fallback) and fired GET /actions?source_id=suricata
   * before the instance was known — causing two spurious 404s on every Settings load.
   * After the fetch resolves, sourceInstance?.source_id is the real "vm-target" and
   * SourceActions mounts once with the correct id.
   *
   * When no instance exists at all (source not configured), instanceResolved is set to
   * true and sourceId falls back to source.type_key as before — that single fetch is fine.
   *
   * Issue #315: when supervisorOffline=true, instanceResolved stays false so SourceActions
   * never mounts. This is intentional — the supervisor gate suppresses the fan-out.
   */
  const [instanceResolved, setInstanceResolved] = useState(false)
  /**
   * fetchedAt: epoch ms when the source instance was last fetched.
   * Stored in state so the render can compute secondsAgo from it without
   * calling Date.now() during render (react-hooks/purity forbids impure calls).
   * The effect sets this — side-effects are the correct place for Date.now().
   */
  const [fetchedAt, setFetchedAt] = useState<number>(0)
  const [saveError, setSaveError] = useState<string | null>(null)
  /**
   * savedToast: true while the success toast is visible after a save.
   * Auto-dismissed after SAVE_TOAST_DISMISS_MS (R9 / issue #497 — toast replaces
   * the static "Settings saved." text row from DSSourceCard's `success` prop).
   */
  const [savedToast, setSavedToast] = useState(false)
  const saveToastTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  /**
   * ADR-0062 Amendment 1 §1 (issue #737): isActive is tri-valued.
   * - null  = GET /sources not yet settled (loading — initial state)
   * - false = settled, auto_sync_enabled is false (idle / never-enabled)
   * - true  = settled, auto_sync_enabled is true (pull loop running)
   *
   * null prevents the "committed Off" flicker (bug 2a): the toggle and status text
   * both use loading affordances while null.  Once settled, the value comes ONLY from
   * auto_sync_enabled — never from instance-presence or state (bug 2b fix).
   *
   * After PUT /auto-sync toggles the state, we update isActive optimistically so the
   * header pill + schedule sub-line respond instantly.  The next loadInstance call
   * confirms the real server state via auto_sync_enabled.
   */
  const [isActive, setIsActive] = useState<boolean | null>(null)

  const loadInstance = useCallback(() => {
    // Issue #315: suppress the per-source GET /sources fan-out when the supervisor is
    // absent. The probe (useSupervisorGate) has already confirmed 503; firing 12 more
    // requests would all fail with the same error. When the supervisor comes back, the
    // parent re-renders with supervisorOffline=false and this effect runs normally.
    if (supervisorOffline) return

    let cancelled = false
    fetchInstanceForType(source.type_key).then((inst) => {
      if (!cancelled) {
        // Record timestamp in effect — side-effects are the correct place for Date.now().
        setFetchedAt(Date.now())
        setSourceInstance(inst)
        // ADR-0062 Amendment 1 §1 (issue #737): derive Active from auto_sync_enabled ONLY.
        // inst !== null was the old (wrong) discriminant — it was true for idle sources too.
        // auto_sync_enabled is the real server-computed flag (bug 2b fix).
        setIsActive(inst?.auto_sync_enabled ?? false)
        setInstanceResolved(true)
      }
    })
    return () => {
      cancelled = true
    }
  }, [source.type_key, supervisorOffline])

  useEffect(loadInstance, [loadInstance])

  // Cleanup toast timer on unmount
  useEffect(() => {
    return () => {
      if (saveToastTimerRef.current !== null) clearTimeout(saveToastTimerRef.current)
    }
  }, [])

  const handleSaved = useCallback(() => {
    setSaveError(null)
    // R9 (#497): show success toast and auto-dismiss after 3 s.
    setSavedToast(true)
    if (saveToastTimerRef.current !== null) clearTimeout(saveToastTimerRef.current)
    saveToastTimerRef.current = setTimeout(() => setSavedToast(false), 3000)
  }, [])

  const handleServerErrors = useCallback((errors: string | null) => {
    setSaveError(errors)
    if (errors) setSavedToast(false)
  }, [])

  /**
   * handleDotClick — scroll the diagnostics panel into view when the health dot is
   * clicked.  Entry point for the "why did this source go dark?" flow (ADR-0032,
   * issue #139): the red dot is the canonical trigger; the panel auto-expands when
   * the source is in an error state.
   *
   * Issue #491: also the "Why?" target from ParkedRecoveryBanner. Both the red-dot
   * and the "Why?" button share this callback — single source of scroll truth.
   */
  const handleShowDiagnostics = useCallback(() => {
    if (diagnosticsRef.current) {
      diagnosticsRef.current.scrollIntoView({ behavior: 'smooth', block: 'nearest' })
    }
  }, [])

  /**
   * ADR-0062 §B: handle Active toggle from the card header.
   * Optimistically updates local isActive so the pill + schedule sub-line
   * respond immediately without waiting for a full reload.
   */
  const handleActiveChange = useCallback((newActive: boolean) => {
    setIsActive(newActive)
    // Reload instance to get fresh server state (source_id, state, etc.)
    // after a successful toggle. This is a lightweight re-query, not a full page reload.
    loadInstance()
  }, [loadInstance])

  // Derive all time-based display values from pre-computed fetchedAt state.
  // fetchedAt was set in an effect (not during render) so it is pure to use here.
  const { cardStatus, statusText, healthItems, isDark, isInRecoveryState } = useMemo(() => {
    // "Last event" and recency caption: prefer last_event_at from /stats (the newest
    // actual event time), falling back to last_success_at from /sources only when the
    // stats item is unavailable.  last_success_at is the last successful pull-cycle
    // completion time — not the newest event timestamp — so it is a poor proxy and
    // can be epoch/never even when events are present.
    const statsLastEventAt = serverHealthItem?.lastEventAt ?? null
    const lastEventAt = statsLastEventAt ?? sourceInstance?.last_success_at ?? null

    const secondsAgo =
      lastEventAt && fetchedAt > 0
        ? Math.max(0, Math.floor((fetchedAt - new Date(lastEventAt).getTime()) / 1000))
        : null

    // ADR-0032 Decision C: dot color is driven by serverHealth (from GET /stats), NOT
    // by local recency. serverHealth=null (stats not yet fetched or unavailable) → idle.
    //
    // Fallback chain for the health item passed to the SourceHealth dot component:
    //   1. serverHealth (prop from SettingsList → useSourceStatsHealth) — preferred
    //   2. Supervisor state inference (error/backoff → red) — if supervisor is offline
    //      the stats fetch may also have failed, but this covers the gap
    //   3. null → 'not_configured' (neutral/grey) — never false-red
    const supervisorStatus = sourceInstance?.state
    let resolvedHealth: string
    if (serverHealth !== null && serverHealth !== undefined) {
      // Server health is authoritative (ADR-0032 D/C). Use it directly.
      resolvedHealth = serverHealth
    } else if (supervisorStatus === 'error' || supervisorStatus === 'backoff') {
      // Stats fetch unavailable but supervisor tells us there's a problem.
      resolvedHealth = 'red'
    } else if (!sourceInstance) {
      resolvedHealth = 'not_configured'
    } else {
      // Stats not yet available — fall back to neutral rather than red (#573 spirit).
      resolvedHealth = 'not_configured'
    }

    // isDark: true when the resolved health is red (entry point for diagnostics panel).
    // ADR-0032: the red dot is the canonical trigger for "why did this source go dark?".
    const isDark = resolvedHealth === 'red' ||
      (sourceInstance != null && DARK_STATES.has(sourceInstance.state))

    // isInRecoveryState: true when the card body should lead with the recovery banner.
    // Issue #491 (R7): driven by instance.state, no per-source branching.
    const isInRecoveryState = sourceInstance != null && RECOVERY_STATES.has(sourceInstance.state)

    const healthItem: SourceHealthItem = {
      id: source.type_key,
      // Use type_key as label in the card's inline status slot — display_name is
      // already prominent in the card header; repeating it here is redundant.
      label: source.type_key,
      // The health field drives the dot color via dotStateFromHealth() in SourceHealth.
      // It is the server-computed value (ADR-0032 D/C) — same field the AppHeader uses.
      health: resolvedHealth,
      supervisorState: supervisorStatus ?? null,
      // lastEventAt: use the /stats last_event_at (newest actual event) so the HealthCard
      // popover's "Last event" row matches the AppHeader tooltip value (#626 follow-up).
      // Falls back to last_success_at when /stats is unavailable.
      lastEventAt,
      // ADR-0031 §F / issue #139: last_error is now exposed on GET /sources.
      // Render in the health dot tooltip — text only, server-sanitized.
      lastError: sourceInstance?.last_error ?? null,
      // eventCount: use the real total from /stats so the HealthCard "Events" row
      // matches the AppHeader count.  Falls back to 0 when stats are unavailable.
      eventCount: serverHealthItem?.eventCount ?? 0,
      sourceType: source.type_key,
    }

    return {
      // cardStatus drives DS shell chrome (card border/background tint).
      // Also derived from serverHealth for consistency.
      cardStatus: toCardStatus(resolvedHealth),
      // ADR-0062 §E: pass isActive so toStatusText returns "Off" for inactive sources.
      statusText: toStatusText(sourceInstance, secondsAgo, resolvedHealth, isActive),
      healthItems: [healthItem],
      isDark,
      isInRecoveryState,
    }
  }, [source.type_key, sourceInstance, fetchedAt, serverHealth, serverHealthItem, isActive])

  /**
   * ADR-0062 §C: real source_id in the header.
   * Instance present → use its source_id (e.g. "suricata", "vm-target").
   * Instance absent → fall back to type_key (per ADR-0031 §B: source_id defaults to type_key).
   * No per-source branching — generic.
   */
  const displaySourceId = sourceInstance?.source_id ?? source.type_key

  return (
    // #706 fix: removed flex:1 and height:100% propagation that was added by #574
    // for equal-height rows. ADR-0062 collapse invalidated that assumption — a
    // collapsed card must sit at its natural header-only height. The grid parent
    // now uses align-items:start so each cell shrinks to content height.
    <section
      aria-label={`${source.display_name} settings`}
      data-testid={`source-card-${source.type_key}`}
      style={{ display: 'flex', flexDirection: 'column' }}
    >
      <DSSourceCard
        collapsible
        defaultExpanded={isActive === true || supervisorOffline}
        name={
          /*
           * #706 fix (3): header overflow — now that columns are equal-width
           * (minmax(0,1fr)), the Suricata card no longer gets 494px but exactly
           * half the grid. The display_name + SourceBadge + source_id + version
           * span must not overflow or overlap.
           *
           * Strategy:
           *   - Outer span: min-width:0 + overflow:hidden so it respects the
           *     grid cell boundary. flex-wrap:wrap lets metadata drop to a second
           *     line on very narrow viewports.
           *   - Display name: flex-shrink:0 so it never truncates (it's the
           *     primary label). SourceBadge and source_id are secondary — they
           *     can wrap or truncate.
           *   - source_id / version spans: min-width:0 + overflow:hidden +
           *     text-overflow:ellipsis so a long source_id doesn't push version
           *     off-screen.
           */
          <span style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0, flexWrap: 'wrap' }}>
            <span
              data-testid={`source-name-${source.type_key}`}
              style={{ flexShrink: 0 }}
            >
              {source.display_name}
            </span>
            <SourceBadge source={source.type_key} />
            {/* ADR-0062 §C: real source_id (not "default" placeholder) */}
            <span
              style={{
                fontSize: 'var(--fw-fs-xs)',
                color: 'var(--fw-t3)',
                fontFamily: 'var(--fw-font-mono)',
                minWidth: 0,
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }}
              data-testid={`source-id-${source.type_key}`}
            >
              {displaySourceId}
            </span>
            <span
              style={{
                fontSize: 'var(--fw-fs-xs)',
                color: 'var(--fw-t3)',
                fontFamily: 'var(--fw-font-mono)',
                flexShrink: 0,
              }}
            >
              v{source.version}
            </span>
          </span>
        }
        icon={sourceIcon(source.type_key)}
        status={cardStatus}
        statusText={
          <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            {/*
             * ADR-0032 / issue #139: the red dot is the entry point into the
             * diagnostics panel. When isDark, wrap the SourceHealth dot in a
             * clickable button so operators can navigate from "red dot" → "why?"
             * without hunting for the panel below the form.
             * Non-dark sources: dot is static (no button wrapper).
             */}
            {isDark ? (
              <button
                type="button"
                onClick={handleShowDiagnostics}
                title="Click to see diagnostics"
                aria-label="View source diagnostics"
                data-testid="health-dot-diagnostics-trigger"
                style={{
                  background: 'none',
                  border: 'none',
                  padding: 0,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                }}
              >
                <SourceHealth sources={healthItems} />
              </button>
            ) : (
              <SourceHealth sources={healthItems} />
            )}
            <span>{statusText}</span>
          </span>
        }
        headerSlot={
          // ADR-0062 §B: Active toggle in header slot — pull sources only.
          // Push sources have no Active toggle (configuring starts the listener, ADR-0031 §D).
          source.flavor === 'pull' && !supervisorOffline ? (
            <ActiveToggle
              typeKey={source.type_key}
              isActive={isActive}
              onActiveChange={handleActiveChange}
            />
          ) : undefined
        }
        actions={
          <>
            {/*
             * Issue #315 / #491: when the supervisor is offline, show a concise inline
             * notice instead of active controls. This satisfies ADR-0035 honesty —
             * we never present controls as operable when the supervisor is absent.
             * The config form body (children below) remains accessible: configuration
             * does not depend on a running supervisor (state-driven design).
             *
             * ONE notice per card — never per field (EARS #491 UT-16).
             */}
            {supervisorOffline ? (
              <div
                data-testid="source-actions-offline"
                style={{
                  marginTop: 12,
                  padding: '6px 10px',
                  borderRadius: 'var(--fw-r-sm)',
                  background: 'var(--fw-bg-input)',
                  border: '1px solid var(--fw-border-l)',
                  fontSize: 'var(--fw-fs-xs)',
                  color: 'var(--fw-t3)',
                  fontFamily: 'var(--fw-font-ui)',
                }}
              >
                Controls offline — supervisor unavailable
              </div>
            ) : (
              /*
               * Bug #3 fix: wrap all action-area children in a column-flex container
               * so CollectControls, SourceActions, and the Diagnostics panel stack
               * vertically.  Without this wrapper, DSSourceCard's row-flex `actions`
               * container places them side-by-side, pushing the Diagnostics button
               * to the right of "Test: OK" instead of below the controls.
               */
              <div
                data-testid="source-actions-column"
                style={{ display: 'flex', flexDirection: 'column', width: '100%' }}
              >
                <CollectControls
                  typeKey={source.type_key}
                  flavor={source.flavor}
                  instance={sourceInstance}
                  isActive={isActive ?? false}
                />
                {/*
                 * ADR-0034: mount SourceActions only when the discovery entry
                 * declares actions. Zero per-source branching — the declarations
                 * array drives everything. No actions declared → null rendered.
                 *
                 * R1 fix: defer mount until instanceResolved is true.
                 * Mounting before the /sources fetch completes would use the fallback
                 * sourceId=type_key, causing spurious 404s on every Settings load.
                 * Once resolved, sourceInstance?.source_id is the real instance id
                 * (e.g. "vm-target") — or type_key when no instance exists.
                 *
                 * Issue #315: instanceResolved stays false when supervisorOffline=true,
                 * so this block is never entered in offline state anyway.
                 */}
                {(source.actions ?? []).length > 0 && instanceResolved && (
                  <SourceActions
                    typeKey={source.type_key}
                    sourceId={sourceInstance?.source_id ?? source.type_key}
                    declarations={source.actions ?? []}
                  />
                )}
                {/*
                 * Issue #139 / ADR-0032 / #491: diagnostics panel.
                 * "Why did this source go dark?" — always rendered (healthy shows collapsed).
                 * Auto-expands when instance is in an error/dark state (red dot entry point).
                 * The ref is used by both handleShowDiagnostics (dot click) and the "Why?"
                 * button in ParkedRecoveryBanner to scroll this panel into view.
                 */}
                <div ref={diagnosticsRef}>
                  <SourceDiagnosticsPanel instance={sourceInstance} />
                </div>
              </div>
            )}
          </>
        }
        error={saveError ?? undefined}
      >
        {/*
         * The DS SourceCard body renders children in a 2-col grid.
         * Span both columns so the rjsf form renders at full card width.
         * The form manages its own internal layout via rjsf templates.
         *
         * Issue #491 (R7): when the source is in a recovery state (parked/backoff/error),
         * render the ParkedRecoveryBanner FIRST — above the config form — so the operator
         * sees the recovery path without scrolling past the form.
         * Driven by instance.state, no per-source-type branching (ADR-0010 modularity).
         */}
        <div style={{ gridColumn: '1 / -1' }}>
          {isInRecoveryState && sourceInstance !== null && (
            <ParkedRecoveryBanner
              instance={sourceInstance}
              typeKey={source.type_key}
              onShowDiagnostics={handleShowDiagnostics}
            />
          )}
          <SourceConfigForm
            source={source}
            onSaved={handleSaved}
            onServerErrors={handleServerErrors}
          />
        </div>

        {/* R9 (#497): transient DS Toast on successful save — replaces the static
            "Settings saved." text row in DSSourceCard's `success` prop. Auto-dismissed
            after 3 s via handleSaved → setSavedToast(false) timer. */}
        {savedToast && (
          <div
            data-testid="save-success-toast"
            style={{
              gridColumn: '1 / -1',
              display: 'flex',
              justifyContent: 'flex-end',
              padding: '0 0 4px',
            }}
          >
            <Toast tone="ok">Settings saved.</Toast>
          </div>
        )}
      </DSSourceCard>
    </section>
  )
}
