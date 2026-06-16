/**
 * SettingsRoute — the /settings page.
 *
 * P5 (#116): restructured to match the kit oracle (Settings.jsx):
 *   - "Ingest sources" label + 2-column sources-grid of DS SourceCard shells
 *   - Local AI panel (🤖) below with model selector, status, theme/threshold/webhook controls
 *
 * Issue #488 (R3): added a real page header — title "Settings" and a one-sentence subtitle
 * explaining the purpose of the page and the install-to-card model.
 *
 * Fetches GET /sources/types on mount → one DS SourceCard per installed plugin.
 * Fetches GET /health for Local AI status in the AI panel.
 *
 * Issue #315: useSupervisorGate probes GET /sources; if the supervisor is absent
 * (503), the SupervisorOfflineBanner is shown once and per-source fan-out is
 * suppressed via the supervisorOffline prop. Normal rendering resumes on recovery.
 *
 * Satisfies EARS:
 *   - Ubiquitous (modularity): When a source plugin is installed, its DS card appears
 *     with zero per-source frontend code.
 *   - State-driven: When the supervisor is absent (503), an honest banner is shown and
 *     no per-source sub-requests fire.
 *   - Event-driven: When Theme select changes, data-theme flips (ThemeContext F1).
 *   - Ubiquitous (#488): Page title and subtitle explain what this page is for.
 */

import { useState, useEffect } from 'react'
import type { SourceTypeEntry } from '../schema/types'
import type { HealthResponse } from '../api/types'
import { fetchSourceTypes, fetchHealth, ApiError } from '../api/client'
import SettingsList from '../components/SettingsList'
import LocalAiPanel from '../components/LocalAiPanel'
import NotificationsPanel from '../components/notifications/NotificationsPanel'
import AlertingPolicyPanel from '../components/alerting/AlertingPolicyPanel'
import ApiKeyPanel from '../components/ApiKeyPanel'
import SupervisorOfflineBanner from '../components/SupervisorOfflineBanner'
import { useSupervisorGate } from '../hooks/useSupervisorGate'
import { useApiKeyVersion } from '../hooks/useApiKeyVersion'

export default function SettingsRoute() {
  const [sources, setSources] = useState<SourceTypeEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [health, setHealth] = useState<HealthResponse | null>(null)
  /**
   * #579: healthLoading starts true so LocalAiPanel shows a neutral "Checking…"
   * state rather than "Disconnected" during the initial /health fetch window.
   * Set to false once the fetch settles (success or failure).
   */
  const [healthLoading, setHealthLoading] = useState(true)

  // Issue #315: supervisor gate — single probe for /sources availability.
  // supervisorOffline=true suppresses all per-source sub-requests in child components.
  const { supervisorStatus, retryCountdown, retryNow } = useSupervisorGate()
  const supervisorOffline = supervisorStatus === 'offline'

  // Issue #589: re-fetch sources when the API key is restored in-session.
  // keyVersion increments on every setApiKey call; adding it to the effect dep
  // array triggers a re-fetch without any risk of an infinite loop.
  const keyVersion = useApiKeyVersion()

  useEffect(() => {
    let cancelled = false
    // All setState calls inside async IIFE to satisfy react-hooks/set-state-in-effect.
    // The IIFE body is treated as a callback, not a synchronous effect statement.
    void (async () => {
      if (!cancelled) {
        // Reset to loading state on re-fetch (e.g., after key restore clears a 401).
        setLoading(true)
        setError(null)
      }
      try {
        const data = await fetchSourceTypes()
        if (!cancelled) {
          setSources(data)
          setLoading(false)
        }
      } catch (err: unknown) {
        if (!cancelled) {
          setError(
            err instanceof ApiError
              ? `Discovery failed: ${err.status}`
              : 'Failed to load source types',
          )
          setLoading(false)
        }
      }
    })()
    return () => {
      cancelled = true
    }
  }, [keyVersion])

  useEffect(() => {
    let cancelled = false
    fetchHealth()
      .then((data) => {
        if (!cancelled) {
          setHealth(data)
          setHealthLoading(false)
        }
      })
      .catch(() => {
        // Health fetch failure is non-blocking — LocalAiPanel shows disconnected state.
        if (!cancelled) setHealthLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [])

  return (
    <main
      className="container"
      style={{ padding: '24px 32px', maxWidth: 1200, margin: '0 auto' }}
    >
      {/* Issue #315: one honest supervisor-offline banner — shown only when 503.
          Distinct from per-source ADR-0032 health vocab (ok|amber|red|not_configured).
          Mounted in the content region, outside the route table (safe from #316 merge). */}
      <SupervisorOfflineBanner
        supervisorStatus={supervisorStatus}
        retryCountdown={retryCountdown}
        onRetryNow={retryNow}
      />

      {/* Page header — issue #488 (R3): title + one-sentence subtitle.
          The subtitle explains the page purpose and the install-to-card model
          so a first-time user immediately knows where they are. */}
      <header style={{ marginBottom: 24 }} data-testid="settings-page-header">
        <h1
          data-testid="settings-page-title"
          style={{
            margin: '0 0 6px',
            fontSize: 'var(--fw-fs-lg)',
            fontWeight: 'var(--fw-fw-bold)',
            fontFamily: 'var(--fw-font-ui)',
            color: 'var(--fw-t1)',
          }}
        >
          Settings
        </h1>
        <p
          data-testid="settings-page-subtitle"
          style={{
            margin: 0,
            fontSize: 'var(--fw-fs-sm)',
            fontFamily: 'var(--fw-font-ui)',
            color: 'var(--fw-t3)',
          }}
        >
          FireWatch watches the telemetry sources you install here — each installed source shows its
          own settings card automatically.
        </p>
      </header>

      {/* Section label — matches kit oracle "Ingest sources" */}
      <div
        style={{
          fontSize: 'var(--fw-fs-xs)',
          fontWeight: 'var(--fw-fw-bold)',
          textTransform: 'uppercase',
          letterSpacing: '.5px',
          color: 'var(--fw-t3)',
          marginBottom: 10,
          fontFamily: 'var(--fw-font-ui)',
        }}
        data-testid="ingest-sources-label"
      >
        Ingest sources
      </div>

      {/* 2-column sources grid — matches kit .sources-grid (1fr 1fr) */}
      <SettingsList
        sources={sources}
        loading={loading}
        error={error}
        supervisorOffline={supervisorOffline}
      />

      {/* Local AI panel — matches kit Settings.jsx "Ollama AI" section; renamed per ADR-0022 */}
      {/* #579: healthLoading is passed so the panel shows "Checking…" during the
          initial /health fetch window instead of a false "Disconnected" state. */}
      <div style={{ marginTop: 24 }}>
        <LocalAiPanel health={health} healthLoading={healthLoading} />
      </div>

      {/* Escalation Policy card — ADR-0059 D1/D5 / ADR-0058 D1/D6 / issue #650.
          Global card: Triage threshold + policy table + dual-axis explainer + enforcement staircase.
          NEVER per-source — install/uninstall a source does NOT affect this card. */}
      <div style={{ marginTop: 24 }}>
        <AlertingPolicyPanel />
      </div>

      {/* Notifications panel — ADR-0059 D4 / issue #661.
          Global notification controls (threshold, webhook, escalation-aware toggle)
          separated from the AI engine card per ADR-0043.
          Rendered after Escalation Policy so policy context precedes notification thresholds. */}
      <div style={{ marginTop: 24 }}>
        <NotificationsPanel />
      </div>

      {/* API key panel — ADR-0026 Amendment 1 / issue #550.
          The operator sets the shared credential here once; buildHeaders() reuses it
          automatically on every subsequent request so the dashboard never locks itself out. */}
      <div style={{ marginTop: 24 }}>
        <ApiKeyPanel />
      </div>
    </main>
  )
}
