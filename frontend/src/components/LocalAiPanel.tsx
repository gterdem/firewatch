/**
 * LocalAiPanel — Settings panel for the Local AI engine.
 *
 * ADR-0022: the engine is any local OpenAI-compatible endpoint
 * (Ollama / vLLM / llama.cpp / LM Studio) — hence the generic "Local AI" label.
 * Backend field names (ollama_model, ollama_connected) are unchanged; rename DEFERRED (#135).
 *
 * Capabilities added in #135:
 *   - Model selector: dropdown populated from GET /ai/models.
 *     Pre-selects the `current` value; on change persists via PUT /config/runtime.
 *   - Connection status: reads the tri-state health.ai + ollama_model from GET /health
 *     (issue #93 fast-follow to #41 / ADR-0066 — see "Connection status" below).
 *   - Empty models (endpoint unreachable): shows a status message, no crash.
 *
 * Connection status tri-state (issue #93, ADR-0066): branches on `health.ai`
 * via `resolveHealthAiState` rather than the deprecated `ollama_connected`
 * boolean, which collapsed "off by choice" (disabled) and "unreachable" (fault)
 * into one ambiguous value:
 *   health.ai='active'      → "● Connected" + model name (green)
 *   health.ai='unreachable' → "● Unreachable" (amber — attention, not critical;
 *                              detection continues on the rules-only floor, ADR-0015)
 *   health.ai='disabled'    → "● Off" (muted — deliberate choice, non-alarming)
 *   health=null             → "● Disconnected" (unknown — no data at all; the
 *                              boolean-style safe default, distinct from the
 *                              'disabled'/'unreachable' health.ai values)
 *
 * Capabilities formerly in #131 (moved to NotificationsPanel in #661):
 *   - Alert threshold, webhook URL, alert_on_sync have been moved to the global
 *     Notifications card (NotificationsPanel) per ADR-0059 D4 / ADR-0043.
 *
 * Capabilities added in #492 (R5):
 *   - ai_enabled toggle: on/off switch for the AI analysis engine; persisted via PUT.
 *   - ollama_base_url text input: configures the OpenAI-compatible endpoint (ADR-0022 promise —
 *     vLLM / llama.cpp / LM Studio). Save button persists via PUT; 422 validation surfaced.
 *   - Test endpoint button: read-only GET /ai/models probe; shows live model list. No PUT.
 *   - geo_provider select: "offline" (zero-egress MMDB) or "online" (ip-api.com); ADR-0039.
 *
 * Restructured in #493 (R6) + IA divide in #661:
 *   - Now two labeled groups: "AI engine", "Appearance" (Alerting moved to NotificationsPanel).
 *   - Each control has a one-line consequence description.
 *   - Scoring provenance line per ADR-0035 (which local model + rules+AI vs rules-only).
 *   - Theme moved to a standalone "Appearance" section (display pref, not security config).
 *
 * Honest webhook state in #494 (R4):
 *   - Replaced session-local `webhookIsSet=false` heuristic with `webhook_url_set`
 *     boolean from GET /config/runtime (ADR-0006 / ADR-0035 honesty).
 *   - The server-side boolean distinguishes "set+masked" from "never set" — the
 *     masked-null heuristic could not. Secret value is never echoed.
 *
 * ADR-0019: React + TS. Wires to ThemeContext (F1 shared state).
 */

import { useState, useEffect } from 'react'
import { Panel, Select, Button, Toast, Input } from './ds'
import type { ToastTone } from './ds'
import type { HealthResponse } from '../api/types'
import { fetchAiModels, getRuntimeConfig, putRuntimeConfig, ApiError } from '../api/client'
import { useTheme } from '../app/useTheme'
import type { Theme } from '../app/ThemeContext'
import { capModelName } from '../lib/modelName'
import { useApiKeyVersion } from '../hooks/useApiKeyVersion'
import { resolveHealthAiState } from './aiStatusCopy'

interface LocalAiPanelProps {
  /** Health data from GET /health — null while loading or on error. */
  health: HealthResponse | null
  /**
   * #579: true while the initial GET /health request is in flight.
   * When true the connection status shows "Checking…" instead of "Disconnected"
   * so the operator sees a neutral loading state rather than a false negative.
   * Defaults to false so standalone usage (tests, Storybook) behaves as before.
   */
  healthLoading?: boolean
}

interface ToastState {
  tone: ToastTone
  message: string
}

const THEME_OPTIONS: { value: Theme; label: string }[] = [
  { value: 'dark', label: 'Dark (default)' },
  { value: 'light', label: 'Light (presentation)' },
]
const GEO_PROVIDER_OPTIONS: { value: string; label: string }[] = [
  { value: 'offline', label: 'Offline (zero-egress MMDB)' },
  { value: 'online', label: 'Online (ip-api.com)' },
]

// ---------------------------------------------------------------------------
// Shared sub-component styles
// ---------------------------------------------------------------------------

const LABEL_STYLE: React.CSSProperties = {
  display: 'block',
  fontSize: 'var(--fw-fs-sm)',
  color: 'var(--fw-t2)',
  marginBottom: 4,
  fontWeight: 'var(--fw-fw-medium)',
  fontFamily: 'var(--fw-font-ui)',
}

const HELP_STYLE: React.CSSProperties = {
  fontSize: 'var(--fw-fs-sm)',
  color: 'var(--fw-t3)',
  fontFamily: 'var(--fw-font-ui)',
  marginTop: 4,
}

/** A labeled section within the panel with a faint top border and a heading. */
function SectionGroup({
  title,
  children,
  testId,
}: {
  title: string
  children: React.ReactNode
  testId?: string
}) {
  return (
    <div
      data-testid={testId}
      style={{
        borderTop: '1px solid var(--fw-border-l)',
        paddingTop: 16,
        marginTop: 16,
      }}
    >
      <div
        style={{
          fontSize: 'var(--fw-fs-sm)',
          fontWeight: 'var(--fw-fw-medium)',
          color: 'var(--fw-t2)',
          fontFamily: 'var(--fw-font-ui)',
          textTransform: 'uppercase',
          letterSpacing: '0.06em',
          marginBottom: 14,
        }}
      >
        {title}
      </div>
      {children}
    </div>
  )
}

/**
 * Extract a human-readable error message from an ApiError response.
 *
 * 422 bodies from PUT /config/runtime are Pydantic validation error arrays
 * (e.g. anti-SSRF rejection from RuntimeConfig._validate_webhook_url_ssrf).
 * We surface the first `msg` string as sanitized text — never eval/innerHTML.
 */
function extractApiErrorMessage(err: unknown): string {
  if (!(err instanceof ApiError)) return 'Save failed'
  const detail = err.detail
  // Pydantic 422 detail is an array of {type, loc, msg, url} objects
  if (Array.isArray(detail) && detail.length > 0) {
    const first = detail[0] as Record<string, unknown>
    if (typeof first.msg === 'string') return first.msg
  }
  if (typeof detail === 'string') return detail
  return `Save failed (${err.status})`
}

export default function LocalAiPanel({ health, healthLoading = false }: LocalAiPanelProps) {
  const { theme, setTheme } = useTheme()

  // Issue #589: re-fetch models when the API key is restored in-session.
  // keyVersion increments on every setApiKey call; keying the models effect on it
  // causes a re-fetch after the operator re-enters the key, clearing any 401 error.
  const keyVersion = useApiKeyVersion()

  const [toast, setToast] = useState<ToastState | null>(null)

  // Model selector state — populated from GET /ai/models.
  // modelsLoading starts true so the loading indicator shows immediately.
  const [models, setModels] = useState<string[]>([])
  const [selectedModel, setSelectedModel] = useState<string>('')
  const [modelsLoading, setModelsLoading] = useState(true)
  const [modelsError, setModelsError] = useState<string | null>(null)
  const [modelSaving, setModelSaving] = useState(false)

  // Saving state for ai_enabled, geo_provider, etc.
  const [configSaving, setConfigSaving] = useState(false)

  // -----------------------------------------------------------------------
  // #492 (R5) — ai_enabled, ollama_base_url, geo_provider
  // -----------------------------------------------------------------------

  // ai_enabled — whether the AI analysis engine is active (ADR-0022, issue #54)
  const [aiEnabled, setAiEnabled] = useState(true)

  // ollama_base_url — the OpenAI-compatible endpoint (ADR-0022 "any local endpoint")
  const [baseUrl, setBaseUrl] = useState('http://localhost:11434')
  // Saving state for the base URL field (separate from other configSaving)
  const [baseUrlSaving, setBaseUrlSaving] = useState(false)
  // Inline field error for ollama_base_url — populated from 422 (issue #527).
  // Shown directly under the input with aria-invalid; cleared on next keystroke.
  const [baseUrlError, setBaseUrlError] = useState<string | null>(null)

  // "Test endpoint" probe state — populated by GET /ai/models against current baseUrl.
  // This is a read-only, SIEM-safe probe (EARS optional event-driven).
  const [testProbeRunning, setTestProbeRunning] = useState(false)
  const [testProbeResult, setTestProbeResult] = useState<string | null>(null)

  // geo_provider — "offline" (zero-egress MMDB) or "online" (ip-api.com); ADR-0039
  const [geoProvider, setGeoProvider] = useState<'offline' | 'online'>('offline')

  // Connection status from health prop (issue #93, ADR-0066 tri-state).
  // health is authoritative via `health.ai`; when health itself hasn't arrived
  // yet (null), aiState is null — the loading/unknown bucket, rendered
  // separately below (never conflated with the real 'disabled' state).
  const aiState = health != null ? resolveHealthAiState(health) : null
  const aiConnected = aiState === 'active'
  // NB-2 (issue #306): cap model name to 64 chars to guard against layout breaks.
  const aiModelFromHealth = capModelName(health?.ollama_model)

  function showToast(tone: ToastTone, message: string) {
    setToast({ tone, message })
    setTimeout(() => setToast(null), 3000)
  }

  // Fetch available models on mount, and again whenever the API key changes
  // (issue #589: a 401 on mount is cleared once the operator re-enters the key).
  useEffect(() => {
    let cancelled = false

    // All setState calls inside async IIFE to satisfy react-hooks/set-state-in-effect.
    // The IIFE body is a callback — not a synchronous statement in the effect body.
    void (async () => {
      if (!cancelled) {
        // Reset to loading state so the panel shows "Loading models…" during re-fetch
        // rather than the stale 401 error while the new request is in flight.
        setModelsLoading(true)
        setModelsError(null)
      }
      try {
        const data = await fetchAiModels()
        if (cancelled) return
        setModels(data.models)
        // Pre-select current from API, fall back to health, then first option.
        // aiModelFromHealth is intentionally omitted from the dep array — it is a
        // derived prop value and including it would cause spurious re-fetches on
        // every health poll cycle. The pre-select is best-effort on model load.
        const initial = data.current ?? aiModelFromHealth ?? data.models[0] ?? ''
        setSelectedModel(initial)
        setModelsLoading(false)
      } catch (err: unknown) {
        if (cancelled) return
        const msg =
          err instanceof ApiError
            ? `Could not reach Local AI endpoint (${err.status})`
            : 'Local AI endpoint unreachable'
        setModelsError(msg)
        setModels([])
        setSelectedModel('')
        setModelsLoading(false)
      }
    })()

    return () => {
      cancelled = true
    }
    // keyVersion is the only dep that should re-trigger this effect.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [keyVersion])

  // Load runtime config on mount to populate the #492 fields: ai_enabled,
  // ollama_base_url, geo_provider. Notification fields (alert_threshold, webhook_url,
  // alert_on_sync, notify_on_auto_escalate) are now owned by NotificationsPanel (#661).
  useEffect(() => {
    let cancelled = false

    getRuntimeConfig()
      .then((cfg) => {
        if (cancelled) return
        // #492: populate ai_enabled, ollama_base_url, geo_provider
        setAiEnabled(cfg.ai_enabled)
        if (cfg.ollama_base_url) setBaseUrl(cfg.ollama_base_url)
        if (cfg.geo_provider) setGeoProvider(cfg.geo_provider)
      })
      .catch(() => {
        // Non-blocking — controls fall back to defaults if config load fails.
      })

    return () => {
      cancelled = true
    }
  }, [])

  async function handleModelChange(e: React.ChangeEvent<HTMLSelectElement>) {
    const newModel = e.target.value
    setSelectedModel(newModel)
    setModelSaving(true)
    try {
      await putRuntimeConfig({ ollama_model: newModel })
      showToast('ok', `Model set to ${newModel}`)
    } catch (err: unknown) {
      showToast('err', extractApiErrorMessage(err))
    } finally {
      setModelSaving(false)
    }
  }

  function handleThemeChange(e: React.ChangeEvent<HTMLSelectElement>) {
    setTheme(e.target.value as Theme)
  }

  // -----------------------------------------------------------------------
  // #492 handlers — ai_enabled, ollama_base_url, geo_provider
  // -----------------------------------------------------------------------

  async function handleAiEnabledChange(e: React.ChangeEvent<HTMLInputElement>) {
    const newValue = e.target.checked
    setAiEnabled(newValue)
    setConfigSaving(true)
    try {
      await putRuntimeConfig({ ai_enabled: newValue })
      showToast('ok', newValue ? 'AI engine enabled' : 'AI engine disabled')
    } catch (err: unknown) {
      // Roll back optimistic update on failure.
      setAiEnabled(!newValue)
      showToast('err', extractApiErrorMessage(err))
    } finally {
      setConfigSaving(false)
    }
  }

  async function handleSaveBaseUrl() {
    setBaseUrlSaving(true)
    setTestProbeResult(null)
    setBaseUrlError(null)
    try {
      await putRuntimeConfig({ ollama_base_url: baseUrl })
      showToast('ok', 'Endpoint URL saved')
    } catch (err: unknown) {
      if (err instanceof ApiError && err.status === 422) {
        // 422 from the ADR-0022 local-first validator — show an inline field error
        // directly under the endpoint URL input (issue #527).
        // Never log the value; the message from the API is already sanitized text.
        setBaseUrlError(extractApiErrorMessage(err))
      } else {
        // Unexpected server error — surface as panel-level toast.
        showToast('err', extractApiErrorMessage(err))
      }
    } finally {
      setBaseUrlSaving(false)
    }
  }

  /**
   * Test endpoint probe — read-only GET /ai/models.
   * SIEM-safe: never PUTs, never changes state; only displays the model list.
   * EARS optional event-driven: probe SHALL NOT execute any state-changing action.
   */
  async function handleTestEndpoint() {
    setTestProbeRunning(true)
    setTestProbeResult(null)
    try {
      const data = await fetchAiModels()
      if (data.models.length === 0) {
        setTestProbeResult('No models found — check the endpoint URL and ensure the server is running')
      } else {
        setTestProbeResult(`Available: ${data.models.join(', ')}`)
      }
    } catch (err: unknown) {
      const msg =
        err instanceof ApiError
          ? `Endpoint unreachable (${err.status})`
          : 'Endpoint unreachable'
      setTestProbeResult(msg)
    } finally {
      setTestProbeRunning(false)
    }
  }

  async function handleGeoProviderChange(e: React.ChangeEvent<HTMLSelectElement>) {
    const newValue = e.target.value as 'offline' | 'online'
    const prevValue = geoProvider
    setGeoProvider(newValue)
    setConfigSaving(true)
    try {
      await putRuntimeConfig({ geo_provider: newValue })
      showToast('ok', `Geo provider set to ${newValue}`)
    } catch (err: unknown) {
      // Roll back optimistic update on failure.
      setGeoProvider(prevValue)
      showToast('err', extractApiErrorMessage(err))
    } finally {
      setConfigSaving(false)
    }
  }

  // Build model options for the Select DS component
  const modelOptions = models.map((m) => ({ value: m, label: m }))

  // ADR-0035 provenance line: which model is active + scoring mode.
  // "local model X · rules + AI" when enabled and connected; "rules only" otherwise.
  const provenanceModel = aiModelFromHealth ?? (selectedModel || '—')
  const provenance = aiEnabled && aiConnected
    ? `Scoring: local model ${provenanceModel} · rules + AI`
    : 'Scoring: rules only · AI engine offline'

  return (
    <div style={{ position: 'relative' }}>
      <Panel title="Local AI" icon="🤖">
        {/* ------------------------------------------------------------------ */}
        {/* ADR-0035 scoring provenance line                                    */}
        {/* ------------------------------------------------------------------ */}
        <div
          data-testid="scoring-provenance"
          style={{
            fontSize: 'var(--fw-fs-sm)',
            color: aiEnabled && aiConnected ? 'var(--fw-green)' : 'var(--fw-t3)',
            fontFamily: 'var(--fw-font-ui)',
            marginBottom: 4,
          }}
        >
          {provenance}
        </div>

        {/* ================================================================== */}
        {/* Group 1: AI engine                                                  */}
        {/* Controls: ai_enabled, endpoint URL + Test, model selector, status  */}
        {/* ================================================================== */}
        <SectionGroup title="AI engine" testId="section-ai-engine">
          {/* ai_enabled toggle */}
          <div style={{ marginBottom: 14 }}>
            <label
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                fontSize: 'var(--fw-fs-sm)',
                color: 'var(--fw-t1)',
                cursor: 'pointer',
                fontFamily: 'var(--fw-font-ui)',
              }}
            >
              <input
                type="checkbox"
                checked={aiEnabled}
                onChange={handleAiEnabledChange}
                disabled={configSaving}
                data-testid="ai-enabled-toggle"
              />
              Enable AI engine
            </label>
            <div style={HELP_STYLE}>
              When off, scores are derived from rules only (ADR-0035 rules-only mode).
            </div>
          </div>

          {/* ollama_base_url with inline Test probe */}
          <div style={{ marginBottom: 14 }}>
            <label htmlFor="ollama-base-url" style={LABEL_STYLE}>
              Local AI endpoint URL
            </label>
            <div style={{ display: 'flex', gap: 8, marginBottom: 4 }}>
              <Input
                id="ollama-base-url"
                type="url"
                value={baseUrl}
                onChange={(e) => {
                  setBaseUrl(e.target.value)
                  setTestProbeResult(null)
                  // Clear inline validation error as the user edits the field.
                  if (baseUrlError !== null) setBaseUrlError(null)
                }}
                placeholder="http://localhost:11434"
                data-testid="ollama-base-url-input"
                disabled={baseUrlSaving}
                aria-invalid={baseUrlError !== null ? 'true' : undefined}
                aria-describedby={baseUrlError !== null ? 'ollama-base-url-error' : undefined}
              />
              <Button
                variant="primary"
                size="sm"
                onClick={handleSaveBaseUrl}
                disabled={baseUrlSaving || configSaving}
                data-testid="ollama-base-url-save"
              >
                Save
              </Button>
              <Button
                variant="ghost"
                size="sm"
                onClick={handleTestEndpoint}
                disabled={testProbeRunning || baseUrlSaving}
                data-testid="test-endpoint-btn"
              >
                {testProbeRunning ? 'Testing…' : 'Test'}
              </Button>
            </div>
            {baseUrlError !== null && (
              <div
                id="ollama-base-url-error"
                role="alert"
                data-testid="ollama-base-url-error"
                style={{
                  fontSize: 'var(--fw-fs-sm)',
                  color: 'var(--fw-red)',
                  fontFamily: 'var(--fw-font-ui)',
                  marginTop: 4,
                }}
              >
                {baseUrlError}
              </div>
            )}
            {testProbeResult !== null && (
              <div
                data-testid="test-endpoint-result"
                style={{
                  fontSize: 'var(--fw-fs-sm)',
                  color: testProbeResult.startsWith('Available')
                    ? 'var(--fw-green)'
                    : 'var(--fw-t3)',
                  fontFamily: 'var(--fw-font-ui)',
                  marginTop: 4,
                  /* #573: long model lists (8+ models) must wrap rather than
                     clip the panel horizontally. */
                  wordBreak: 'break-all',
                  overflowWrap: 'break-word',
                }}
              >
                {testProbeResult}
              </div>
            )}
            <div style={HELP_STYLE}>
              Ollama · vLLM · llama.cpp · LM Studio — any OpenAI-compatible endpoint (ADR-0022).
            </div>
          </div>

          {/* Model selector — populated from GET /ai/models */}
          <div style={{ marginBottom: 14 }}>
            <label htmlFor="local-ai-model-select" style={LABEL_STYLE}>
              Model
            </label>
            {modelsLoading ? (
              <div
                data-testid="model-select-loading"
                style={{
                  fontSize: 'var(--fw-fs-body)',
                  color: 'var(--fw-t3)',
                  fontFamily: 'var(--fw-font-ui)',
                  padding: '8px 12px',
                  background: 'var(--fw-bg-input)',
                  border: '1px solid var(--fw-border-l)',
                  borderRadius: 'var(--fw-r-sm)',
                }}
              >
                Loading models…
              </div>
            ) : modelsError !== null || models.length === 0 ? (
              <div
                data-testid="model-select-unavailable"
                style={{
                  fontSize: 'var(--fw-fs-body)',
                  color: 'var(--fw-t3)',
                  fontFamily: 'var(--fw-font-ui)',
                  padding: '8px 12px',
                  background: 'var(--fw-bg-input)',
                  border: '1px solid var(--fw-border-l)',
                  borderRadius: 'var(--fw-r-sm)',
                }}
              >
                {modelsError ?? 'No models available — check the Local AI endpoint'}
              </div>
            ) : (
              <select
                id="local-ai-model-select"
                data-testid="model-select"
                value={selectedModel}
                onChange={handleModelChange}
                disabled={modelSaving}
                style={{
                  width: '100%',
                  padding: '8px 12px',
                  background: 'var(--fw-bg-input)',
                  border: '1px solid var(--fw-border-l)',
                  borderRadius: 'var(--fw-r-sm)',
                  color: 'var(--fw-t1)',
                  fontSize: 'var(--fw-fs-body)',
                  fontFamily: 'var(--fw-font-mono)',
                  outline: 'none',
                  cursor: modelSaving ? 'wait' : 'pointer',
                }}
              >
                {modelOptions.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            )}
            <div style={HELP_STYLE}>
              Active model used for AI-assisted scoring and narration.
            </div>
          </div>

          {/* Connection status from GET /health */}
          <div style={{ marginBottom: 4 }}>
            <label style={LABEL_STYLE}>Connection status</label>
            <div
              data-testid="local-ai-status"
              style={{ fontSize: 'var(--fw-fs-body)', fontFamily: 'var(--fw-font-ui)' }}
            >
              {/* #579: show a neutral "Checking…" state while the first /health
                  request is in flight so the operator never sees a brief false
                  "Disconnected" flash on page load.  Once healthLoading resolves,
                  the actual tri-state is displayed.
                  Issue #93 / ADR-0066: branches on health.ai (tri-state) — never
                  collapses 'unreachable' (amber, a real fault) and 'disabled'
                  (neutral, a deliberate choice) into the same treatment. */}
              {healthLoading ? (
                <span style={{ color: 'var(--fw-t3)' }}>○ Checking…</span>
              ) : aiState === 'active' ? (
                <span style={{ color: 'var(--fw-green)' }}>
                  ● Connected
                  {aiModelFromHealth ? (
                    <span style={{ color: 'var(--fw-t2)', marginLeft: 6 }}>
                      — {aiModelFromHealth}
                    </span>
                  ) : null}
                </span>
              ) : aiState === 'unreachable' ? (
                <span style={{ color: 'var(--soc-watch-fg)' }}>● Unreachable</span>
              ) : aiState === 'disabled' ? (
                <span style={{ color: 'var(--fw-t3)' }}>● Off</span>
              ) : (
                // aiState === null: health itself hasn't arrived (no data at all) —
                // distinct "unknown" bucket, never conflated with the real 'disabled' state.
                <span style={{ color: 'var(--fw-t3)' }}>● Disconnected</span>
              )}
            </div>
          </div>
        </SectionGroup>

        {/* ================================================================== */}
        {/* Group 2: Appearance                                                 */}
        {/* Theme is a display preference — separated from detection/alerting   */}
        {/* ================================================================== */}
        <SectionGroup title="Appearance" testId="section-appearance">
          {/* geo_provider placed here as a display/data-enrichment preference */}
          <div style={{ marginBottom: 14 }}>
            <Select
              id="geo-provider"
              label="Geo enrichment"
              value={geoProvider}
              options={GEO_PROVIDER_OPTIONS}
              onChange={handleGeoProviderChange}
              disabled={configSaving}
              data-testid="geo-provider-select"
            />
            <div style={HELP_STYLE}>
              Offline uses the bundled MMDB database (no outbound calls). Online resolves IPs via ip-api.com.
            </div>
          </div>

          {/* Theme select — wired to F1 ThemeContext (EARS: data-theme flips) */}
          <div>
            <Select
              id="theme-select"
              label="Theme"
              value={theme}
              options={THEME_OPTIONS}
              onChange={handleThemeChange}
              data-testid="theme-select"
            />
            <div style={HELP_STYLE}>
              Controls the color scheme for this session.
            </div>
          </div>
        </SectionGroup>
      </Panel>

      {/* Toast notification */}
      {/* #573: use position:fixed so the toast stays in the viewport even when
          the user has scrolled down to the lower sections of the Settings page.
          position:absolute anchored to the panel top would render off-screen. */}
      {toast && (
        <div
          style={{
            position: 'fixed',
            top: 16,
            right: 16,
            zIndex: 50,
          }}
        >
          <Toast tone={toast.tone}>{toast.message}</Toast>
        </div>
      )}
    </div>
  )
}
