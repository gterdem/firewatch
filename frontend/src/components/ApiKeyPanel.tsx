/**
 * ApiKeyPanel — Settings panel for the API key (ADR-0026 Amendment 1, issue #550).
 *
 * ADR-0026 Amendment 1 (enforce-when-set, 2026-06-13): when an api_key is configured
 * on the server, it is enforced on EVERY request — including this loopback dashboard.
 * The operator sets the key here once; the SPA's buildHeaders() reuses it automatically
 * so the dashboard never locks itself out.
 *
 * This is NOT a login screen (deferred — ADR-0026 D8). There is no session cookie,
 * token-refresh flow, or OIDC handshake. The key is a single shared credential held
 * in-memory for the session (apiKeyStore) and fed to buildHeaders() on every call.
 *
 * UX criteria (EARS #550):
 *   - Ubiquitous: honest empty state when no key set ("loopback boundary only").
 *   - Ubiquitous: helper text that once set the key is required on every request.
 *   - Event-driven (first-key-set notice): one-time dismissible banner on first save.
 *   - Event-driven: WHEN the operator saves a key, setApiKey() wires it immediately.
 *   - Event-driven: WHEN the operator clears the key (empty save), key is cleared.
 *   - State-driven: api_key_set=true from server → show "key is configured" placeholder.
 *   - State-driven: 401 on GET /config/runtime → "key configured — re-enter to manage".
 *   - Ubiquitous: field is masked (type="password"); key is NEVER logged or URL-embedded.
 *
 * Save ordering (issue #587 Defect 2a):
 *   - SET path: setApiKey(value) BEFORE putRuntimeConfig so the PUT carries the bearer.
 *     On PUT failure, the optimistic setApiKey is rolled back to null (we don't know
 *     whether the key is valid, so fail-closed is safest).
 *   - CLEAR path: keep the current bearer for the PUT (do NOT call setApiKey(null) first);
 *     only clear the store AFTER a successful PUT.
 *
 * 401 mount awareness (issue #587 Defect 2b):
 *   - A 401 from GET /config/runtime means a key IS configured on the server — the operator
 *     must re-enter it to manage it. Show a "re-enter to manage" state (needsReauth=true).
 *   - Any other failure falls back to the honest "no key set" empty state.
 *
 * Security:
 *   - Key held only in apiKeyStore (module-level, in-memory, not persisted to storage).
 *   - Never logged: no console.log of the key value anywhere.
 *   - Never URL-embedded: the key is passed via Authorization header only.
 *   - Server returns api_key as null (masked) — the UI never prefills the field.
 *   - putRuntimeConfig is used to persist the key server-side (ADR-0006 write path).
 */

import { useState, useEffect } from 'react'
import { Panel, Button, Toast } from './ds'
import type { ToastTone } from './ds'
import { getRuntimeConfig, putRuntimeConfig, ApiError } from '../api/client'
import { setApiKey, isFirstKeySetInSession, clearFirstKeySetFlag } from '../app/apiKeyStore'

// ---------------------------------------------------------------------------
// Shared sub-component styles (mirrored from LocalAiPanel for consistency)
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

// ---------------------------------------------------------------------------
// One-time notice banner — shown after the first key-set in this session.
// Keyboard-reachable dismiss button (WCAG 2.1 SC 2.1.1); not hover-only.
// ---------------------------------------------------------------------------

interface FirstKeyNoticeProps {
  onDismiss: () => void
}

function FirstKeyNotice({ onDismiss }: FirstKeyNoticeProps) {
  return (
    <div
      role="status"
      aria-live="polite"
      aria-atomic="true"
      data-testid="first-key-notice"
      style={{
        display: 'flex',
        alignItems: 'flex-start',
        gap: 12,
        padding: '12px 14px',
        borderRadius: 6,
        background: 'var(--fw-bg3)',
        border: '1px solid var(--fw-accent)',
        marginBottom: 16,
        fontSize: 'var(--fw-fs-sm)',
        fontFamily: 'var(--fw-font-ui)',
        color: 'var(--fw-t1)',
      }}
    >
      <span style={{ flex: 1, lineHeight: 1.5 }}>
        API key now active — required on every request including this dashboard; used
        automatically. Keep it safe; clear the field and save to remove it.
      </span>
      <button
        type="button"
        aria-label="Dismiss notice"
        data-testid="first-key-notice-dismiss"
        onClick={onDismiss}
        style={{
          background: 'none',
          border: 'none',
          cursor: 'pointer',
          color: 'var(--fw-t3)',
          fontSize: 'var(--fw-fs-base)',
          lineHeight: 1,
          padding: '0 2px',
          flexShrink: 0,
        }}
      >
        ×
      </button>
    </div>
  )
}

// ---------------------------------------------------------------------------
// ApiKeyPanel — main export
// ---------------------------------------------------------------------------

interface ToastState {
  tone: ToastTone
  message: string
}

export default function ApiKeyPanel() {
  /** Current text in the masked input field. Never logged. */
  const [inputValue, setInputValue] = useState('')
  /** True when the server reports a key is configured (api_key_set from GET /config/runtime). */
  const [keyIsSet, setKeyIsSet] = useState(false)
  /**
   * True when GET /config/runtime returned 401 on mount — a key IS configured on the server
   * but we don't have it in-memory. Show the "re-enter to manage" state (#587 Defect 2b).
   */
  const [needsReauth, setNeedsReauth] = useState(false)
  const [saving, setSaving] = useState(false)
  const [toast, setToast] = useState<ToastState | null>(null)
  /** Whether to show the one-time first-key-set notice. */
  const [showFirstKeyNotice, setShowFirstKeyNotice] = useState(false)

  function showToast(tone: ToastTone, message: string) {
    setToast({ tone, message })
    setTimeout(() => setToast(null), 4000)
  }

  // Load runtime config on mount to learn whether a key is already configured.
  // We ONLY read api_key_set (boolean) — the secret value is null (masked, ADR-0006).
  // A 401 means a key is configured server-side but not in-memory — show reauth state.
  useEffect(() => {
    let cancelled = false
    getRuntimeConfig()
      .then((cfg) => {
        if (cancelled) return
        setKeyIsSet(cfg.api_key_set)
      })
      .catch((err: unknown) => {
        if (cancelled) return
        if (err instanceof ApiError && err.status === 401) {
          // A key IS configured on the server — the operator needs to re-enter it.
          // Issue #587 Defect 2b: distinguish 401 from "no key set".
          setKeyIsSet(true)
          setNeedsReauth(true)
        }
        // Any other failure: fall back to "no key set" empty state (non-blocking).
      })
    return () => {
      cancelled = true
    }
  }, [])

  async function handleSave() {
    setSaving(true)
    const valueToSend = inputValue.trim() !== '' ? inputValue.trim() : null

    try {
      if (valueToSend !== null) {
        // SET path (issue #587 Defect 2a):
        // Wire the key into the store FIRST so the PUT carries the bearer.
        // On failure, roll back the optimistic store update — the key didn't take.
        setApiKey(valueToSend)
        try {
          await putRuntimeConfig({ api_key: valueToSend })
        } catch (err) {
          // Rollback: the PUT failed, so the key is not accepted by the server.
          // Restore the previous in-memory key (null since we just set it optimistically).
          setApiKey(null)
          throw err
        }
      } else {
        // CLEAR path (issue #587 Defect 2a):
        // Keep the current bearer in the store so the PUT authenticates with it.
        // Only clear the store AFTER the PUT succeeds.
        await putRuntimeConfig({ api_key: null })
        setApiKey(null)
      }

      // Update local state reflecting server state.
      setKeyIsSet(valueToSend !== null)
      // After a successful save, the reauth state is resolved.
      setNeedsReauth(false)

      // Check if this is the first time a key was set in this session.
      if (isFirstKeySetInSession()) {
        clearFirstKeySetFlag()
        setShowFirstKeyNotice(true)
      }

      // Clear the input after a successful save (never leave the key in the field).
      setInputValue('')

      showToast('ok', valueToSend !== null ? 'API key saved' : 'API key cleared')
    } catch (err: unknown) {
      const message =
        err instanceof ApiError
          ? `Save failed (${err.status})`
          : 'Save failed'
      showToast('err', message)
    } finally {
      setSaving(false)
    }
  }

  // Placeholder text reflects the honest server-side state (ADR-0035 honesty).
  const inputPlaceholder = keyIsSet
    ? '•••• set — type to replace, leave blank to keep'
    : 'Enter API key'

  return (
    <div style={{ position: 'relative' }}>
      <Panel title="API access" icon="🔑">
        {/* One-time honest notice — fires once per session on first key-set */}
        {showFirstKeyNotice && (
          <FirstKeyNotice onDismiss={() => setShowFirstKeyNotice(false)} />
        )}

        {/* Re-enter state — shown when a 401 from /config/runtime tells us a key IS set
            server-side but we don't have it in-memory (e.g., after a page reload). */}
        {needsReauth && (
          <div
            data-testid="api-key-reauth-state"
            style={{
              padding: '10px 12px',
              borderRadius: 6,
              background: 'var(--fw-bg3)',
              border: '1px solid var(--fw-border)',
              fontSize: 'var(--fw-fs-sm)',
              fontFamily: 'var(--fw-font-ui)',
              color: 'var(--fw-t2)',
              marginBottom: 14,
              lineHeight: 1.5,
            }}
          >
            API key is configured — re-enter it to manage or replace it.
          </div>
        )}

        {/* Honest empty state — shown when no key is configured */}
        {!keyIsSet && (
          <div
            data-testid="api-key-empty-state"
            style={{
              padding: '10px 12px',
              borderRadius: 6,
              background: 'var(--fw-bg3)',
              border: '1px solid var(--fw-border)',
              fontSize: 'var(--fw-fs-sm)',
              fontFamily: 'var(--fw-font-ui)',
              color: 'var(--fw-t3)',
              marginBottom: 14,
              lineHeight: 1.5,
            }}
          >
            No key set — protected by the loopback boundary only (127.0.0.1). Set a key
            before exposing FireWatch beyond this machine.
          </div>
        )}

        {/* API key input — always masked (type="password") */}
        <div style={{ marginBottom: 12 }}>
          <label htmlFor="api-key-input" style={LABEL_STYLE}>
            API key
          </label>
          <input
            id="api-key-input"
            data-testid="api-key-input"
            type="password"
            autoComplete="off"
            spellCheck={false}
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            placeholder={inputPlaceholder}
            disabled={saving}
            style={{
              width: '100%',
              padding: '7px 10px',
              borderRadius: 5,
              border: '1px solid var(--fw-border)',
              background: 'var(--fw-bg2)',
              color: 'var(--fw-t1)',
              fontSize: 'var(--fw-fs-sm)',
              fontFamily: 'var(--fw-font-mono)',
              boxSizing: 'border-box',
            }}
            aria-describedby="api-key-help"
          />
          <div id="api-key-help" style={HELP_STYLE} data-testid="api-key-help">
            {keyIsSet
              ? 'A key is active — required on every request including this dashboard (ADR-0026 Amendment 1). Leave blank and save to keep the existing key; enter a new value to replace it.'
              : 'Once set, this key is required on every request including this dashboard. Required before exposing FireWatch beyond this machine.'}
          </div>
        </div>

        {/* Save button */}
        <Button
          data-testid="api-key-save"
          onClick={() => void handleSave()}
          disabled={saving}
          variant="primary"
          size="sm"
        >
          {saving ? 'Saving…' : 'Save'}
        </Button>

        {/* Toast feedback */}
        {toast && (
          <div
            style={{
              position: 'absolute',
              bottom: 16,
              right: 16,
              zIndex: 100,
            }}
          >
            <Toast tone={toast.tone}>{toast.message}</Toast>
          </div>
        )}
      </Panel>
    </div>
  )
}
