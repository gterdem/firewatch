/**
 * NotificationsPanel — global Notifications card (ADR-0059 D4 / issue #661).
 *
 * Owns all notification-related settings, separated from the AI Engine card per
 * ADR-0043 (the AI page owns AI-engine accountability, NOT global alerting) and
 * ADR-0059 (three named thresholds: Notification threshold here, AI confidence on
 * the AI Engine card, Triage threshold on the Escalation Policy card).
 *
 * Controls housed here (moved from LocalAiPanel "Alerting" section):
 *   - Notification threshold (label for SDK field alert_threshold)
 *   - Webhook URL + alert_on_sync (preserves ADR-0006 SecretStr masking)
 *
 * New control (ADR-0059 D3, mechanism):
 *   - notify_on_auto_escalate toggle (default ON since ADR-0059 Amendment 1 / issue #74)
 *
 * Security: webhook_url is SecretStr on the server. GET returns null when set.
 * webhook_url_set (boolean) is the honest signal. The secret is never echoed.
 *
 * Wire: GET /config/runtime on mount, PUT /config/runtime on each change.
 */

import { useState, useEffect } from 'react'
import { Panel, Toast } from '../ds'
import type { ToastTone } from '../ds'
import { getRuntimeConfig, putRuntimeConfig, ApiError } from '../../api/client'
import { NotificationThresholdField } from './NotificationThresholdField'
import { WebhookField } from './WebhookField'
import { NotifyOnAutoEscalateToggle } from './NotifyOnAutoEscalateToggle'

// ---------------------------------------------------------------------------
// Shared section group style — matches LocalAiPanel's SectionGroup for visual
// consistency across the Settings page.
// ---------------------------------------------------------------------------

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
 * 422 bodies from PUT /config/runtime are Pydantic validation error arrays.
 */
function extractApiErrorMessage(err: unknown): string {
  if (!(err instanceof ApiError)) return 'Save failed'
  const detail = err.detail
  if (Array.isArray(detail) && detail.length > 0) {
    const first = detail[0] as Record<string, unknown>
    if (typeof first.msg === 'string') return first.msg
  }
  if (typeof detail === 'string') return detail
  return `Save failed (${err.status})`
}

interface ToastState {
  tone: ToastTone
  message: string
}

export default function NotificationsPanel() {
  // Notification threshold (SDK: alert_threshold) — default matches SDK default
  const [threshold, setThreshold] = useState('CRITICAL')
  // Webhook URL — controlled field; empty = user has not typed anything this session
  const [webhookUrl, setWebhookUrl] = useState('')
  // True when the server has a webhook_url set (honest signal, ADR-0006 / #494)
  const [webhookIsSet, setWebhookIsSet] = useState(false)
  // alert_on_sync: persisted on toggle
  const [alertOnSync, setAlertOnSync] = useState(true)
  // notify_on_auto_escalate: ADR-0059 D3 mechanism; default ON per ADR-0059 Amendment 1
  const [notifyOnAutoEscalate, setNotifyOnAutoEscalate] = useState(true)
  // Saving state for all config operations
  const [configSaving, setConfigSaving] = useState(false)
  const [toast, setToast] = useState<ToastState | null>(null)

  function showToast(tone: ToastTone, message: string) {
    setToast({ tone, message })
    setTimeout(() => setToast(null), 3000)
  }

  // Load runtime config on mount to populate all fields.
  useEffect(() => {
    let cancelled = false
    getRuntimeConfig()
      .then((cfg) => {
        if (cancelled) return
        setThreshold(cfg.alert_threshold)
        setAlertOnSync(cfg.alert_on_sync)
        // webhook_url_set: non-secret boolean from server (ADR-0006 / #494).
        // Never prefill the input with the secret value.
        setWebhookIsSet(cfg.webhook_url_set)
        // notify_on_auto_escalate: additive field; default true if absent (ADR-0059 A1)
        setNotifyOnAutoEscalate(cfg.notify_on_auto_escalate ?? true)
      })
      .catch(() => {
        // Non-blocking — controls fall back to safe defaults if config load fails.
      })
    return () => {
      cancelled = true
    }
  }, [])

  async function handleThresholdChange(e: React.ChangeEvent<HTMLSelectElement>) {
    const newThreshold = e.target.value
    setThreshold(newThreshold)
    setConfigSaving(true)
    try {
      await putRuntimeConfig({ alert_threshold: newThreshold })
      showToast('ok', `Notification threshold set to ${newThreshold}`)
    } catch (err: unknown) {
      showToast('err', extractApiErrorMessage(err))
    } finally {
      setConfigSaving(false)
    }
  }

  async function handleSaveWebhook() {
    setConfigSaving(true)
    try {
      await putRuntimeConfig({ webhook_url: webhookUrl || null })
      showToast('ok', webhookUrl ? 'Webhook URL saved' : 'Webhook URL cleared')
      setWebhookIsSet(!!webhookUrl)
      setWebhookUrl('')
    } catch (err: unknown) {
      showToast('err', extractApiErrorMessage(err))
    } finally {
      setConfigSaving(false)
    }
  }

  async function handleAlertOnSyncChange(e: React.ChangeEvent<HTMLInputElement>) {
    const newValue = e.target.checked
    setAlertOnSync(newValue)
    setConfigSaving(true)
    try {
      await putRuntimeConfig({ alert_on_sync: newValue })
      showToast('ok', newValue ? 'Sync alerts enabled' : 'Sync alerts disabled')
    } catch (err: unknown) {
      setAlertOnSync(!newValue)
      showToast('err', extractApiErrorMessage(err))
    } finally {
      setConfigSaving(false)
    }
  }

  async function handleNotifyOnAutoEscalateChange(e: React.ChangeEvent<HTMLInputElement>) {
    const newValue = e.target.checked
    setNotifyOnAutoEscalate(newValue)
    setConfigSaving(true)
    try {
      await putRuntimeConfig({ notify_on_auto_escalate: newValue })
      showToast(
        'ok',
        newValue ? 'Escalation-aware notifications enabled' : 'Escalation-aware notifications disabled',
      )
    } catch (err: unknown) {
      // Roll back optimistic UI update on failure.
      setNotifyOnAutoEscalate(!newValue)
      showToast('err', extractApiErrorMessage(err))
    } finally {
      setConfigSaving(false)
    }
  }

  return (
    <div style={{ position: 'relative' }}>
      <Panel title="Notifications" icon="🔔">
        <SectionGroup title="Alerts" testId="section-notifications-alerts">
          <NotificationThresholdField
            value={threshold}
            onChange={handleThresholdChange}
            disabled={configSaving}
          />
          <WebhookField
            webhookUrl={webhookUrl}
            onWebhookUrlChange={(e) => setWebhookUrl(e.target.value)}
            onSaveWebhook={handleSaveWebhook}
            webhookIsSet={webhookIsSet}
            alertOnSync={alertOnSync}
            onAlertOnSyncChange={handleAlertOnSyncChange}
            disabled={configSaving}
          />
        </SectionGroup>

        <SectionGroup title="Escalation" testId="section-notifications-escalation">
          <NotifyOnAutoEscalateToggle
            value={notifyOnAutoEscalate}
            onChange={handleNotifyOnAutoEscalateChange}
            disabled={configSaving}
          />
        </SectionGroup>
      </Panel>

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
