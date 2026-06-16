/**
 * AlertingPolicyPanel — global Escalation Policy settings card (ADR-0059 D1/D5 / issue #650).
 *
 * Implements ADR-0058 D1 (the policy registry surface) and ADR-0059 D1 (the Triage threshold).
 *
 * GLOBAL card — not per-source. Install/uninstall a source NEVER adds/removes this card
 * (modular-UI rule / ADR-0059 D5). Mounted on the Settings page next to other global cards.
 *
 * This card owns:
 *   - Triage threshold (TriageThresholdField) — band gate for the banner's severity half.
 *   - Dual-axis explainer (DualAxisExplainer) — band OR auto-escalate tier (ADR-0036).
 *   - Escalation policy table (EscalationPolicyTable) — per-rule severity/auto_escalate/hits.
 *   - Enforcement staircase (EnforcementStaircase) — WARN + require-approval active; auto-block greyed.
 *
 * Wire: GET /config/runtime on mount (reads triage_threshold), PUT /config/runtime on change.
 * Same mechanism as NotificationsPanel / LocalAiPanel.
 *
 * This card does NOT own:
 *   - Notification threshold → NotificationsPanel (#661).
 *   - AI confidence threshold → AI Engine card (/ai).
 *
 * Deviation from rjsf recorded in ADR-0059 D5: this card uses the established hand-built
 * runtime-config pattern (non-form widgets + live data make rjsf unsuitable here).
 */

import { useState, useEffect } from 'react'
import { Panel, Toast } from '../ds'
import type { ToastTone } from '../ds'
import { getRuntimeConfig, putRuntimeConfig, ApiError } from '../../api/client'
import { TriageThresholdField } from './TriageThresholdField'
import { DualAxisExplainer } from './DualAxisExplainer'
import { EscalationPolicyTable } from './EscalationPolicyTable'
import { EnforcementStaircase } from './EnforcementStaircase'

// ---------------------------------------------------------------------------
// SectionGroup — matches the pattern used in NotificationsPanel / LocalAiPanel.
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
          fontWeight: 'var(--fw-fw-medium)' as React.CSSProperties['fontWeight'],
          color: 'var(--fw-t2)',
          fontFamily: 'var(--fw-font-ui)',
          textTransform: 'uppercase' as const,
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

// ---------------------------------------------------------------------------
// Error message extractor — mirrors NotificationsPanel.
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Toast state type
// ---------------------------------------------------------------------------

interface ToastState {
  tone: ToastTone
  message: string
}

// ---------------------------------------------------------------------------
// AlertingPolicyPanel
// ---------------------------------------------------------------------------

export default function AlertingPolicyPanel() {
  /**
   * Triage threshold — SDK field: triage_threshold (default HIGH).
   * ADR-0059 D1: default HIGH preserves today's {CRITICAL, HIGH} banner band exactly.
   */
  const [triageThreshold, setTriageThreshold] = useState('HIGH')
  const [configSaving, setConfigSaving] = useState(false)
  const [toast, setToast] = useState<ToastState | null>(null)

  function showToast(tone: ToastTone, message: string) {
    setToast({ tone, message })
    setTimeout(() => setToast(null), 3000)
  }

  // Load runtime config on mount.
  useEffect(() => {
    let cancelled = false

    getRuntimeConfig()
      .then((cfg) => {
        if (cancelled) return
        // triage_threshold is an additive SDK field; absent on older responses → keep default.
        if (cfg.triage_threshold) {
          setTriageThreshold(cfg.triage_threshold)
        }
      })
      .catch(() => {
        // Non-blocking — safe default "HIGH" preserved.
      })

    return () => {
      cancelled = true
    }
  }, [])

  async function handleThresholdChange(e: React.ChangeEvent<HTMLSelectElement>) {
    const newThreshold = e.target.value
    setTriageThreshold(newThreshold)
    setConfigSaving(true)
    try {
      await putRuntimeConfig({ triage_threshold: newThreshold })
      showToast('ok', `Triage threshold set to ${newThreshold}`)
    } catch (err: unknown) {
      showToast('err', extractApiErrorMessage(err))
    } finally {
      setConfigSaving(false)
    }
  }

  return (
    <div style={{ position: 'relative' }}>
      <Panel title="Escalation Policy" icon="🚨" data-testid="alerting-policy-panel">
        {/* Triage threshold — operator-configurable band gate for the banner */}
        <TriageThresholdField
          value={triageThreshold}
          onChange={handleThresholdChange}
          disabled={configSaving}
        />

        {/* Dual-axis explainer — band OR auto-escalate tier (ADR-0036) */}
        <SectionGroup title="Alert-worthiness" testId="section-dual-axis">
          <DualAxisExplainer />
        </SectionGroup>

        {/* Escalation policy table — per-rule severity + auto_escalate + 24h hit-count */}
        <SectionGroup title="Registered detections" testId="section-policy-table">
          <EscalationPolicyTable />
        </SectionGroup>

        {/* Enforcement staircase — WARN + require-approval active; auto-block greyed */}
        <SectionGroup title="Enforcement tiers" testId="section-enforcement">
          <EnforcementStaircase />
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
