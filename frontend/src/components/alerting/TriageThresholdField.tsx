/**
 * TriageThresholdField — editable Triage threshold selector (ADR-0059 D1 / issue #650).
 *
 * SDK field name: triage_threshold (net-new on RuntimeConfig, default HIGH).
 * UI label: "Triage threshold" (distinguishes from Notification threshold and AI
 * confidence threshold per ADR-0059 three-name taxonomy).
 *
 * The subtitle MUST state that the action-aware escalation tier always surfaces in
 * the banner regardless of this threshold (ADR-0058 D2 / ADR-0036 two-axes invariant).
 *
 * Default HIGH preserves the existing hard-coded {CRITICAL, HIGH} banner band exactly
 * (ADR-0059 D1). Persists via PUT /config/runtime — same mechanism as NotificationThresholdField.
 *
 * Owned by the Escalation Policy card, NOT the Notifications card.
 */

import { Select } from '../ds'

const THRESHOLD_OPTIONS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

const HELP_STYLE: React.CSSProperties = {
  fontSize: 'var(--fw-fs-sm)',
  color: 'var(--fw-t3)',
  fontFamily: 'var(--fw-font-ui)',
  marginTop: 4,
}

interface TriageThresholdFieldProps {
  value: string
  onChange: (e: React.ChangeEvent<HTMLSelectElement>) => void
  disabled?: boolean
}

export function TriageThresholdField({
  value,
  onChange,
  disabled = false,
}: TriageThresholdFieldProps) {
  return (
    <div style={{ marginBottom: 14 }}>
      <Select
        id="triage-threshold"
        label="Triage threshold"
        value={value}
        options={THRESHOLD_OPTIONS}
        onChange={onChange}
        disabled={disabled}
        data-testid="triage-threshold-select"
      />
      {/* EARS: subtitle MUST state the escalation tier always surfaces regardless. */}
      <div style={HELP_STYLE} data-testid="triage-threshold-subtitle">
        The action-aware escalation tier always surfaces in the banner regardless of this threshold.
      </div>
    </div>
  )
}
