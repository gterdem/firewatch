/**
 * NotificationThresholdField — relabelled alert_threshold control (ADR-0059 D4 / issue #661).
 *
 * SDK field name: alert_threshold (unchanged — no migration).
 * UI label: "Notification threshold" (distinguishes from AI confidence threshold
 * and Triage threshold per ADR-0059 three-name taxonomy).
 *
 * Owned by the Notifications card, NOT the AI Engine card (ADR-0043 / ADR-0059).
 */

import { Select } from '../ds'

const THRESHOLD_OPTIONS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

const HELP_STYLE: React.CSSProperties = {
  fontSize: 'var(--fw-fs-sm)',
  color: 'var(--fw-t3)',
  fontFamily: 'var(--fw-font-ui)',
  marginTop: 4,
}

interface NotificationThresholdFieldProps {
  value: string
  onChange: (e: React.ChangeEvent<HTMLSelectElement>) => void
  disabled?: boolean
}

export function NotificationThresholdField({
  value,
  onChange,
  disabled = false,
}: NotificationThresholdFieldProps) {
  return (
    <div style={{ marginBottom: 14 }}>
      <Select
        id="notification-threshold"
        label="Notification threshold"
        value={value}
        options={THRESHOLD_OPTIONS}
        onChange={onChange}
        disabled={disabled}
        data-testid="notification-threshold-select"
      />
      <div style={HELP_STYLE}>
        Send to Discord / Slack / webhook at or above this severity.
      </div>
    </div>
  )
}
