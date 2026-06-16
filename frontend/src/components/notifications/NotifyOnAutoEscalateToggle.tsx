/**
 * NotifyOnAutoEscalateToggle — opt-in escalation-aware notifications (ADR-0059 D3 / issue #661).
 *
 * SDK field: notify_on_auto_escalate: bool (default false — additive, backward-compatible).
 *
 * When OFF (default): notifier gates on the Notification threshold severity band only.
 * When ON: notifier uses is_alert_worthy(threat, threshold) — band OR escalation tier <= 2 —
 * so a low-score auto-escalating threat (allowed-through but dispositioned suspicious/malicious)
 * also triggers a notification.
 *
 * Default OFF keeps chat quiet by design per ADR-0059 D3.
 */

const HELP_STYLE: React.CSSProperties = {
  fontSize: 'var(--fw-fs-sm)',
  color: 'var(--fw-t3)',
  fontFamily: 'var(--fw-font-ui)',
  marginTop: 4,
}

interface NotifyOnAutoEscalateToggleProps {
  value: boolean
  onChange: (e: React.ChangeEvent<HTMLInputElement>) => void
  disabled?: boolean
}

export function NotifyOnAutoEscalateToggle({
  value,
  onChange,
  disabled = false,
}: NotifyOnAutoEscalateToggleProps) {
  return (
    <div style={{ marginBottom: 4 }}>
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
          checked={value}
          onChange={onChange}
          disabled={disabled}
          data-testid="notify-on-auto-escalate-toggle"
        />
        Also notify on auto-escalating detections
      </label>
      <div style={{ ...HELP_STYLE, marginLeft: 24 }}>
        When off, notifications fire on the Notification threshold band only. When on, a low-score
        allowed-through threat (escalation tier &le; 2) also notifies.
      </div>
    </div>
  )
}
