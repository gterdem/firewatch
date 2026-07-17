/**
 * NotifyOnAutoEscalateToggle — escalation-aware notifications, ON by default
 * (ADR-0059 D3 mechanism / ADR-0059 Amendment 1 default / issue #74).
 *
 * SDK field: notify_on_auto_escalate: bool (default true since Amendment 1 — additive,
 * backward-compatible; existing persisted configs keep their stored value).
 *
 * When ON (default): notifier uses is_alert_worthy(threat, threshold) — band OR escalation
 * tier <= 2 — so a HIGH ALERT / escalation-tier actor (allowed-through but dispositioned
 * suspicious/malicious) notifies out of the box. When OFF: notifier gates on the
 * Notification threshold severity band only.
 *
 * Default ON per ADR-0059 Amendment 1: the ADR-0067 assertion gate already bounds the
 * population that can reach tier <= 2 to the triage-queue population, so quiet chat is
 * preserved by the gate, not by this toggle. The toggle still exists so an operator can
 * opt back OUT to band-only notifications.
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
        Default ON (ADR-0059 Amendment 1): a HIGH ALERT / escalation-tier actor (tier &le; 2)
        notifies even below the Notification threshold. Quiet chat is preserved by the
        assertion gate upstream, not by this toggle — turn it off to fall back to
        Notification-threshold-only alerting.
      </div>
    </div>
  )
}
