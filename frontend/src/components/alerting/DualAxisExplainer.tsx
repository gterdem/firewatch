/**
 * DualAxisExplainer — explains the two-axis alert-worthiness predicate (ADR-0036 / ADR-0059 D2).
 *
 * The two axes are NEVER collapsed into one number (ADR-0036):
 *   Axis 1 — score band ≥ Triage threshold (severity-based).
 *   Axis 2 — auto-escalate tier from the ESCALATION_POLICY registry (action-aware).
 *
 * This component renders a short, plain-language statement helping operators understand why a
 * low-score threat might still surface in the banner (because its escalation tier fires).
 *
 * READ-ONLY — no controls. Used inside AlertingPolicyPanel.
 */

const CONTAINER_STYLE: React.CSSProperties = {
  padding: '10px 14px',
  borderRadius: 6,
  background: 'var(--fw-bg2)',
  border: '1px solid var(--fw-border-l)',
  fontSize: 'var(--fw-fs-sm)',
  fontFamily: 'var(--fw-font-ui)',
  color: 'var(--fw-t2)',
  lineHeight: 1.55,
}

const AXIS_STYLE: React.CSSProperties = {
  display: 'flex',
  gap: 6,
  alignItems: 'flex-start',
  marginTop: 6,
}

const BULLET_STYLE: React.CSSProperties = {
  fontWeight: 'var(--fw-fw-semibold)' as React.CSSProperties['fontWeight'],
  color: 'var(--fw-t1)',
  whiteSpace: 'nowrap',
}

export function DualAxisExplainer() {
  return (
    <div data-testid="dual-axis-explainer" style={CONTAINER_STYLE}>
      <span style={{ fontWeight: 'var(--fw-fw-semibold)' as React.CSSProperties['fontWeight'], color: 'var(--fw-t1)' }}>
        A threat is alert-worthy when EITHER axis fires:
      </span>
      <div style={AXIS_STYLE}>
        <span style={BULLET_STYLE}>1.</span>
        <span>
          <strong>Score band axis</strong> — threat level meets or exceeds the{' '}
          <em>Triage threshold</em> above.
        </span>
      </div>
      <div style={AXIS_STYLE}>
        <span style={BULLET_STYLE}>2.</span>
        <span>
          <strong>Escalation tier axis</strong> — the detection rule's{' '}
          <em>auto_escalate</em> flag is set, making the threat surface regardless of score.
        </span>
      </div>
    </div>
  )
}
