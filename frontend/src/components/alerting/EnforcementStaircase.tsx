/**
 * EnforcementStaircase — visual representation of the enforcement tiers (ADR-0033 / ADR-0015).
 *
 * Three tiers (the staircase):
 *   Tier A — WARN:              ACTIVE — fires on every alert-worthy detection.
 *   Tier B — Require approval:  ACTIVE — escalated detections require an explicit Block action.
 *   Tier C — Auto-block:        GREYED / DISABLED — labelled "coming with SOAR" (ADR-0033 seam).
 *
 * ADR-0033: the auto-block tier is the SIEM-now/SOAR-later seam. It is displayed but greyed
 * to indicate planned future capability, not a hidden omission.
 * ADR-0015: tiered-autonomy ceiling — automated enforcement stays below Tier C until SOAR lands.
 *
 * READ-ONLY — no controls. Used inside AlertingPolicyPanel.
 */

const TIER_STYLE_BASE: React.CSSProperties = {
  display: 'flex',
  alignItems: 'center',
  gap: 10,
  padding: '8px 12px',
  borderRadius: 6,
  border: '1px solid var(--fw-border)',
  marginBottom: 8,
  fontFamily: 'var(--fw-font-ui)',
  fontSize: 'var(--fw-fs-sm)',
}

const ACTIVE_STYLE: React.CSSProperties = {
  ...TIER_STYLE_BASE,
  background: 'var(--fw-bg2)',
  color: 'var(--fw-t1)',
}

const GREYED_STYLE: React.CSSProperties = {
  ...TIER_STYLE_BASE,
  background: 'var(--fw-bg1)',
  color: 'var(--fw-t3)',
  opacity: 0.65,
  cursor: 'not-allowed',
}

const BADGE_ACTIVE: React.CSSProperties = {
  padding: '2px 8px',
  borderRadius: 4,
  background: 'var(--fw-tint-green)',
  color: 'var(--fw-green)',
  fontSize: 'var(--fw-fs-xs)',
  fontWeight: 'var(--fw-fw-semibold)' as React.CSSProperties['fontWeight'],
  whiteSpace: 'nowrap',
  border: '1px solid var(--fw-tint-green-bd)',
}

const BADGE_COMING: React.CSSProperties = {
  padding: '2px 8px',
  borderRadius: 4,
  background: 'var(--fw-bg3)',
  color: 'var(--fw-t3)',
  fontSize: 'var(--fw-fs-xs)',
  fontWeight: 'var(--fw-fw-semibold)' as React.CSSProperties['fontWeight'],
  whiteSpace: 'nowrap',
  border: '1px dashed var(--fw-border)',
}

const STEP_LABEL: React.CSSProperties = {
  fontWeight: 'var(--fw-fw-semibold)' as React.CSSProperties['fontWeight'],
  flex: 1,
}

const STEP_DESC: React.CSSProperties = {
  fontSize: 'var(--fw-fs-xs)',
  color: 'var(--fw-t3)',
  marginTop: 2,
}

function TierRow({
  step,
  label,
  description,
  active,
  comingSoon = false,
}: {
  step: string
  label: string
  description: string
  active: boolean
  comingSoon?: boolean
}) {
  return (
    <div
      style={active ? ACTIVE_STYLE : GREYED_STYLE}
      data-testid={`enforcement-tier-${step.toLowerCase().replace(/\s/g, '-')}`}
      aria-disabled={!active}
    >
      <div style={{ flex: 1 }}>
        <div style={STEP_LABEL}>{label}</div>
        <div style={STEP_DESC}>{description}</div>
      </div>
      {active && !comingSoon && (
        <span style={BADGE_ACTIVE} data-testid={`tier-badge-active-${step}`}>
          Active
        </span>
      )}
      {comingSoon && (
        <span style={BADGE_COMING} data-testid={`tier-badge-coming-${step}`}>
          coming with SOAR
        </span>
      )}
    </div>
  )
}

export function EnforcementStaircase() {
  return (
    <div data-testid="enforcement-staircase">
      <TierRow
        step="warn"
        label="WARN"
        description="Log the detection and surface it in the triage banner."
        active
      />
      <TierRow
        step="require-approval"
        label="Require approval"
        description="Escalated detections require an explicit Block action from the operator."
        active
      />
      <TierRow
        step="auto-block"
        label="Auto-block"
        description="Automatically block the actor without operator confirmation."
        active={false}
        comingSoon
      />
    </div>
  )
}
