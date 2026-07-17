/**
 * FalsePositiveButton — the entity-panel detection-row False Positive action
 * (issue #45, ADR-0072 D6 — false positive targets a RULE, not the actor;
 * it lives on the detection row inside the entity panel, never the actor
 * card in the triage queue — see TriageBanner.tsx's ActorChip, which
 * deliberately does NOT offer this action).
 *
 * Calls `recordFalsePositive(actorIp, ruleName)` (lib/triageActions.ts) —
 * best-effort `POST /decisions {verb: 'false_positive', rule_name}`
 * (ADR-0072 D2/D4). Suppression is recomputed server-side at read time; this
 * component holds no lifecycle/suppression logic of its own (ADR-0072 D3
 * "client contract" — the client renders what the server computed on the
 * NEXT fetch). The local "Reported" state here is UI feedback only.
 *
 * ADR-0072's fail-toward-visibility boundary: an anonymous/rule-less
 * detection can never be FP-suppressed — callers MUST only render this
 * button when a non-empty `ruleName` identity exists (the caller in
 * IpPanel.tsx gates on the raw stored event's `rule_name` field, NOT the
 * rule-catalog display name — see IpPanel.tsx's `fpRuleName` derivation).
 *
 * SECURITY (ADR-0029 D3): `ruleName` is attacker/source-declared free text —
 * rendered as a text node only (via the aria-label string and button label),
 * never dangerouslySetInnerHTML.
 */

import { useState } from 'react'
import { recordFalsePositive } from '../../../lib/triageActions'
import { ACTION_LABEL } from '../../../lib/escalationCopy'

interface FalsePositiveButtonProps {
  actorIp: string
  ruleName: string
  'data-testid'?: string
}

export default function FalsePositiveButton({
  actorIp,
  ruleName,
  'data-testid': testId,
}: FalsePositiveButtonProps) {
  const [reported, setReported] = useState(false)

  function handleClick() {
    setReported(true)
    void recordFalsePositive(actorIp, ruleName)
  }

  return (
    <button
      type="button"
      data-testid={testId ?? 'false-positive-button'}
      aria-label={
        reported
          ? `Reported ${ruleName} as false positive`
          : `Mark ${ruleName} as false positive`
      }
      disabled={reported}
      onClick={handleClick}
      style={{
        marginLeft: 6,
        background: 'none',
        border: '1px solid var(--fw-border)',
        borderRadius: 4,
        padding: '0px 5px',
        fontSize: 10,
        color: reported ? 'var(--fw-t3)' : 'var(--fw-t2)',
        cursor: reported ? 'default' : 'pointer',
        lineHeight: 1.6,
        whiteSpace: 'nowrap',
      }}
    >
      {reported ? 'Reported' : ACTION_LABEL.falsePositive}
    </button>
  )
}
