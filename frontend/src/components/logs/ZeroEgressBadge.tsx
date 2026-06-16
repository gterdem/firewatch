/**
 * ZeroEgressBadge — ML-5 (#433) EARS-2.
 *
 * Persistent "Local-only · 0 bytes egressed" trust indicator for any page
 * that performs local inference or processes threat data without off-host calls.
 *
 * Design rationale (ADR-0015, ADR-0026):
 *   - The AI engine runs on Ollama (loopback only, ADR-0026).
 *   - No telemetry, no cloud API, no external model endpoints.
 *   - This badge makes that guarantee visible to analysts.
 *
 * Reuses the ProvenanceChip colour vocabulary (ADR-0035 §2):
 *   - Styled like a RULE chip (muted/neutral) to communicate a deterministic,
 *     infrastructure-level guarantee — not an LLM-derived label.
 *
 * SECURITY (ADR-0029 D3):
 *   - All text is a static constant; no attacker-controlled values are rendered.
 *
 * Props:
 *   compact — when true, shows only the shield icon + "Local-only" (no bytes copy).
 *             Useful in tight header contexts. Defaults to false.
 */

import type { HTMLAttributes } from 'react'

export interface ZeroEgressBadgeProps extends Omit<HTMLAttributes<HTMLSpanElement>, 'children'> {
  /** Show compact form (icon + "Local-only" only). Default: false. */
  compact?: boolean
}

export function ZeroEgressBadge({ compact = false, style, ...rest }: ZeroEgressBadgeProps) {
  const label = compact ? 'Local-only' : 'Local-only · 0 bytes egressed'

  return (
    <span
      role="status"
      aria-label="Zero-egress: all inference runs locally; no data leaves this machine"
      data-testid="zero-egress-badge"
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 4,
        padding: '2px 8px',
        borderRadius: 'var(--fw-r-xs)',
        fontSize: 'var(--fw-fs-2xs)',
        fontWeight: 'var(--fw-fw-semibold)',
        fontFamily: 'var(--fw-font-ui)',
        textTransform: 'uppercase',
        letterSpacing: 'var(--fw-ls-label)',
        border: '1px solid var(--fw-border)',
        background: 'var(--fw-bg-input)',
        color: 'var(--fw-t2)',
        whiteSpace: 'nowrap',
        lineHeight: 1.6,
        ...style,
      }}
      {...rest}
    >
      {/* Shield icon — SVG inline so no external load (loopback policy, ADR-0026). */}
      <svg
        width="10"
        height="11"
        viewBox="0 0 10 11"
        fill="none"
        aria-hidden="true"
        style={{ flexShrink: 0 }}
      >
        <path
          d="M5 1L9 2.5V5.5C9 7.8 7.3 9.9 5 10.5C2.7 9.9 1 7.8 1 5.5V2.5L5 1Z"
          stroke="currentColor"
          strokeWidth="1"
          fill="none"
        />
        <path
          d="M3 5.5L4.5 7L7 4"
          stroke="currentColor"
          strokeWidth="1"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
      {label}
    </span>
  )
}
