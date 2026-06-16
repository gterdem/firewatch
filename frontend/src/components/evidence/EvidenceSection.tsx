/**
 * EvidenceSection — score-breakdown section with clickable evidence factors.
 *
 * Integrates into IpPanel as the "Evidence" block inside the score section.
 * Consumes the useEvidenceChain hook and renders:
 *   1. EvidenceFactorRow per factor from the evidence chain.
 *   2. EvidenceFooter at the bottom with API-derived event/rule counts.
 *
 * Falls back gracefully when evidence is unavailable or the IP has no events:
 *   - Loading: renders nothing (the score breakdown from ThreatScore renders
 *     instead as usual; the evidence rows appear once the fetch resolves).
 *   - Empty (404): renders factor rows without expand toggles + empty footer.
 *   - Error: renders an error note without fabricated counts.
 *
 * ADR-0035: ProvenanceChip on every factor row (delegated to EvidenceFactorRow).
 * WCAG 2.1.1: expand toggles are keyboard-operable (delegated to EvidenceFactorRow).
 * No LLM call is triggered (ai-engine-invariants boundary — the endpoint enforces this).
 *
 * SECURITY (ADR-0029 D3): all EventSummary fields are attacker-controlled.
 * Rendered as text nodes only — never via dangerouslySetInnerHTML.
 */

import { useEvidenceChain } from '../../hooks/useEvidenceChain'
import { EvidenceFactorRow } from './EvidenceFactorRow'
import { EvidenceFooter } from './EvidenceFooter'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SECTION_LABEL_STYLE: React.CSSProperties = {
  fontSize: 10,
  fontWeight: 700,
  color: 'var(--fw-t3)',
  textTransform: 'uppercase',
  letterSpacing: '.5px',
  marginBottom: 6,
}

// ---------------------------------------------------------------------------
// EvidenceSection
// ---------------------------------------------------------------------------

export interface EvidenceSectionProps {
  /** The actor IP to fetch evidence for. */
  ip: string
}

export function EvidenceSection({ ip }: EvidenceSectionProps) {
  const { status, data, error } = useEvidenceChain(ip)

  // While loading and no data yet — render nothing; the score breakdown from
  // ThreatScore covers this section until evidence is ready.
  if (status === 'loading') {
    return null
  }

  // Error state — show a minimal degrade note (no spinner-forever).
  if (status === 'error') {
    return (
      <section
        aria-label="Score evidence"
        data-testid="evidence-section"
        style={{ marginTop: 12 }}
      >
        <div style={SECTION_LABEL_STYLE}>Score evidence</div>
        <p
          data-testid="evidence-section-error"
          style={{ fontSize: 12, color: 'var(--fw-t3)' }}
        >
          Evidence chain unavailable
        </p>
        <EvidenceFooter chain={null} error={error} />
      </section>
    )
  }

  // Empty state — IP has no stored events (404). Show factor rows without links.
  // data is null; factors list is empty — show the footer only.
  if (status === 'empty') {
    return (
      <section
        aria-label="Score evidence"
        data-testid="evidence-section"
        style={{ marginTop: 12 }}
      >
        <div style={SECTION_LABEL_STYLE}>Score evidence</div>
        <EvidenceFooter chain={null} isEmpty />
      </section>
    )
  }

  // OK state — evidence chain loaded.
  if (status === 'ok' && data !== null && data.factors.length > 0) {
    return (
      <section
        aria-label="Score evidence"
        data-testid="evidence-section"
        style={{ marginTop: 12 }}
      >
        <div style={SECTION_LABEL_STYLE}>Score evidence</div>

        <div data-testid="evidence-factor-list">
          {data.factors.map((item) => (
            <EvidenceFactorRow
              key={item.factor}
              item={item}
              evidenceEmpty={false}
            />
          ))}
        </div>

        <EvidenceFooter chain={data} />
      </section>
    )
  }

  // OK but empty factors — degenerate case; render footer with zero counts.
  if (status === 'ok' && data !== null && data.factors.length === 0) {
    return (
      <section
        aria-label="Score evidence"
        data-testid="evidence-section"
        style={{ marginTop: 12 }}
      >
        <div style={SECTION_LABEL_STYLE}>Score evidence</div>
        <EvidenceFooter chain={data} />
      </section>
    )
  }

  return null
}
