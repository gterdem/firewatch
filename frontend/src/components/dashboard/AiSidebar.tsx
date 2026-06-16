/**
 * AiSidebar — kit `.sidebar` (issue #113).
 *
 * Panel ORDER (CR6 #617 — orient → respond scan):
 *   📈 Risk Movers          — "who is escalating RIGHT NOW?" (orient)
 *   ⚡ Recommended actions  — "what should I do about it?" (respond)
 *
 * Risk Movers answers the orientation question first; recommended actions are the
 * follow-on response step — matching the SOC triage F-pattern scan order.
 *
 * Recommended actions is shown in compact mode (top-3 + "view all" affordance)
 * to match sidebar density and honor the no-inner-scrollbar rule.
 *
 * Data: GET /threats (ThreatScore[]). Non-fatal: sidebar degrades gracefully
 * if threats array is empty (ADR-0015).
 *
 * COLLISION NOTE (CR6 #617): This file owns panel ORDER and the compact recommendations
 * card only. Do NOT edit RiskMovers internals (CR4/CR5).
 *
 * SECURITY (ADR-0029 D3): all fields are attacker-controlled (IP).
 * Rendered as text nodes only — no dangerouslySetInnerHTML.
 *
 * ADR-0028 D6: no raw hex — all colors via var(--fw-*) tokens.
 * ADR-0033: actions remain advisory; onAction seam only.
 * ADR-0035: provenance chips retained on every recommendation card.
 */

import type { ThreatScore, HealthResponse } from '../../api/types'
import type { OnAction } from '../../lib/triageActions'
import RiskMovers, { WINDOW_LABEL } from './RiskMovers'
import RecommendationCards from './RecommendationCards'

interface AiSidebarProps {
  threats: ThreatScore[]
  /** Action seam — forwarded to compact RecommendationCards (ADR-0033). */
  onAction: OnAction
  /**
   * Authoritative AI engine state from GET /health (fix #180).
   * null = health in flight or failed — RecommendationCards degrades to rules-only.
   */
  health?: HealthResponse | null
}

export default function AiSidebar({ threats, onAction, health }: AiSidebarProps) {
  return (
    <div
      style={{ display: 'flex', flexDirection: 'column', gap: 12 }}
      data-testid="ai-sidebar"
    >
      {/* 📈 Risk Movers — FIRST (orient: "who is escalating RIGHT NOW?") */}
      {/* replaces the former "IP threat scores" card (#251, #331) */}
      <SbCard title={`📈 Risk Movers · ${WINDOW_LABEL}`}>
        <RiskMovers threats={threats} />
      </SbCard>

      {/* ⚡ Recommended actions — SECOND (respond: "what do I do about it?") */}
      {/* CR6 (#617): compact mode — top-3 + "view all" affordance; no inner scrollbar. */}
      <SbCard title="⚡ Recommended actions">
        <RecommendationCards
          threats={threats}
          onAction={onAction}
          health={health}
          compact
        />
      </SbCard>
    </div>
  )
}

/**
 * Internal sidebar card — maps to kit `.sb-card`.
 *
 * title is ReactNode so emoji + mixed-case labels are preserved (issue #364).
 * textTransform: uppercase is intentionally absent: the heading text already
 * carries the intended casing ("📈 Risk Movers · 1h") — uppercase was a
 * display bug that also dropped the leading emoji in some browsers.
 */
function SbCard({ title, children }: { title: React.ReactNode; children: React.ReactNode }) {
  return (
    <div
      style={{
        background: 'var(--fw-bg-input)',
        border: '1px solid var(--fw-border)',
        borderRadius: 8,
        padding: 12,
      }}
    >
      <h3
        data-testid="sb-card-title"
        style={{
          fontSize: 11,
          fontWeight: 700,
          color: 'var(--fw-t1)',
          letterSpacing: 0.5,
          marginBottom: 8,
          display: 'flex',
          alignItems: 'center',
          gap: 5,
        }}
      >
        {title}
      </h3>
      {children}
    </div>
  )
}
