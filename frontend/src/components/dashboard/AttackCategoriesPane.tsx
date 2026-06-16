/**
 * AttackCategoriesPane — "Attacks (attempted)" pane (issue #206).
 *
 * Data source: per-actor `attack_types` strings from GET /threats (ThreatScore[]).
 * Aggregation: count the number of threat actors that reported each attack type.
 *   e.g. if 3 actors have "SQL Injection" in their attack_types[] → count 3.
 * This represents "how many distinct attackers attempted this class of attack",
 * which is the correct "attempted" framing (not event-count, which would be
 * dispositions-adjacent and mislead the analyst).
 *
 * MITRE mapping: where a clean MITRE ATT&CK tactic label exists for a raw engine
 * label, a human-readable alias is shown; otherwise the engine label is shown
 * verbatim (ADR-0014). The mapping is static and conservative — unknown labels
 * pass through unchanged.
 *
 * Provenance: the attack-type strings are rule-engine output → ProvenanceChip RULE
 * (ADR-0035 §1: derivation determined at authorship; this pane authors rule-derived content).
 * The RULE chip is rendered in the Panel header by the parent (DashboardRoute).
 *
 * Click-through: clicking a bar navigates to /logs?q=<type> so the analyst reaches
 * filtered evidence in one click (issue #206 EARS criterion 3).
 *
 * Pure helpers (aggregateAttackTypes, applyMitreLabel) live in attackTypeUtils.ts
 * (react-refresh/only-export-components rule: this file exports only the component).
 *
 * ADR-0028 D6: all colors via var(--fw-*) tokens.
 * ADR-0029 D3: attack_types are attacker-influenced; rendered as text nodes only.
 */

import { useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import type { ThreatScore } from '../../api/types'
import HorizontalBarList from './HorizontalBarList'
import { aggregateAttackTypes } from './attackTypeUtils'

interface AttackCategoriesPaneProps {
  /** Threat scores from GET /threats. */
  threats: ThreatScore[]
}

/** Map an attack-type label to a DS color token. No raw hex. */
function attackTypeColor(label: string): string {
  const lower = label.toLowerCase()
  if (lower.includes('sql') || lower.includes('injection')) return 'var(--fw-orange)'
  if (lower.includes('brute') || lower.includes('force') || lower.includes('t1110')) return 'var(--fw-red)'
  if (lower.includes('scan') || lower.includes('t1595')) return 'var(--fw-blue)'
  if (lower.includes('xss')) return 'var(--fw-accent)'
  if (lower.includes('lfi') || lower.includes('path') || lower.includes('t1083')) return 'var(--fw-orange)'
  if (lower.includes('malware') || lower.includes('t1587')) return 'var(--fw-red)'
  if (lower.includes('command') || lower.includes('cmdi') || lower.includes('t1059')) return 'var(--fw-purple)'
  if (lower.includes('geo')) return 'var(--fw-cyan)'
  return 'var(--fw-t3)'
}

export default function AttackCategoriesPane({ threats }: AttackCategoriesPaneProps) {
  const navigate = useNavigate()
  const rows = useMemo(() => aggregateAttackTypes(threats), [threats])

  function handleBarClick(label: string) {
    // Strip the MITRE suffix for the search query so the raw category matches logs.
    // e.g. "SQL Injection (T1190)" → "SQL Injection"
    const searchTerm = label.replace(/\s*\([^)]+\)\s*$/, '').trim()
    navigate(`/logs?q=${encodeURIComponent(searchTerm)}`)
  }

  if (rows.length === 0) {
    // Compact empty-state: a single centred row rather than a large blank area.
    // LOW-score actors often have no attack_types[] (F5-D3 sparsity) — treat as
    // a proper empty-state, not dead space (issue #577).
    return (
      <div
        data-testid="attacks-empty"
        style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          gap: 4,
          padding: '16px 12px',
          borderRadius: 'var(--fw-r-sm)',
          background: 'var(--fw-bg-card)',
          border: '1px dashed var(--fw-border)',
        }}
      >
        <span aria-hidden="true" style={{ fontSize: 20, opacity: 0.45 }}>🛡️</span>
        <p
          style={{
            margin: 0,
            fontSize: 12,
            color: 'var(--fw-t3)',
            textAlign: 'center',
            fontFamily: 'var(--fw-font-ui)',
          }}
        >
          No attack-type data — low-score actors may not have attack classifications yet
        </p>
      </div>
    )
  }

  return (
    <div data-testid="attack-categories-pane">
      <HorizontalBarList
        rows={rows}
        colorFor={attackTypeColor}
        onBarClick={handleBarClick}
        data-testid="attack-categories-bars"
      />
    </div>
  )
}
