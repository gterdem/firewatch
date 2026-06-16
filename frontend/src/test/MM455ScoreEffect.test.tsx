/**
 * Tests for MM #455 — plain-English score-effect causal line + confidence-vs-gate mini-bar.
 *
 * EARS criteria covered:
 *
 * EARS-MM455-1: WHEN score_derivation='rule' AND threat_level is LOW or MEDIUM,
 *   THE score-effect line SHALL state the verdict left the rule-based score alone
 *   because the verdict was low-risk (NOT imply confidence was the gating reason).
 *   The mini-bar SHALL NOT be rendered.
 *
 * EARS-MM455-2: WHEN score_derivation='rule' AND threat_level is HIGH or CRITICAL
 *   AND confidence <= CONFIDENCE_HIGH_THRESHOLD,
 *   THE score-effect line SHALL state the AI leaned high/critical-risk but wasn't
 *   confident enough (showing band word + raw value) to raise the rule-based score.
 *   The mini-bar (verdict-confidence-minibar) SHALL be present, showing a gate line
 *   and a caption with the confidence value, gate value, and "below by" delta.
 *
 * EARS-MM455-3: WHEN score_derivation includes 'ai' (boost fired),
 *   THE score-effect line SHALL state the AI was confident enough to raise the score
 *   (boost applied). The mini-bar SHALL NOT be rendered.
 *
 * EARS-MM455-4: THE gate value in the mini-bar caption SHALL come from the imported
 *   CONFIDENCE_HIGH_THRESHOLD constant — never a different hard-coded number.
 *   (Verified by checking the caption shows the same value as the constant.)
 *
 * EARS-MM455-5: WHEN threat_level is HIGH/CRITICAL-under-confident, THE mini-bar
 *   SHALL be presentational only — no interactive controls.
 *
 * EARS-MM455-6: WHEN threat_level is LOW/MEDIUM, THE mini-bar testid
 *   SHALL NOT be in the document (suppressed, not hidden).
 */

import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { VerdictCard } from '../components/ai/ledger/VerdictCard'
import EntityPanelProvider from '../components/entity/EntityPanelProvider'
import type { AnalysisSummary } from '../api/types'
import { CONFIDENCE_HIGH_THRESHOLD } from '../lib/provenance'

// ---------------------------------------------------------------------------
// Fixtures (RFC 5737 IPs throughout)
// ---------------------------------------------------------------------------

const BASE_ANALYSIS: AnalysisSummary = {
  id: 1,
  ip: '192.0.2.1',
  kind: 'concise',
  model: 'qwen3:8b',
  endpoint_host: '127.0.0.1:11434',
  ai_status: 'ok',
  threat_level: 'HIGH',
  confidence: 0.87,
  score: 78,
  score_derivation: 'ai',
  latency_ms: 1200,
  prompt_tokens: null,
  completion_tokens: null,
  schema_version: 1,
  created_at: '2026-06-12T10:00:00Z',
  feedback: null,
}

/** Case 1: Moved — boost fired. */
const ANALYSIS_MOVED_AI: AnalysisSummary = {
  ...BASE_ANALYSIS,
  score_derivation: 'ai',
  threat_level: 'HIGH',
  confidence: 0.87,
}

/** Case 1b: Moved with ai+rule. */
const ANALYSIS_MOVED_AI_PLUS_RULE: AnalysisSummary = {
  ...BASE_ANALYSIS,
  score_derivation: 'ai+rule',
  threat_level: 'CRITICAL',
  confidence: 0.92,
}

/** Case 2: HIGH verdict, under-confident — confidence 0.60 < gate 0.70. */
const ANALYSIS_HIGH_UNDER_CONFIDENT: AnalysisSummary = {
  ...BASE_ANALYSIS,
  id: 2,
  ip: '192.0.2.2',
  score_derivation: 'rule',
  threat_level: 'HIGH',
  confidence: 0.60,
  score: 30,
}

/** Case 2b: CRITICAL verdict, under-confident — confidence 0.55 < gate 0.70. */
const ANALYSIS_CRITICAL_UNDER_CONFIDENT: AnalysisSummary = {
  ...BASE_ANALYSIS,
  id: 3,
  ip: '192.0.2.3',
  score_derivation: 'rule',
  threat_level: 'CRITICAL',
  confidence: 0.55,
  score: 30,
}

/** Case 3: LOW verdict — confidence not the gate reason. */
const ANALYSIS_LOW_VERDICT: AnalysisSummary = {
  ...BASE_ANALYSIS,
  id: 4,
  ip: '192.0.2.4',
  score_derivation: 'rule',
  threat_level: 'LOW',
  confidence: 0.30,
  score: 10,
}

/** Case 3b: MEDIUM verdict — confidence not the gate reason. */
const ANALYSIS_MEDIUM_VERDICT: AnalysisSummary = {
  ...BASE_ANALYSIS,
  id: 5,
  ip: '192.0.2.5',
  score_derivation: 'rule',
  threat_level: 'MEDIUM',
  confidence: 0.50,
  score: 20,
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

function renderCard(analysis: AnalysisSummary) {
  render(
    <MemoryRouter>
      <EntityPanelProvider>
        <VerdictCard analysis={analysis} />
      </EntityPanelProvider>
    </MemoryRouter>,
  )
}

// ---------------------------------------------------------------------------
// EARS-MM455-3: AI moved the score (boost fired)
// ---------------------------------------------------------------------------

describe('MM #455 — score-effect: moved cases (boost fired)', () => {
  it('score_derivation="ai": line states AI was confident enough to raise the score', () => {
    renderCard(ANALYSIS_MOVED_AI)
    const effectLine = screen.getByTestId('verdict-score-effect')
    expect(effectLine).toBeInTheDocument()
    expect(effectLine).toHaveTextContent('confident enough to raise the score')
    expect(effectLine).toHaveTextContent('boost applied')
  })

  it('score_derivation="ai+rule": same "confident enough" wording', () => {
    renderCard(ANALYSIS_MOVED_AI_PLUS_RULE)
    const effectLine = screen.getByTestId('verdict-score-effect')
    expect(effectLine).toHaveTextContent('confident enough to raise the score')
    expect(effectLine).toHaveTextContent('boost applied')
  })

  it('moved cards: mini-bar is NOT rendered (EARS-MM455-3)', () => {
    renderCard(ANALYSIS_MOVED_AI)
    expect(screen.queryByTestId('verdict-confidence-minibar')).not.toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// EARS-MM455-2: HIGH/CRITICAL under-confident — mini-bar present
// ---------------------------------------------------------------------------

describe('MM #455 — score-effect: HIGH verdict, under-confident (sole mini-bar case)', () => {
  it('line states AI leaned High-risk but not confident enough', () => {
    renderCard(ANALYSIS_HIGH_UNDER_CONFIDENT)
    const effectLine = screen.getByTestId('verdict-score-effect')
    expect(effectLine).toBeInTheDocument()
    expect(effectLine).toHaveTextContent('leaned High-risk')
    expect(effectLine).toHaveTextContent("wasn't confident enough")
    expect(effectLine).toHaveTextContent('rule-based score')
  })

  it('line includes confidence band word (Medium for 0.60)', () => {
    renderCard(ANALYSIS_HIGH_UNDER_CONFIDENT)
    const effectLine = screen.getByTestId('verdict-score-effect')
    expect(effectLine).toHaveTextContent('Medium')
  })

  it('line includes raw confidence value (0.60)', () => {
    renderCard(ANALYSIS_HIGH_UNDER_CONFIDENT)
    const effectLine = screen.getByTestId('verdict-score-effect')
    expect(effectLine).toHaveTextContent('0.60')
  })

  it('mini-bar IS rendered on HIGH-under-confident card (EARS-MM455-2)', () => {
    renderCard(ANALYSIS_HIGH_UNDER_CONFIDENT)
    expect(screen.getByTestId('verdict-confidence-minibar')).toBeInTheDocument()
  })

  it('mini-bar caption shows confidence value vs gate value and "below by" delta', () => {
    renderCard(ANALYSIS_HIGH_UNDER_CONFIDENT)
    const caption = screen.getByTestId('verdict-minibar-caption')
    // Caption format: "{conf} vs {gate} gate · below by {delta}"
    expect(caption).toHaveTextContent('0.60')
    expect(caption).toHaveTextContent('gate')
    expect(caption).toHaveTextContent('below by')
  })

  it('mini-bar gate value matches CONFIDENCE_HIGH_THRESHOLD constant (EARS-MM455-4)', () => {
    renderCard(ANALYSIS_HIGH_UNDER_CONFIDENT)
    const caption = screen.getByTestId('verdict-minibar-caption')
    // Gate value is CONFIDENCE_HIGH_THRESHOLD (0.70). The caption must show this exact value.
    const expectedGate = CONFIDENCE_HIGH_THRESHOLD.toFixed(2)
    expect(caption.textContent).toContain(expectedGate)
  })

  it('mini-bar gate line element is present (presentational, no interaction — EARS-MM455-5)', () => {
    renderCard(ANALYSIS_HIGH_UNDER_CONFIDENT)
    const gateEl = screen.getByTestId('verdict-minibar-gate-line')
    expect(gateEl).toBeInTheDocument()
    // No button role or interactive role — purely presentational
    expect(gateEl.tagName.toLowerCase()).not.toBe('button')
    expect(gateEl.getAttribute('role')).toBeNull()
  })
})

describe('MM #455 — score-effect: CRITICAL verdict, under-confident', () => {
  it('line states AI leaned Critical-risk but not confident enough', () => {
    renderCard(ANALYSIS_CRITICAL_UNDER_CONFIDENT)
    const effectLine = screen.getByTestId('verdict-score-effect')
    expect(effectLine).toHaveTextContent('leaned Critical-risk')
    expect(effectLine).toHaveTextContent("wasn't confident enough")
  })

  it('mini-bar IS rendered on CRITICAL-under-confident card', () => {
    renderCard(ANALYSIS_CRITICAL_UNDER_CONFIDENT)
    expect(screen.getByTestId('verdict-confidence-minibar')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// EARS-MM455-1: LOW/MEDIUM verdict — confidence NOT the gating reason
// ---------------------------------------------------------------------------

describe('MM #455 — score-effect: LOW verdict (confidence irrelevant to gate)', () => {
  it('line states AI read this as Low-risk and left rule-based score alone', () => {
    renderCard(ANALYSIS_LOW_VERDICT)
    const effectLine = screen.getByTestId('verdict-score-effect')
    expect(effectLine).toBeInTheDocument()
    expect(effectLine).toHaveTextContent('Low-risk')
    expect(effectLine).toHaveTextContent('left the rule-based score alone')
  })

  it('line explains that only High/Critical-risk verdicts can raise the score', () => {
    renderCard(ANALYSIS_LOW_VERDICT)
    const effectLine = screen.getByTestId('verdict-score-effect')
    // The parenthetical explanation must be present for glass-box honesty
    expect(effectLine).toHaveTextContent('Only a High- or Critical-risk verdict can raise the score')
  })

  it('LOW verdict: mini-bar is NOT rendered (EARS-MM455-6)', () => {
    renderCard(ANALYSIS_LOW_VERDICT)
    expect(screen.queryByTestId('verdict-confidence-minibar')).not.toBeInTheDocument()
  })

  it('LOW verdict: line does NOT imply confidence was the gating reason', () => {
    renderCard(ANALYSIS_LOW_VERDICT)
    const effectLine = screen.getByTestId('verdict-score-effect')
    // Must NOT say "confident enough" or "confidence" as a reason the score didn't move
    expect(effectLine.textContent).not.toContain("wasn't confident enough")
  })
})

describe('MM #455 — score-effect: MEDIUM verdict (confidence irrelevant to gate)', () => {
  it('line states AI read this as Medium-risk and left rule-based score alone', () => {
    renderCard(ANALYSIS_MEDIUM_VERDICT)
    const effectLine = screen.getByTestId('verdict-score-effect')
    expect(effectLine).toHaveTextContent('Medium-risk')
    expect(effectLine).toHaveTextContent('left the rule-based score alone')
  })

  it('MEDIUM verdict: mini-bar is NOT rendered (EARS-MM455-6)', () => {
    renderCard(ANALYSIS_MEDIUM_VERDICT)
    expect(screen.queryByTestId('verdict-confidence-minibar')).not.toBeInTheDocument()
  })

  it('MEDIUM verdict: line does NOT imply confidence was the gating reason', () => {
    renderCard(ANALYSIS_MEDIUM_VERDICT)
    const effectLine = screen.getByTestId('verdict-score-effect')
    expect(effectLine.textContent).not.toContain("wasn't confident enough")
  })
})
