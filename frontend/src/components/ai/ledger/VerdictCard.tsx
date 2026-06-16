/**
 * VerdictCard — read-only card for one persisted AI analysis (MK-3, ADR-0043/0044).
 *
 * Renders the stored analysis summary: AI prose summary fields with an AI
 * ProvenanceChip (ADR-0035), ConfidenceLabel (ADR-0036 banded), ScoreBadge
 * (ADR-0036), model identity, and creation age.
 *
 * Reuses shipped DS components — never forks:
 *   ProvenanceChip  (ADR-0035 provenance)
 *   ConfidenceLabel (ADR-0036 word-banded confidence)
 *   ScoreBadge      (ADR-0036 banded score — engine band from score, NOT AI threat_level)
 *   ClickableIp     (ADR-0037 entity slide-over)
 *
 * ADR-0036 D1 (score-effect honesty):
 *   - ScoreBadge receives the ENGINE band derived from the numeric score
 *     (via scoreToSeverityBand), NOT the AI verdict's threat_level.
 *     The AI's threat_level is a SEPARATE artifact — rendered in its own labeled area.
 *   - A short deterministic "score-effect" line states whether the AI moved the
 *     score, derived from score_derivation + confidence. No invented constants.
 *
 * SECURITY (ADR-0029 D3):
 *   - All model-authored and attacker-influenced strings (ip, threat_level,
 *     model, ai_status) are rendered as text nodes only — never via
 *     dangerouslySetInnerHTML. The validated_json fields are never echoed here
 *     (they are on the full-record detail endpoint, out of scope for MK-3).
 *
 * ADR-0015: AI being offline is informational; this card only renders for
 *   stored (completed) analyses — it never shows "pending" or "generating".
 *
 * WCAG: card is keyboard-focusable (tabIndex=0, role="article").
 * Note: agree/disagree controls mount here in MK-6; prompt drawer opens in MK-7.
 *
 * D2 reactivity: onFeedbackSubmitted is forwarded to VerdictFeedback so that
 * AIRoute can bump feedbackVersion → AgreementStat re-fetches after each submit.
 */

import { useState } from 'react'
import type { AnalysisSummary } from '../../../api/types'
import { ProvenanceChip, ConfidenceLabel, ScoreBadge } from '../../ds'
import ClickableIp from '../../entity/ClickableIp'
import { formatAnalysisAge } from './coverage'
import { scoreToSeverityBand, confidenceToWord, CONFIDENCE_HIGH_THRESHOLD } from '../../../lib/provenance'
import { VerdictFeedback } from './VerdictFeedback'
// MK-7: prompt-transparency drawer
import { PromptDrawer } from './PromptDrawer'
// MK-11: Re-run analysis — same ticker component, zero forked logic.
import StageTicker from '../../entity/ip/ticker/StageTicker'
import { useStageTicker } from '../../entity/ip/ticker/useStageTicker'
// Issue #534 (ADR-0053 D1): "Open case" affordance — launches case file slide-over.
import { CreateCaseButton } from '../../entity/case/CreateCaseButton'

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface VerdictCardProps {
  /** The analysis summary row from the ledger. */
  analysis: AnalysisSummary
  /** Optional: current timestamp for age calculation (injectable for testing). */
  now?: number
  /**
   * Called after a successful feedback submit on this card (server confirmed).
   * Forwarded from VerdictCardList → AIRoute handleFeedbackChange.
   * AIRoute uses this to bump feedbackVersion → AgreementStat re-fetches (D2 fix).
   */
  onFeedbackSubmitted?: () => void
  /**
   * MK-11: called after a Re-run analysis stream completes on this card.
   * Forwarded from VerdictCardList → AIRoute handleRerunComplete.
   * AIRoute uses this to bump ledgerVersion → useVerdictLedger re-fetches.
   */
  onRerunComplete?: () => void
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Derive the ProvenanceChip derivation for a VerdictCard.
 *
 * A VerdictCard is BY DEFINITION an AI-authored analysis (the prose and verdict
 * come from the model). The chip reflects CONTENT AUTHORSHIP, not score derivation.
 * (ADR-0035 honest provenance / ADR-0043 D1 — chip must not misrepresent authorship.)
 *
 * Rules:
 *   - A ledger record is always AI-authored → chip is at minimum 'ai'.
 *   - If score_derivation is 'ai+rule' (both AI and rules contributed to the score),
 *     we show 'ai+rule' to faithfully represent the mixed signal.
 *   - If score_derivation is 'rule' (AI ran but score stayed rule-derived, e.g.
 *     confidence < threshold), the card still shows 'ai' — the content (verdict prose)
 *     is AI-authored even though the numeric score was not updated. Showing RULE on
 *     an AI-authored card misrepresents what the model did (ADR-0035).
 *   - Fallback: 'ai' (safe default for any unrecognised value).
 */
function deriveCardChip(score_derivation: string | null | undefined): 'ai' | 'ai+rule' {
  if (score_derivation === 'ai+rule') return 'ai+rule'
  // 'ai', 'rule' (AI ran but score stayed rule-derived), null, or unknown → 'ai'
  return 'ai'
}

/**
 * Verdict class — the three causal branches for the score-effect line (MM #455).
 *
 * - 'moved': AI ran and the boost fired (score_derivation includes 'ai').
 * - 'not-moved-low-verdict': AI ran but the verdict was LOW or MEDIUM — the
 *   boost gate requires HIGH or CRITICAL, so confidence was never the gating
 *   reason. Showing a confidence-vs-gate bar here would mislead the reader.
 * - 'not-moved-under-confident': AI ran, verdict was HIGH or CRITICAL, but
 *   confidence fell below the gate. This is the sole case where
 *   confidence-vs-gate is the actual cause.
 */
type ScoreEffectClass =
  | 'moved'
  | 'not-moved-low-verdict'
  | 'not-moved-under-confident'

/**
 * Classify why the AI's verdict did or did not move the score.
 *
 * The boost gate is: threat_level ∈ {CRITICAL, HIGH} AND confidence > CONFIDENCE_HIGH_THRESHOLD.
 * We must faithfully represent which branch applies so the causal line is honest.
 *
 * @param score_derivation - Wire value from the ledger row.
 * @param threat_level     - AI's assessed threat level (from the ledger row).
 * @param confidence       - AI confidence 0–1 (from the ledger row; null = AI off).
 */
function classifyScoreEffect(
  score_derivation: string | null | undefined,
  threat_level: string | null | undefined,
  confidence: number | null | undefined,
): ScoreEffectClass {
  const aiMoved = score_derivation === 'ai' || score_derivation === 'ai+rule'
  if (aiMoved) return 'moved'

  const upperLevel = (threat_level ?? '').toUpperCase()
  const verdictCanBoost = upperLevel === 'CRITICAL' || upperLevel === 'HIGH'

  // Only when the verdict COULD have boosted (HIGH/CRITICAL) but confidence was too low
  // is confidence-vs-gate the real reason. On LOW/MEDIUM verdicts confidence is irrelevant.
  if (verdictCanBoost && confidence != null && confidence <= CONFIDENCE_HIGH_THRESHOLD) {
    return 'not-moved-under-confident'
  }

  return 'not-moved-low-verdict'
}

/**
 * Result of deriving the score-effect presentation (MM #455).
 *
 * - `text`: the plain-English causal sentence shown on every card.
 * - `showMiniBar`: true only on the HIGH/CRITICAL-under-confident card — the one
 *   case where confidence-vs-gate is the actual sole reason the score didn't move.
 *   Suppressed on other cards to avoid misleading the reader (glass-box honesty).
 */
interface ScoreEffectResult {
  text: string
  showMiniBar: boolean
  effectClass: ScoreEffectClass
}

/**
 * Derive the score-effect presentation for a VerdictCard (MM #455).
 *
 * Three plain-English branches, each truthful about the actual cause:
 *
 * 1. AI moved the score → "The AI was confident enough to raise the score (boost applied)."
 * 2. Verdict LOW/MEDIUM → "The AI read this as {level}-risk, so it left the rule-based score
 *    alone. (Only a High- or Critical-risk verdict can raise the score.)"
 * 3. Verdict HIGH/CRITICAL but under-confident → "The AI leaned {level}-risk but wasn't
 *    confident enough ({word}, {value}) to raise the rule-based score…"
 *    PLUS a confidence-vs-gate mini-bar (the sole truthful use of that bar).
 *
 * Gate value comes from the imported `CONFIDENCE_HIGH_THRESHOLD` constant — never hard-coded.
 */
function deriveScoreEffect(
  score_derivation: string | null | undefined,
  threat_level: string | null | undefined,
  confidence: number | null | undefined,
): ScoreEffectResult {
  const effectClass = classifyScoreEffect(score_derivation, threat_level, confidence)

  if (effectClass === 'moved') {
    return {
      text: 'The AI was confident enough to raise the score (boost applied).',
      showMiniBar: false,
      effectClass,
    }
  }

  if (effectClass === 'not-moved-under-confident') {
    const band = confidenceToWord(confidence)
    const confStr = confidence != null ? confidence.toFixed(2) : '—'
    const levelLabel = (threat_level ?? 'HIGH').toUpperCase()
    const displayLevel = levelLabel.charAt(0) + levelLabel.slice(1).toLowerCase()
    return {
      text: `The AI leaned ${displayLevel}-risk but wasn't confident enough (${band}, ${confStr}) to raise the rule-based score. The score you see is still from the rules.`,
      showMiniBar: true,
      effectClass,
    }
  }

  // not-moved-low-verdict: confidence was never the gating reason — don't mention it.
  const levelLabel = (threat_level ?? 'LOW').toUpperCase()
  const displayLevel = levelLabel.charAt(0) + levelLabel.slice(1).toLowerCase()
  return {
    text: `The AI read this as ${displayLevel}-risk, so it left the rule-based score alone. (Only a High- or Critical-risk verdict can raise the score.)`,
    showMiniBar: false,
    effectClass,
  }
}

// ---------------------------------------------------------------------------
// ConfidenceVsGateMiniBar — tiny inline bar (MM #455)
// ---------------------------------------------------------------------------

/**
 * ConfidenceVsGateMiniBar — renders ONLY on HIGH/CRITICAL-under-confident cards.
 *
 * Shows the model's confidence relative to the boost gate in a single bar line.
 * Purely presentational (no interaction), no inner scrollbar, token-styled.
 *
 * The gate value comes from CONFIDENCE_HIGH_THRESHOLD (the shared constant);
 * it is never hard-coded here.
 *
 * SECURITY (ADR-0029 D3): all values are numbers from the ledger — rendered
 * as text nodes and CSS widths (percentages), never via innerHTML.
 */
function ConfidenceVsGateMiniBar({ confidence }: { confidence: number }) {
  const gate = CONFIDENCE_HIGH_THRESHOLD
  // Clamp confidence to [0, 1] defensively (data from server, should be valid).
  const clampedConf = Math.min(1, Math.max(0, confidence))
  const confPct = Math.round(clampedConf * 100)
  const gatePct = Math.round(gate * 100)
  const belowBy = (gate - clampedConf).toFixed(2)

  return (
    <div
      data-testid="verdict-confidence-minibar"
      aria-label={`Confidence ${clampedConf.toFixed(2)} vs gate ${gate.toFixed(2)}`}
      style={{
        marginTop: 6,
        display: 'flex',
        flexDirection: 'column',
        gap: 3,
      }}
    >
      {/* Bar track */}
      <div
        style={{
          position: 'relative',
          height: 6,
          borderRadius: 3,
          background: 'var(--fw-bg-input)',
          border: '1px solid var(--fw-border)',
          overflow: 'visible',
        }}
      >
        {/* Confidence fill */}
        <div
          style={{
            position: 'absolute',
            left: 0,
            top: 0,
            height: '100%',
            width: `${confPct}%`,
            borderRadius: 3,
            background: 'var(--fw-orange)',
          }}
        />
        {/* Gate line */}
        <div
          data-testid="verdict-minibar-gate-line"
          style={{
            position: 'absolute',
            left: `${gatePct}%`,
            top: -3,
            bottom: -3,
            width: 2,
            background: 'var(--fw-t2)',
            borderRadius: 1,
          }}
        />
      </div>
      {/* Caption */}
      <span
        data-testid="verdict-minibar-caption"
        style={{
          fontSize: 'var(--fw-fs-2xs)',
          color: 'var(--fw-t3)',
          fontFamily: 'var(--fw-font-mono)',
        }}
      >
        {clampedConf.toFixed(2)} vs {gate.toFixed(2)} gate · below by {belowBy}
      </span>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

/**
 * One verdict card — the primary accountability artifact of the AI Engine page.
 *
 * Layout (top to bottom):
 *   Row 1: IP (ClickableIp) | AI ProvenanceChip | ConfidenceLabel | ScoreBadge (engine band)
 *   Row 2: model identity + authored-at age
 *   Row 3: AI verdict level (separate from engine score) | kind chip | ai_status
 *   Row 4: score-effect line (deterministic — did the AI move the score?)
 */
// ---------------------------------------------------------------------------
// MK-11: RerunControl — self-contained re-run block (zero forked ticker logic)
// ---------------------------------------------------------------------------

/**
 * RerunControl — "Re-run analysis" button + StageTicker for VerdictCard (MK-11).
 *
 * Mounts the SAME StageTicker / useStageTicker used by DeepAnalysisControl —
 * zero forked logic (ADR-0046 §7). On completion, calls onRerunComplete so
 * AIRoute can bump ledgerVersion → useVerdictLedger re-fetches the card list.
 *
 * This block is intentionally self-contained (its own state, clearly delimited)
 * so that concurrent VerdictCard edits from other branches rebase cleanly.
 *
 * SECURITY (ADR-0029 D3): ip is attacker-controlled — passed to useStageTicker
 * which URL-encodes it. Never rendered as HTML.
 * NO model-authored text renders from stage events (ADR-0046 D3).
 */
function RerunControl({
  ip,
  onRerunComplete,
}: {
  ip: string
  onRerunComplete?: () => void
}) {
  type RerunPhase = 'idle' | 'streaming' | 'done'
  const [phase, setPhase] = useState<RerunPhase>('idle')
  const [resultDispatched, setResultDispatched] = useState(false)

  // useStageTicker is called unconditionally (Rules of Hooks); enabled only
  // while streaming. When phase transitions to 'done', enabled flips to false —
  // the hook aborts the stream but retains 'stages' in its reducer state.
  // This means the completed stages are available in the 'done' phase without
  // any snapshot/copy, purely from the hook's persisted state.
  const { stages, generatingElapsedMs, result, streamError, streaming } = useStageTicker({
    ip,
    enabled: phase === 'streaming',
  })

  // When the terminal result arrives, notify parent and transition to done.
  if (result !== null && !resultDispatched) {
    Promise.resolve().then(() => {
      setResultDispatched(true)
      setPhase('done')
      onRerunComplete?.()
    })
  }

  // Stream error: still call onRerunComplete (the backend ran — just notify).
  if (streamError && phase === 'streaming' && !resultDispatched) {
    Promise.resolve().then(() => {
      setResultDispatched(true)
      setPhase('done')
      onRerunComplete?.()
    })
  }

  const hasFailed = stages.some((s) => s.stage === 'failed')
  const displayStages = stages.filter((s) => s.stage !== 'generating')

  if (phase === 'idle') {
    return (
      <div
        style={{ marginTop: 8, borderTop: '1px solid var(--fw-border)', paddingTop: 8 }}
        data-testid="verdict-card-rerun-section"
      >
        <button
          type="button"
          data-testid="verdict-card-rerun-btn"
          aria-label={`Re-run analysis for ${ip}`}
          onClick={() => {
            setPhase('streaming')
            setResultDispatched(false)
          }}
          style={{
            fontSize: 11,
            color: 'var(--fw-t3)',
            background: 'none',
            border: '1px solid var(--fw-border)',
            borderRadius: 4,
            padding: '3px 8px',
            cursor: 'pointer',
            fontFamily: 'var(--fw-font-mono)',
          }}
        >
          Re-run analysis
        </button>
      </div>
    )
  }

  if (phase === 'streaming') {
    return (
      <div
        style={{ marginTop: 8, borderTop: '1px solid var(--fw-border)', paddingTop: 8 }}
        data-testid="verdict-card-rerun-section"
      >
        <StageTicker
          stages={displayStages}
          generatingElapsedMs={generatingElapsedMs}
          streaming={streaming}
          hasFailed={hasFailed}
        />
      </div>
    )
  }

  // done: show the completed pipeline as a static summary + "refreshing" note.
  // 'displayStages' still holds the facts from the completed stream — useStageTicker
  // retains its state when enabled flips to false (no STREAM_STARTED reset).
  // done=true suppresses animation and the live generating counter.
  return (
    <div
      style={{ marginTop: 8, borderTop: '1px solid var(--fw-border)', paddingTop: 8 }}
      data-testid="verdict-card-rerun-section"
    >
      {displayStages.length > 0 && (
        <StageTicker
          stages={displayStages}
          generatingElapsedMs={null}
          streaming={false}
          hasFailed={hasFailed}
          done={true}
        />
      )}
      <span
        style={{ fontSize: 11, color: 'var(--fw-t3)', fontFamily: 'var(--fw-font-mono)' }}
        data-testid="verdict-card-rerun-done"
      >
        Analysis complete — ledger refreshing
      </span>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Main VerdictCard component
// ---------------------------------------------------------------------------

export function VerdictCard({ analysis, now, onFeedbackSubmitted, onRerunComplete }: VerdictCardProps) {
  const {
    id,
    ip,
    model,
    kind,
    ai_status,
    threat_level,
    confidence,
    score,
    score_derivation,
    created_at,
    feedback,
  } = analysis

  const age = formatAnalysisAge(created_at, now)
  // Chip reflects content authorship (AI-authored verdict), not score derivation.
  const chipDerivation = deriveCardChip(score_derivation)
  // Engine band is derived from the numeric score (ADR-0036 D1).
  // The AI's threat_level is a separate verdict artifact rendered below.
  const engineBand = scoreToSeverityBand(score)
  // Score-effect: plain-English causal line + optional mini-bar (MM #455).
  const scoreEffect = deriveScoreEffect(score_derivation, threat_level, confidence)

  return (
    <article
      data-testid="verdict-card"
      data-analysis-id={id}
      tabIndex={0}
      aria-label={`AI verdict for ${ip} — ${threat_level} threat, authored by ${model}`}
      /* #572: fw-verdict-card supplies :hover (border-color + background shift) —
         React inline style cannot target :hover pseudo-class. */
      className="fw-verdict-card"
      style={{
        background: 'var(--fw-bg-card)',
        border: '1px solid var(--fw-border)',
        borderRadius: 'var(--fw-r-card)',
        padding: '12px 16px',
        display: 'flex',
        flexDirection: 'column',
        gap: 8,
        fontFamily: 'var(--fw-font-ui)',
        outline: 'none',
        transition: 'border-color 0.15s, background 0.15s',
      }}
      // Keyboard focus glow (WCAG 2.4.7 focus visible)
      onFocus={(e) => {
        e.currentTarget.style.boxShadow = '0 0 0 2px var(--fw-accent)'
      }}
      onBlur={(e) => {
        e.currentTarget.style.boxShadow = 'none'
      }}
    >
      {/* Row 1: IP + provenance + confidence + score (engine band) */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          flexWrap: 'wrap',
        }}
      >
        {/* ADR-0029 D3: ip is attacker-controlled — ClickableIp renders as text node */}
        <ClickableIp value={String(ip)} aria-label={`Investigate ${ip}`} />

        {/*
         * ADR-0035 / ADR-0043: chip reflects content authorship (the verdict is AI-authored).
         * A VerdictCard is always an AI analysis — chip is 'ai' or 'ai+rule'.
         * It must NEVER show pure 'rule' even when score_derivation='rule'
         * (that means the score stayed rule-derived, but the prose/verdict is still AI).
         */}
        <ProvenanceChip
          derivation={chipDerivation}
          data-testid="verdict-provenance-chip"
        />

        {/* ADR-0036: word-banded confidence — never a raw percentage */}
        <ConfidenceLabel
          confidence={confidence}
          data-testid="verdict-confidence-label"
        />

        {/*
         * ADR-0036 D1: ScoreBadge shows the ENGINE score + its ENGINE band.
         * The band is derived from the numeric score via scoreToSeverityBand —
         * NOT from the AI's threat_level (which is a separate verdict artifact).
         * Example: score=0 → LOW band (engine), even if AI said MEDIUM.
         */}
        {/*
         * variant="default" renders "Risk N · BAND" with the band label visible —
         * compact would suppress the band text to just a chip, hiding the engine
         * band from sighted users (browser-verify: acceptance criterion requires
         * "0 · LOW" as visible text).
         */}
        <ScoreBadge
          score={score}
          threatLevel={engineBand}
          data-testid="verdict-score-badge"
        />
      </div>

      {/* Row 2: model identity + age */}
      <div
        style={{
          fontSize: 'var(--fw-fs-xs)',
          color: 'var(--fw-t3)',
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          flexWrap: 'wrap',
        }}
      >
        <span data-testid="verdict-model-identity">
          authored by{' '}
          {/* model is local model ID — render as text node (ADR-0029 D3) */}
          <span
            style={{
              fontFamily: 'var(--fw-font-mono)',
              color: 'var(--fw-t2)',
            }}
          >
            {String(model)}
          </span>
        </span>
        <span aria-hidden="true" style={{ opacity: 0.4 }}>·</span>
        <time
          dateTime={created_at}
          data-testid="verdict-age"
          title={created_at}
        >
          {age}
        </time>
      </div>

      {/* Row 3: AI verdict level (separate from engine score) | kind chip | ai_status */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          flexWrap: 'wrap',
        }}
      >
        {/*
         * AI verdict level — the model's assessment (separate from the engine score band).
         * ADR-0036 D1: two artifacts, two places. The ScoreBadge above shows the engine
         * band; this label shows what the AI said independently.
         */}
        <span
          data-testid="verdict-ai-level"
          style={{
            fontSize: 'var(--fw-fs-2xs)',
            fontWeight: 'var(--fw-fw-medium)',
            color: 'var(--fw-t2)',
          }}
        >
          {/* threat_level is model-validated — text node (ADR-0029 D3) */}
          AI verdict: {String(threat_level)}
        </span>

        <span
          data-testid="verdict-kind-chip"
          style={{
            fontSize: 'var(--fw-fs-2xs)',
            fontWeight: 'var(--fw-fw-medium)',
            padding: '1px 6px',
            borderRadius: 'var(--fw-r-xs)',
            background: 'var(--fw-bg-input)',
            border: '1px solid var(--fw-border)',
            color: 'var(--fw-t2)',
            textTransform: 'uppercase' as const,
            letterSpacing: 'var(--fw-ls-label)',
          }}
        >
          {/* kind is server-validated ('concise'|'detailed') — text node */}
          {String(kind)}
        </span>
        <span
          data-testid="verdict-ai-status"
          style={{
            fontSize: 'var(--fw-fs-2xs)',
            color: ai_status === 'ok' ? 'var(--fw-green)' : 'var(--fw-t3)',
          }}
        >
          {/* ai_status is server-validated — text node (ADR-0029 D3) */}
          {String(ai_status)}
        </span>
      </div>

      {/* Row 4: Score-effect line + optional confidence-vs-gate mini-bar (MM #455) */}
      <div
        data-testid="verdict-score-effect"
        style={{
          fontSize: 'var(--fw-fs-xs)',
          color: 'var(--fw-t3)',
          fontStyle: 'italic',
        }}
      >
        {/* Causal plain-English line — branch determined by verdict class (MM #455) */}
        {scoreEffect.text}
        {/*
         * Mini-bar: rendered ONLY when AI verdict was HIGH/CRITICAL but confidence
         * was below the gate. That is the sole case where confidence-vs-gate is
         * the actual reason the score didn't move — showing it elsewhere would mislead.
         * Gate value comes from CONFIDENCE_HIGH_THRESHOLD (never hard-coded here).
         */}
        {scoreEffect.showMiniBar && confidence != null && (
          <ConfidenceVsGateMiniBar confidence={confidence} />
        )}
      </div>

      {/*
       * Row 5: Agree / Disagree feedback controls (MK-6 / ADR-0045).
       * VerdictFeedback owns its own submit state via useFeedbackSubmit.
       * The list-row feedback field has a partial shape (no id/reason), so we
       * pass the verdict as initialVerdict rather than a full FeedbackRow — the
       * hook uses the POST response to populate the full stored row.
       * onSubmitted is forwarded from VerdictCardList → AIRoute (D2 reactivity).
       */}
      <VerdictFeedback
        analysisId={id}
        initialVerdict={feedback?.verdict ?? null}
        onSubmitted={onFeedbackSubmitted}
      />

      {/* --- MK-7: prompt-transparency drawer --- BEGIN ---
       * Localized block — keep this section self-contained so concurrent
       * VerdictCard edits (e.g. MK-11 re-run control) rebase cleanly.
       * PromptDrawer mounts its own fetch hook (useAnalysisDetail) and
       * disclosure (useDismissableDisclosure); no extra props required.
       * SECURITY: PromptDrawer renders prompt_text/response_text as text
       * nodes only — no dangerouslySetInnerHTML (ADR-0029 D3 / OWASP LLM05).
       */}
      <PromptDrawer analysisId={id} />
      {/* --- MK-7: prompt-transparency drawer --- END --- */}
      {/*
       * MK-11: Re-run analysis control — clearly-delimited block.
       * Uses the SAME StageTicker / useStageTicker as DeepAnalysisControl (zero forked logic).
       * On completion, calls onRerunComplete → AIRoute bumps ledgerVersion → ledger re-fetches.
       * ip is URL-encoded inside useStageTicker; never rendered as HTML (ADR-0029 D3).
       */}
      {/* BEGIN MK-11 re-run block */}
      <RerunControl ip={String(ip)} onRerunComplete={onRerunComplete} />
      {/* END MK-11 re-run block */}

      {/*
       * Issue #534 (ADR-0053 D1 / EARS-1): "Open case" affordance.
       * Creates a case file for this AI analysis and opens it in the slide-over.
       * Title is deterministic from the IP + analysis id (operator text, not attacker-
       * controlled — the value comes from our own ledger, not from the event payload).
       * No per-source code: CreateCaseButton is generic.
       */}
      <div
        style={{
          marginTop: 4,
          paddingTop: 8,
          borderTop: '1px solid var(--fw-border)',
        }}
        data-testid="verdict-card-case-section"
      >
        <CreateCaseButton
          title={`AI analysis #${id} — ${String(ip)}`}
          subject={String(ip)}
          label="Open case"
        />
      </div>
    </article>
  )
}
