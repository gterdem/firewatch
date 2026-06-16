/**
 * DriftPanel — Model Trust panel for the AI Engine page (MK-9, issue #414).
 *
 * Surfaces the MI-9 `firewatch ai-baseline` verdict-drift CLI output in the UI.
 * Mounted as the last block in AIRoute.tsx (ADR-0043 D3 — page block 4).
 *
 * States (EARS criteria):
 *   1. Loading: spinner while both endpoints resolve.
 *   2. No baseline: honest empty state with CLI commands (no run button — CLI-triggered).
 *   3. Baseline exists, no comparison run: metadata + CLI instructions.
 *   4. Drift report available: headline + bounded diff list.
 *   5. Error (422 corrupt/oversized, network): honest error message.
 *
 * EARS:
 *   - WHEN drift report exists: headline (two models, run_at, changed/total,
 *     escalations/de-escalations) + bounded diff list; each diff expands to
 *     side-by-side baseline-vs-candidate, ConfidenceLabel, summary prose —
 *     both sides AI-chipped with their authoring model named (ADR-0035).
 *   - WHEN no baseline: honest empty state with CLI commands.
 *   - WHEN baseline only: metadata (model, saved_at, scenario_count) + CLI note.
 *   - Scenarios described as "synthetic baseline scenarios" (not production verdicts).
 *   - Pane bounded: top-N diffs + expand (no inner scrollbars, ADR-0043 D3).
 *   - WCAG: keyboard-navigable, role labels, focus-visible.
 *
 * MM #474 (value-first empty-state + "what is this panel" header):
 *   - A plain-language framing block renders in EVERY state (including no-baseline)
 *     before any instructions, so a new user understands the purpose before being asked
 *     to do anything (issue #474, P5 rec #1).
 *   - NoBaselineState leads with value framing, then shows the CLI path to enable.
 *   - Framing reinforces zero-egress (ADR-0022): "your model, on your box — nothing leaves".
 *   - Copy frames drift as operational integrity, not ML statistics.
 *
 * MM #475 (Model Consistency Score headline):
 *   - A single at-a-glance score renders as the TOP-LINE of DriftReportView:
 *     "N% consistent with baseline — M of P scenarios unchanged."
 *   - Score = (scenarios - changed) / scenarios, whole-number percent.
 *   - When changed===0: score reads 100% with a green reassurance badge.
 *   - "consistent" self-explains via a visible sub-caption and hover gloss.
 *
 * MM #476 (Model-swap banner):
 *   - WHEN the currently-configured model differs from the model recorded in the
 *     saved baseline, a proactive banner is shown above the state content:
 *     "Your model changed from `<old>` to `<new>` since your last baseline. Run a
 *     drift check to see what your new model judges differently."
 *   - Both model IDs are text nodes (ADR-0029 D3) — never interpolated as HTML.
 *   - Banner action points to CLI `--compare` (web-triggered compare not yet shipped;
 *     COMPARE_NOW_AVAILABLE capability flag gates the future "Compare now" button).
 *   - Compare-only: banner never offers to auto-save a new baseline (ADR-0051
 *     deliberate-act — the trust anchor must not be overwritten silently).
 *   - Banner is suppressed when: models match, baseline has no recorded model (old
 *     _meta-less file), or /health is unavailable (configuredModel null).
 *
 * ADR-0022: zero-egress — copy must not imply any cloud/remote step.
 * ADR-0029 D3: all model IDs, scenario names, prose rendered as text nodes only.
 * ADR-0035: AI chips on both sides of every diff; model name stated beside chip.
 * ADR-0043 D3: pane is bounded — overflow-y hidden; no inner scrollbar.
 *
 * Out of scope: UI-triggered baseline runs (CLI-triggered in MK — ADR-0043 Out-of-scope).
 */

import { Panel } from '../../ds'
import { DriftDiffRow } from './DriftDiffRow'
import { useBaselineDrift } from './useBaselineDrift'

/** Maximum diffs shown in the bounded list before "view all" (ADR-0043 D3). */
const TOP_N = 10

/**
 * Capability flag — set to true when the web-triggered compare job (issue #478 /
 * ADR-0051) is shipped. WHILE false, the banner action points to the CLI command.
 * WHEN true, replace the CLI note with a "Compare now" button that enqueues the job.
 *
 * ADR-0051 deliberate-act: the "Compare now" path (when enabled) MUST only trigger
 * a comparison, NEVER auto-save / overwrite the baseline.
 */
const COMPARE_NOW_AVAILABLE = false

/**
 * Model-swap detection banner (MM #476).
 *
 * Renders ONLY when a saved baseline has a recorded model AND the currently
 * configured engine model is different. Both model ID strings are text nodes
 * (ADR-0029 D3) — never interpolated as HTML.
 *
 * Props:
 *   baselineModel    — model string stored in the baseline _meta block.
 *   configuredModel  — model string from GET /health (ollama_model).
 *
 * Suppressed (returns null) when either value is null/empty or when they match.
 *
 * ADR-0022: copy must not imply any cloud/remote step.
 * ADR-0043 D3: bounded height, no inner scrollbar.
 * ADR-0051: compare-only — never offers to auto-save a new baseline.
 */
function ModelSwapBanner({
  baselineModel,
  configuredModel,
}: {
  baselineModel: string | null
  configuredModel: string | null
}) {
  // Suppress when either model is unknown or when they match.
  if (!baselineModel || !configuredModel || baselineModel === configuredModel) {
    return null
  }

  return (
    <div
      role="status"
      data-testid="model-swap-banner"
      style={{
        marginBottom: 16,
        padding: '10px 14px',
        background: 'color-mix(in srgb, var(--fw-accent) 10%, transparent)',
        border: '1px solid color-mix(in srgb, var(--fw-accent) 35%, transparent)',
        borderRadius: 'var(--fw-r-sm)',
        fontFamily: 'var(--fw-font-ui)',
      }}
    >
      <p
        data-testid="model-swap-banner-message"
        style={{
          margin: '0 0 6px',
          fontSize: 'var(--fw-fs-body)',
          fontWeight: 'var(--fw-fw-medium)',
          color: 'var(--fw-t1)',
          lineHeight: 1.5,
        }}
      >
        {/* Model IDs rendered as text nodes — ADR-0029 D3 */}
        {'Your model changed from '}
        <code
          data-testid="model-swap-banner-from"
          style={{
            fontFamily: 'var(--fw-font-mono)',
            background: 'var(--fw-bg-input)',
            padding: '1px 4px',
            borderRadius: 'var(--fw-r-xs)',
            fontSize: 'var(--fw-fs-xs)',
          }}
        >
          {String(baselineModel)}
        </code>
        {' to '}
        <code
          data-testid="model-swap-banner-to"
          style={{
            fontFamily: 'var(--fw-font-mono)',
            background: 'var(--fw-bg-input)',
            padding: '1px 4px',
            borderRadius: 'var(--fw-r-xs)',
            fontSize: 'var(--fw-fs-xs)',
          }}
        >
          {String(configuredModel)}
        </code>
        {' since your last baseline. Run a drift check to see what your new model judges differently.'}
      </p>
      {/*
       * Action — COMPARE_NOW_AVAILABLE gates a future one-click "Compare now" button.
       * WHILE false: show the CLI command (ADR-0051: compare-only, no auto-save).
       * WHEN true (issue #478 shipped): replace with a button that enqueues the job.
       */}
      {COMPARE_NOW_AVAILABLE ? null : (
        <p
          data-testid="model-swap-banner-action"
          style={{
            margin: 0,
            fontSize: 'var(--fw-fs-xs)',
            color: 'var(--fw-t2)',
          }}
        >
          {'Run: '}
          <code
            style={{
              fontFamily: 'var(--fw-font-mono)',
              background: 'var(--fw-bg-input)',
              padding: '1px 4px',
              borderRadius: 'var(--fw-r-xs)',
            }}
          >
            firewatch ai-baseline --compare
          </code>
          {' — this compares your models without overwriting your baseline.'}
        </p>
      )}
    </div>
  )
}

/**
 * "What is this panel" framing block — rendered in EVERY state before any instructions.
 *
 * MM #474: value-first pattern (P5 rec #1). A new user reads the purpose before being
 * asked to do anything. Copy is plain text (ADR-0029 D3); no model/scenario strings
 * are interpolated here (all static). Zero-egress reinforced (ADR-0022).
 */
function PanelExplainer() {
  return (
    <div data-testid="drift-panel-explainer" style={{ marginBottom: 16 }}>
      <p
        data-testid="drift-panel-tagline"
        style={{
          margin: '0 0 4px',
          fontSize: 'var(--fw-fs-body)',
          fontWeight: 'var(--fw-fw-medium)',
          color: 'var(--fw-t1)',
          fontFamily: 'var(--fw-font-ui)',
        }}
      >
        Model trust — does your AI still judge attacks the same way?
      </p>
      <p
        data-testid="drift-panel-subline"
        style={{
          margin: 0,
          fontSize: 'var(--fw-fs-xs)',
          color: 'var(--fw-t3)',
          lineHeight: 1.5,
          fontFamily: 'var(--fw-font-ui)',
        }}
      >
        When you upgrade or swap your local AI model, its verdicts can quietly change. This panel
        re-runs a fixed set of known attack scenarios through your model and tells you exactly what
        changed — so a model upgrade never silently weakens your detection. Your model, on your box
        — nothing leaves.
      </p>
    </div>
  )
}

/** Format an ISO-8601 timestamp to a locale-aware date-time string. */
function fmtTimestamp(iso: string): string {
  try {
    return new Date(iso).toLocaleString(undefined, {
      dateStyle: 'medium',
      timeStyle: 'short',
    })
  } catch {
    return iso
  }
}

/**
 * Honest empty state — displayed when no baseline has been saved.
 *
 * MM #474: value framing leads (the user understands WHY before being asked to act).
 * CLI commands are shown after the framing — no run button (CLI-triggered per ADR-0043).
 * Operational integrity framing: "did my model get worse at calling real attacks".
 * Zero-egress reinforced in PanelExplainer above (ADR-0022).
 */
function NoBaselineState() {
  return (
    <div data-testid="drift-no-baseline" style={{ padding: '4px 0' }}>
      <p
        data-testid="drift-no-baseline-prompt"
        style={{
          fontSize: 'var(--fw-fs-body)',
          color: 'var(--fw-t2)',
          margin: '0 0 12px',
          fontFamily: 'var(--fw-font-ui)',
          lineHeight: 1.5,
        }}
      >
        To start tracking, save a baseline with your current model — then compare after any
        upgrade to see whether your model got better or worse at calling real attacks.
      </p>
      <p
        style={{
          fontSize: 'var(--fw-fs-xs)',
          color: 'var(--fw-t3)',
          margin: '0 0 8px',
          fontFamily: 'var(--fw-font-ui)',
        }}
      >
        Run from the CLI:
      </p>
      <ol
        style={{
          margin: '0 0 0 20px',
          padding: 0,
          fontSize: 'var(--fw-fs-xs)',
          color: 'var(--fw-t3)',
          fontFamily: 'var(--fw-font-ui)',
          display: 'flex',
          flexDirection: 'column',
          gap: 4,
        }}
      >
        <li>
          Save a baseline with your current model:
          {' '}
          <code
            style={{
              fontFamily: 'var(--fw-font-mono)',
              background: 'var(--fw-bg-input)',
              padding: '1px 4px',
              borderRadius: 'var(--fw-r-xs)',
            }}
          >
            firewatch ai-baseline --save
          </code>
        </li>
        <li>
          After switching models, run a comparison:
          {' '}
          <code
            style={{
              fontFamily: 'var(--fw-font-mono)',
              background: 'var(--fw-bg-input)',
              padding: '1px 4px',
              borderRadius: 'var(--fw-r-xs)',
            }}
          >
            firewatch ai-baseline --compare
          </code>
        </li>
      </ol>
      <p
        style={{
          marginTop: 12,
          fontSize: 'var(--fw-fs-2xs)',
          color: 'var(--fw-t3)',
          fontStyle: 'italic',
          fontFamily: 'var(--fw-font-ui)',
        }}
      >
        Drift is computed against 25 synthetic baseline scenarios — it is not
        a re-judgment of production verdicts.
      </p>
    </div>
  )
}

/**
 * Baseline-only state — baseline saved but no comparison run yet.
 * Shows baseline metadata + instructions to run --compare.
 */
function BaselineOnlyState({
  scenarioCount,
  model,
  savedAt,
}: {
  scenarioCount: number
  model: string | null
  savedAt: string | null
}) {
  return (
    <div data-testid="drift-baseline-only" style={{ padding: '12px 0' }}>
      <p
        style={{
          fontSize: 'var(--fw-fs-body)',
          color: 'var(--fw-t2)',
          margin: '0 0 10px',
          fontFamily: 'var(--fw-font-ui)',
        }}
      >
        A baseline has been saved ({scenarioCount} synthetic scenarios
        {model ? (
          <>
            {', model '}
            <span style={{ fontFamily: 'var(--fw-font-mono)' }}>{String(model)}</span>
          </>
        ) : null}
        {savedAt ? `, saved ${fmtTimestamp(savedAt)}` : null}
        {')'}. No comparison has been run yet.
      </p>
      <p
        style={{
          fontSize: 'var(--fw-fs-xs)',
          color: 'var(--fw-t3)',
          margin: '0 0 4px',
          fontFamily: 'var(--fw-font-ui)',
        }}
      >
        After switching models, run:
        {' '}
        <code
          style={{
            fontFamily: 'var(--fw-font-mono)',
            background: 'var(--fw-bg-input)',
            padding: '1px 4px',
            borderRadius: 'var(--fw-r-xs)',
          }}
        >
          firewatch ai-baseline --compare
        </code>
      </p>
      <p
        style={{
          marginTop: 12,
          fontSize: 'var(--fw-fs-2xs)',
          color: 'var(--fw-t3)',
          fontStyle: 'italic',
          fontFamily: 'var(--fw-font-ui)',
        }}
      >
        Drift is computed against synthetic scenarios — it is not a
        re-judgment of production verdicts.
      </p>
    </div>
  )
}

/**
 * Model Consistency Score headline — the single at-a-glance number (issue #475).
 *
 * Score = (scenarios - changed) / scenarios, rendered as whole-number percent.
 * When changed === 0 the score reads 100% with a green reassurance badge.
 *
 * If scenarios is zero, flags unavailable rather than inventing a value (EARS-475-8).
 *
 * ADR-0029 D3: all numbers/strings are text nodes (no child elements on the score span).
 * ADR-0043 D3: bounded-height pane, no inner scrollbar.
 */
function ConsistencyScoreHeadline({
  scenarios,
  changed,
}: {
  scenarios: number
  changed: number
}) {
  // Guard: if scenarios is zero we cannot derive a meaningful score — flag, never invent.
  if (scenarios <= 0) {
    return (
      <p
        data-testid="drift-consistency-unavailable"
        style={{
          fontSize: 'var(--fw-fs-xs)',
          color: 'var(--fw-t3)',
          fontStyle: 'italic',
          fontFamily: 'var(--fw-font-ui)',
          marginBottom: 12,
        }}
      >
        Consistency score unavailable (no scenarios recorded).
      </p>
    )
  }

  const unchanged = scenarios - changed
  const scorePercent = Math.round((unchanged / scenarios) * 100)
  const isPerfect = changed === 0

  return (
    <div
      data-testid="drift-consistency-score"
      style={{
        marginBottom: 16,
        fontFamily: 'var(--fw-font-ui)',
      }}
    >
      {/* Top-line score row */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          flexWrap: 'wrap',
        }}
      >
        <span
          data-testid="drift-score-percent"
          style={{
            fontSize: 'var(--fw-fs-xl, 1.5rem)',
            fontWeight: 'var(--fw-fw-semibold, 600)',
            color: isPerfect ? 'var(--fw-green)' : 'var(--fw-t1)',
            fontVariantNumeric: 'tabular-nums',
          }}
        >
          {String(scorePercent)}%
        </span>
        <span
          data-testid="drift-score-label"
          style={{
            fontSize: 'var(--fw-fs-body)',
            color: 'var(--fw-t1)',
            fontWeight: 'var(--fw-fw-medium)',
          }}
        >
          consistent with baseline
        </span>
        {/* Green reassurance badge — only for the perfect (resting) state */}
        {isPerfect && (
          <span
            data-testid="drift-score-perfect-badge"
            role="status"
            style={{
              display: 'inline-block',
              fontSize: 'var(--fw-fs-2xs)',
              fontWeight: 'var(--fw-fw-medium)',
              color: 'var(--fw-green)',
              background: 'color-mix(in srgb, var(--fw-green) 12%, transparent)',
              border: '1px solid color-mix(in srgb, var(--fw-green) 30%, transparent)',
              borderRadius: 'var(--fw-r-sm)',
              padding: '1px 8px',
            }}
          >
            No drift detected
          </span>
        )}
      </div>

      {/* Supporting detail — unchanged / total (text node, ADR-0029 D3) */}
      <p
        data-testid="drift-score-detail"
        style={{
          margin: '4px 0 0',
          fontSize: 'var(--fw-fs-xs)',
          color: 'var(--fw-t2)',
          fontFamily: 'var(--fw-font-ui)',
        }}
      >
        {String(unchanged)} of {String(scenarios)} scenarios unchanged.
      </p>

      {/*
       * Self-explaining gloss (EARS-475-4: "consistent" self-explains at point-of-use).
       * Visible sub-caption; title attribute provides hover tooltip.
       * ADR-0029 D3: static text node — no dynamic model/scenario interpolation here.
       */}
      <p
        data-testid="drift-score-gloss"
        title="How often your current model gives the same verdict as the saved baseline"
        style={{
          margin: '2px 0 0',
          fontSize: 'var(--fw-fs-2xs)',
          color: 'var(--fw-t3)',
          fontStyle: 'italic',
          fontFamily: 'var(--fw-font-ui)',
        }}
      >
        How often your current model gives the same verdict as the saved baseline.
      </p>
    </div>
  )
}

/**
 * Full drift report state — consistency score headline + detail + bounded diff list.
 *
 * MM #475: ConsistencyScoreHeadline is the TOP-LINE element (rendered first in the view).
 * The existing model names, changed/total, escalations/de-escalations and diff list follow
 * as drill-down detail (ADR-0043 D3 — top-line number → detail, no scrolling).
 *
 * ADR-0029 D3: baseline_model, candidate_model are server-validated text nodes.
 * ADR-0043 D3: bounded top-N; no inner scrollbars.
 */
function DriftReportView({
  baselineModel,
  candidateModel,
  runAt,
  scenarios,
  changed,
  escalations,
  deescalations,
  diffs,
}: {
  baselineModel: string
  candidateModel: string
  runAt: string
  scenarios: number
  changed: number
  escalations: number
  deescalations: number
  diffs: import('../../../api/types').DriftDiff[]
}) {
  const visibleDiffs = diffs.slice(0, TOP_N)
  const hiddenCount = diffs.length - visibleDiffs.length

  return (
    <div data-testid="drift-report-view" style={{ padding: '4px 0' }}>
      {/* TOP-LINE: Model Consistency Score (MM #475) */}
      <ConsistencyScoreHeadline scenarios={scenarios} changed={changed} />

      {/* Detail: models, run_at, changed/total, escalations/de-escalations */}
      <div
        data-testid="drift-headline"
        style={{
          marginBottom: 12,
          fontFamily: 'var(--fw-font-ui)',
        }}
      >
        <div
          style={{
            fontSize: 'var(--fw-fs-body)',
            color: 'var(--fw-t1)',
            fontWeight: 'var(--fw-fw-medium)',
            marginBottom: 4,
          }}
        >
          {/* Model names — server-validated text nodes (ADR-0029 D3) */}
          <span style={{ fontFamily: 'var(--fw-font-mono)' }}>{String(baselineModel)}</span>
          {' → '}
          <span style={{ fontFamily: 'var(--fw-font-mono)' }}>{String(candidateModel)}</span>
        </div>
        <div
          style={{
            fontSize: 'var(--fw-fs-xs)',
            color: 'var(--fw-t2)',
            display: 'flex',
            gap: 12,
            flexWrap: 'wrap',
          }}
        >
          <span data-testid="drift-changed-count">
            {changed} of {scenarios} synthetic baseline scenarios changed
          </span>
          {escalations > 0 && (
            <span style={{ color: 'var(--fw-red)' }} data-testid="drift-escalations">
              {escalations} escalation{escalations !== 1 ? 's' : ''}
            </span>
          )}
          {deescalations > 0 && (
            <span style={{ color: 'var(--fw-green)' }} data-testid="drift-deescalations">
              {deescalations} de-escalation{deescalations !== 1 ? 's' : ''}
            </span>
          )}
          <span style={{ color: 'var(--fw-t3)' }} data-testid="drift-run-at">
            Run {fmtTimestamp(runAt)}
          </span>
        </div>
        <p
          style={{
            marginTop: 6,
            fontSize: 'var(--fw-fs-2xs)',
            color: 'var(--fw-t3)',
            fontStyle: 'italic',
            margin: '6px 0 0',
          }}
        >
          Drift is computed against synthetic scenarios — it is not a
          re-judgment of production verdicts.
        </p>
      </div>

      {/* Diff list — bounded; no changed scenarios = honest "no drift" */}
      {changed === 0 ? (
        <p
          data-testid="drift-no-changes"
          style={{
            fontSize: 'var(--fw-fs-xs)',
            color: 'var(--fw-t3)',
            fontStyle: 'italic',
            fontFamily: 'var(--fw-font-ui)',
          }}
        >
          No verdict changes detected — both models produced the same verdicts
          on all {scenarios} scenarios.
        </p>
      ) : (
        <div data-testid="drift-diff-list">
          {visibleDiffs.map((diff, i) => (
            <DriftDiffRow
              key={diff.scenario}
              diff={diff}
              baselineModel={baselineModel}
              candidateModel={candidateModel}
              index={i}
            />
          ))}
          {hiddenCount > 0 && (
            <p
              data-testid="drift-truncated-notice"
              style={{
                marginTop: 8,
                fontSize: 'var(--fw-fs-xs)',
                color: 'var(--fw-t3)',
                fontStyle: 'italic',
                fontFamily: 'var(--fw-font-ui)',
              }}
            >
              Showing {TOP_N} of {diffs.length} changed scenarios. Re-run{' '}
              <code
                style={{
                  fontFamily: 'var(--fw-font-mono)',
                  background: 'var(--fw-bg-input)',
                  padding: '1px 4px',
                  borderRadius: 'var(--fw-r-xs)',
                }}
              >
                firewatch ai-baseline --compare
              </code>{' '}
              to generate a fresh report with all diffs.
            </p>
          )}
        </div>
      )}
    </div>
  )
}

/**
 * Model Trust panel — top-level component for the AI Engine page (MK-9).
 * Mounted as the last block in AIRoute.tsx (ADR-0043 D3, page block 4).
 *
 * MM #474: PanelExplainer renders in EVERY state — the user always sees the
 * "what is this panel" framing before any instructions or data.
 */
export function DriftPanel() {
  const state = useBaselineDrift()

  return (
    <Panel
      title="Model trust"
      data-testid="drift-panel"
    >
      {/* MM #474: value-first framing — always visible regardless of state. */}
      <PanelExplainer />

      {state.status === 'loading' && (
        <p
          role="status"
          aria-live="polite"
          data-testid="drift-loading"
          style={{
            fontSize: 'var(--fw-fs-xs)',
            color: 'var(--fw-t3)',
            fontFamily: 'var(--fw-font-ui)',
            padding: '4px 0',
          }}
        >
          Loading model trust data…
        </p>
      )}

      {state.status === 'no-baseline' && <NoBaselineState />}

      {state.status === 'baseline-only' && (
        <>
          {/* MM #476: model-swap banner — shown when configured model ≠ baseline model. */}
          <ModelSwapBanner
            baselineModel={state.baseline.model}
            configuredModel={state.configuredModel}
          />
          <BaselineOnlyState
            scenarioCount={state.baseline.scenario_count}
            model={state.baseline.model}
            savedAt={state.baseline.saved_at}
          />
        </>
      )}

      {state.status === 'drift-report' && (
        <>
          {/* MM #476: model-swap banner — shown when configured model ≠ baseline model. */}
          <ModelSwapBanner
            baselineModel={state.baseline.model}
            configuredModel={state.configuredModel}
          />
          <DriftReportView
            baselineModel={state.drift.baseline_model}
            candidateModel={state.drift.candidate_model}
            runAt={state.drift.run_at}
            scenarios={state.drift.scenarios}
            changed={state.drift.changed}
            escalations={state.drift.escalations}
            deescalations={state.drift.deescalations}
            diffs={state.drift.diffs}
          />
        </>
      )}

      {state.status === 'error' && (
        <p
          role="alert"
          data-testid="drift-error"
          style={{
            fontSize: 'var(--fw-fs-xs)',
            color: 'var(--fw-red)',
            fontFamily: 'var(--fw-font-ui)',
            padding: '4px 0',
          }}
        >
          {/* error message is client-composed — text node (never attacker-controlled) */}
          {state.message}
        </p>
      )}
    </Panel>
  )
}
