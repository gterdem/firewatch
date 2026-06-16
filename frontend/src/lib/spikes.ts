/**
 * spikes.ts — deterministic spike detection over timeline bucket totals (issue #248).
 *
 * Algorithm: rolling median + k·MAD (Median Absolute Deviation).
 *
 * Rationale for median/MAD over mean/stddev:
 *   - MAD is breakdown-resistant: up to ~50% of values can be arbitrarily
 *     extreme without corrupting the estimate. Mean/stddev collapse under even
 *     one large outlier, which is exactly what we are trying to detect.
 *   - Result: on a flat or smoothly-ramping series no spike marker appears;
 *     on a series with a genuine step-change the flagged bucket stands out.
 *   - Fully deterministic: same series in, same marks out (no sampling, no RNG).
 *
 * References:
 *   - Leys et al. (2013) "Detecting outliers: Do not use standard deviation
 *     around the mean, use absolute deviation around the median." — Journal of
 *     Experimental Social Psychology.
 *   - Iglewicz & Hoaglin (1993) "How to Detect and Handle Outliers" — ASQC
 *     Quality Press. (k = 3.5 / 0.6745 in their z-score formulation;
 *     we expose k directly so callers can tune it.)
 *
 * Constants:
 *   DEFAULT_WINDOW  = 6   — look-back window size (number of preceding buckets)
 *   DEFAULT_K       = 3.5 — multiplier on MAD; buckets with
 *                           value > median + k·MAD are flagged.
 *                           3.5 is the Iglewicz-Hoaglin recommended threshold.
 *
 * Edge-case contracts (unit-tested):
 *   - series shorter than (window + 1) → no marks produced (safe: no crash).
 *   - flat series → no marks.
 *   - smooth ramp → no marks.
 *   - single genuine spike → exactly that bucket marked.
 *   - sparse/zero-heavy buckets → no false marks.
 *
 * LLM-reason seam (#213):
 *   SpikeMark.llmReason is defined in the type but is NEVER set by this module.
 *   When #213 lands, it may populate the field via a separate async call.
 *   Per ADR-0035: NOTHING in spikes.ts implies or asserts AI derivation.
 */

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/** One detected spike annotation. */
export interface SpikeMark {
  /** Index into the original series array. */
  bucketIndex: number
  /**
   * Ratio of the bucket's value to the window median.
   * e.g. 4.2 means "4.2x the median of its look-back window".
   */
  ratio: number
  /** Absolute count value of the flagged bucket. */
  value: number
  /** The window median used for this comparison. */
  windowMedian: number
  /**
   * Reserved seam for the LLM-generated one-line reason (#213, gated).
   * This module NEVER sets this field.  ADR-0035: no AI-attributed wording
   * until #213 wires in.
   */
  llmReason?: string
}

/** Options for detectSpikes. All fields are optional — defaults are recommended. */
export interface SpikeDetectionOptions {
  /**
   * Number of preceding buckets in the look-back window.
   * Minimum meaningful value is 3.  Default: 6.
   */
  window?: number
  /**
   * Spike threshold multiplier on MAD.
   * A bucket is flagged when: value > median(window) + k * MAD(window).
   * Default: 3.5 (Iglewicz-Hoaglin).
   */
  k?: number
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/** Sort-based median — works on a mutable copy. */
function median(values: number[]): number {
  if (values.length === 0) return 0
  const sorted = [...values].sort((a, b) => a - b)
  const mid = Math.floor(sorted.length / 2)
  return sorted.length % 2 === 0
    ? (sorted[mid - 1] + sorted[mid]) / 2
    : sorted[mid]
}

/** MAD = median(|xi - median(x)|). */
function mad(values: number[], med: number): number {
  const deviations = values.map((v) => Math.abs(v - med))
  return median(deviations)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export const DEFAULT_WINDOW = 6
export const DEFAULT_K = 3.5

/**
 * Detect spike buckets in a numeric time-series using rolling median + k·MAD.
 *
 * @param series   Array of non-negative integer counts (one per timeline bucket).
 * @param opts     Optional tuning parameters (window, k).
 * @returns        Array of SpikeMark — one per flagged bucket; empty when none detected.
 *
 * The function makes NO async calls, NO LLM calls, and produces NO side-effects.
 * It is safe to call on every render (pure).
 */
export function detectSpikes(
  series: number[],
  opts: SpikeDetectionOptions = {},
): SpikeMark[] {
  const windowSize = opts.window ?? DEFAULT_WINDOW
  const k = opts.k ?? DEFAULT_K

  // Contract: series shorter than window+1 → no marks, no crash.
  if (series.length <= windowSize) return []

  const marks: SpikeMark[] = []

  for (let i = windowSize; i < series.length; i++) {
    const window = series.slice(i - windowSize, i)
    const med = median(window)
    const madValue = mad(window, med)

    // Threshold: anything above median + k·MAD is a spike.
    //
    // MAD floor: when MAD = 0 (all-identical window) we apply a minimum noise
    // floor of 5% of the median (or 1.0 when median = 0) so that a genuine
    // spike after a perfectly flat baseline is still detected.
    //
    // Why not skip at MAD=0:
    //   A flat window followed by a value 20x the median is clearly a spike.
    //   Skipping would miss it; the floor gives a robust lower bound.
    //
    // Why not skip a flat candidate:
    //   The floor (0.05 * med ≈ 0.5 when med=10) makes threshold ≈ 10 + 3.5*0.5
    //   = 11.75.  A flat candidate of 10 does NOT exceed 11.75 — no false positive.
    //   A spike of 200 easily exceeds 11.75 — detected.
    const effectiveMad = madValue > 0 ? madValue : Math.max(med * 0.05, 1.0)
    const threshold = med + k * effectiveMad
    const value = series[i]

    if (value > threshold) {
      const ratio = med > 0 ? value / med : 0
      marks.push({
        bucketIndex: i,
        ratio,
        value,
        windowMedian: med,
      })
    }
  }

  return marks
}
