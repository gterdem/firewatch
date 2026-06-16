/**
 * NlQueryInput — "Ask the network" natural-language query bar (ML-6 / ADR-0049 / issue #434).
 *
 * Lets the analyst type a plain-English query (e.g. "show blocked TCP traffic
 * from high severity sources") and converts it into an editable FilterSpec via
 * the local LLM (zero-egress, EARS-5).
 *
 * Behaviour
 * ---------
 * 1. Analyst types a query and submits (Enter or button).
 * 2. Component calls POST /logs/nl-query with the query text.
 * 3. On success:
 *    a. ``degraded=false`` → the returned filter_spec fields are applied as
 *       editable filter chips (EARS-1, EARS-3).  An AI provenance chip is shown.
 *    b. ``degraded=true``  → the parse could not be resolved into a FilterSpec.
 *       The component shows a clearly-labelled "Unparsed input" notice (EARS-3)
 *       and does NOT propagate the raw query text into the filter state or URL
 *       (issue #568 — prompt-injection hardening).
 * 4. On any fetch error the component shows a brief inline error and takes no
 *    action on the filter state — fail-safe (EARS-2).
 *
 * SECURITY (ADR-0049 / OWASP LLM01 / issue #568)
 * -------------------------------------------------
 * The filter values received from the server have already been validated against
 * the strict allowlist (server-side, via the validator module).  The component
 * applies them as regular filter chips — the same path as manual chip selection.
 * The NL query string is submitted as a JSON body field (POST), not embedded in
 * the URL or interpolated into any template.
 *
 * On the degraded path, the raw user query text is intentionally NOT forwarded
 * to onFilterApply and NOT placed into ?q=.  Unvetted NL input (which may contain
 * prompt-injection or adversarial content) is only displayed as an escaped React
 * text node inside a clearly-labeled "Unparsed input" notice — never as an
 * applied filter chip or URL parameter.  React's JSX rendering (text nodes, not
 * dangerouslySetInnerHTML) prevents XSS; the filter-chip framing concern is
 * resolved by not calling onFilterApply at all on the degraded path.
 *
 * EARS-3 (AI provenance chip)
 * ----------------------------
 * When the parse succeeds, a small badge labelled "AI" is shown next to the
 * result chips.  When degraded, the badge shows "AI: degraded" and a secondary
 * inline notice names the unparsed input so the analyst can rephrase.  The badge
 * uses DS-safe inline styles (no external libraries) consistent with the rest of
 * the logs page.
 */

import { useState, useCallback } from 'react'
import { fetchNlQuery } from '../../api/logs'
import type { LogsFilter } from '../../api/types'
import { Button, Spinner } from '../ds'

export interface NlQueryInputProps {
  /**
   * Called ONLY when a validated FilterSpec is produced (EARS-1, degraded=false).
   * On the degraded path onFilterApply is deliberately NOT called — raw NL input
   * must not propagate into the filter state or ?q= URL param (issue #568).
   * The provenance chip ("AI" / "AI: degraded") is rendered by NlQueryInput
   * itself (EARS-3); the caller receives only the filter to apply.
   */
  onFilterApply: (filter: Partial<LogsFilter>) => void
}

/** Visual badge for AI provenance — rendered next to the query bar after a parse. */
function AiProvenanceChip({ provenance }: { provenance: string | null }) {
  if (!provenance) return null

  const isDegraded = provenance === 'ai_degraded'

  return (
    <span
      data-testid="nl-provenance-chip"
      aria-label={isDegraded ? 'AI: parse degraded — query not applied' : 'AI: filter generated'}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 4,
        padding: '2px 8px',
        borderRadius: 12,
        fontSize: 'var(--fw-fs-2xs)',
        fontFamily: 'var(--fw-font-ui)',
        fontWeight: 'var(--fw-fw-medium)',
        background: isDegraded ? 'var(--fw-bg-card)' : 'color-mix(in srgb, var(--fw-blue) 15%, transparent)',
        border: `1px solid ${isDegraded ? 'var(--fw-border)' : 'var(--fw-blue)'}`,
        color: isDegraded ? 'var(--fw-t3)' : 'var(--fw-blue)',
        whiteSpace: 'nowrap',
      }}
    >
      {isDegraded ? 'AI: degraded' : 'AI'}
    </span>
  )
}

/**
 * "Unparsed input" notice — shown on the degraded path (issue #568).
 *
 * Renders the original query text as a plain React text node (no
 * dangerouslySetInnerHTML, no filter propagation) so the analyst can see
 * what was submitted and rephrase it.  The surrounding label makes the
 * "not-an-applied-filter" framing explicit for both the operator and the
 * security reviewer.
 *
 * SECURITY: `inputText` is rendered as a JSX text node only.  React escapes
 * all HTML entities by default, so no XSS is possible even for adversarial
 * content such as ``<script>`` or injection payloads.
 */
function UnparsedInputNotice({ inputText }: { inputText: string | null }) {
  if (!inputText) return null

  return (
    <span
      data-testid="nl-unparsed-notice"
      role="status"
      aria-label="NL query could not be parsed — no filter applied"
      style={{
        fontSize: 'var(--fw-fs-xs)',
        color: 'var(--fw-t3)',
        fontFamily: 'var(--fw-font-ui)',
        paddingLeft: 2,
      }}
    >
      {'Unparsed input (no filter applied): '}
      <span
        data-testid="nl-unparsed-text"
        style={{ fontStyle: 'italic' }}
      >
        {inputText}
      </span>
      {' — try rephrasing the query.'}
    </span>
  )
}

export default function NlQueryInput({ onFilterApply }: NlQueryInputProps) {
  const [query, setQuery] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [provenance, setProvenance] = useState<string | null>(null)
  /**
   * Tracks the query text that produced a degraded parse so the "Unparsed
   * input" notice can display it.  Set only on the degraded path; cleared
   * when the user modifies the query.  The value is shown as a plain text
   * node — never applied to the filter state (issue #568).
   */
  const [unparsedInput, setUnparsedInput] = useState<string | null>(null)

  const handleSubmit = useCallback(async () => {
    const trimmed = query.trim()
    if (!trimmed) return

    setLoading(true)
    setError(null)
    setProvenance(null)
    setUnparsedInput(null)

    try {
      const result = await fetchNlQuery(trimmed)
      setProvenance(result.provenance)

      if (result.degraded) {
        // SECURITY (issue #568): do NOT propagate raw NL text into the filter
        // state.  The query text may contain prompt-injection or adversarial
        // content.  Instead, surface it as a clearly-labeled "Unparsed input"
        // notice (escaped React text node) so the analyst can rephrase.
        // onFilterApply is deliberately NOT called on the degraded path.
        setUnparsedInput(trimmed)
      } else {
        // Validated filter_spec from the strict server-side allowlist —
        // safe to apply as filter chips (equivalent to manual chip selection).
        onFilterApply(result.filter_spec)
      }
    } catch (err: unknown) {
      // Fetch errors (503, network failure) — show inline message, do not modify filter.
      const message =
        err instanceof Error ? err.message : 'NL query failed — try a manual filter'
      setError(message)
    } finally {
      setLoading(false)
    }
  }, [query, onFilterApply])

  function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Enter' && !loading) {
      void handleSubmit()
    }
  }

  return (
    <div
      data-testid="nl-query-input"
      aria-label="Ask the network (natural-language query)"
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: 4,
        marginBottom: 8,
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
        {/* Label */}
        <span
          style={{
            fontSize: 'var(--fw-fs-2xs)',
            color: 'var(--fw-t3)',
            textTransform: 'uppercase',
            letterSpacing: 'var(--fw-ls-table)',
            whiteSpace: 'nowrap',
          }}
        >
          Ask the network
        </span>

        {/* Query input */}
        <input
          type="text"
          value={query}
          placeholder='e.g. "show blocked high severity TCP traffic"'
          aria-label="Natural-language log query"
          data-testid="nl-query-text"
          disabled={loading}
          style={{
            flex: 1,
            background: 'var(--fw-bg-input)',
            color: 'var(--fw-t1)',
            border: '1px solid var(--fw-border)',
            borderRadius: 'var(--fw-r-xs)',
            padding: '6px 10px',
            fontSize: 'var(--fw-fs-sm)',
            fontFamily: 'var(--fw-font-ui)',
            outline: 'none',
            minWidth: 260,
            opacity: loading ? 0.7 : 1,
          }}
          onChange={(e) => {
            setQuery(e.target.value)
            // Clear provenance / error / unparsed notice when the user modifies the query
            if (provenance) setProvenance(null)
            if (error) setError(null)
            if (unparsedInput) setUnparsedInput(null)
          }}
          onKeyDown={handleKeyDown}
        />

        {/* Submit button */}
        <Button
          variant="secondary"
          size="sm"
          data-testid="nl-query-submit"
          aria-label="Apply natural-language query as filter"
          disabled={loading || !query.trim()}
          onClick={() => void handleSubmit()}
        >
          {loading ? (
            <Spinner label="" style={{ width: 14, height: 14 }} />
          ) : (
            'Ask'
          )}
        </Button>

        {/* Provenance chip — shown after a parse attempt (EARS-3).
            On the degraded path this shows "AI: degraded" — not "AI: plain search" —
            to make it unambiguous that the query was NOT accepted as a filter. */}
        <AiProvenanceChip provenance={provenance} />
      </div>

      {/* Unparsed input notice — degraded path only (issue #568).
          Shows the query text as a plain escaped text node with a clear label.
          NOT a filter chip; NOT applied to the filter state; NOT placed in ?q=. */}
      <UnparsedInputNotice inputText={unparsedInput} />

      {/* Inline error — shown when fetch/parse fails completely (never on degradation) */}
      {error !== null && (
        <span
          data-testid="nl-query-error"
          role="alert"
          style={{
            fontSize: 'var(--fw-fs-xs)',
            color: 'var(--fw-red)',
            fontFamily: 'var(--fw-font-ui)',
            paddingLeft: 2,
          }}
        >
          {error}
        </span>
      )}
    </div>
  )
}
