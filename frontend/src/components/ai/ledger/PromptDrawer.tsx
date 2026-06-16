/**
 * PromptDrawer — "What the model saw" disclosure inside a VerdictCard.
 *
 * MK-7 (issue #412) / ADR-0044 / ADR-0029 D3.
 *
 * Renders the full analysis detail fetched from GET /ai/analyses/{id}:
 *   - Prompt text (split into instructions / samples / schema sections)
 *   - Raw response text from the model
 *   - Validated JSON fields the product consumed
 *   - Model identity, latency, token stats
 *   - Truncation notices (64 KiB limit)
 *
 * SECURITY (ADR-0029 D3 / OWASP LLM05):
 *   prompt_text and response_text are the most attacker-controlled strings in
 *   the product. This component renders them as TEXT NODES ONLY:
 *   - No dangerouslySetInnerHTML anywhere in this subtree (zero exceptions).
 *   - No markdown rendering, no HTML interpretation, no ANSI processing.
 *   - All text content uses React's default text-node rendering (the DOM
 *     textContent path, not innerHTML).
 *   Hostile strings like <img src=x onerror=alert(1)>, [x](javascript:...),
 *   and ANSI escapes are rendered as inert literal characters.
 *
 * Accessibility (WCAG):
 *   - Reuses useDismissableDisclosure: Esc closes, outside-click closes,
 *     focus returns to trigger on close (WCAG 1.4.13 / WCAG 2.4.7).
 *   - The "What the model saw" control is a <button> with aria-expanded.
 *   - The drawer region has role="region" with an accessible name.
 *
 * Bounded height + section expand:
 *   - The drawer does NOT use an inner scrollbar per spec.
 *   - Long text sections collapse to 10 lines; a "Show full …" toggle
 *     expands each section individually.
 */

import { useState } from 'react'
import { useDismissableDisclosure } from '../../ds'
import { useAnalysisDetail } from './useAnalysisDetail'
import { splitPromptSections } from './promptSections'

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Lines shown before "Show full …" expand (per section). */
const COLLAPSED_LINE_COUNT = 10

/** Text shown when a text field was truncated at persistence. */
const TRUNCATED_NOTICE = 'truncated at 64 KiB'

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

interface CollapsibleTextProps {
  /** Accessible label for the section (e.g. "Instructions"). */
  label: string
  /** The raw text content — rendered as a text node only (ADR-0029 D3). */
  text: string
  /** When true, show a truncation notice below the text. */
  truncated?: boolean
  /** data-testid forwarded to the pre element. */
  testId?: string
}

/**
 * One collapsible text section with an expand toggle.
 *
 * SECURITY: text is rendered inside a <pre> element as a text node (React's
 * default). There is NO dangerouslySetInnerHTML in this component or its
 * children. Hostile HTML/markdown/ANSI in `text` renders as literal characters.
 */
function CollapsibleText({ label, text, truncated, testId }: CollapsibleTextProps) {
  const lines = text.split('\n')
  const needsCollapse = lines.length > COLLAPSED_LINE_COUNT
  const [expanded, setExpanded] = useState(false)

  const visibleText =
    needsCollapse && !expanded
      ? lines.slice(0, COLLAPSED_LINE_COUNT).join('\n')
      : text

  return (
    <div
      style={{
        marginBottom: 12,
        borderRadius: 'var(--fw-r-xs)',
        border: '1px solid var(--fw-border)',
        overflow: 'hidden',
      }}
    >
      {/* Section label */}
      <div
        style={{
          padding: '4px 10px',
          background: 'var(--fw-bg-input)',
          fontSize: 'var(--fw-fs-2xs)',
          fontWeight: 'var(--fw-fw-medium)',
          color: 'var(--fw-t3)',
          letterSpacing: 'var(--fw-ls-label)',
          textTransform: 'uppercase',
          borderBottom: '1px solid var(--fw-border)',
        }}
      >
        {/* label is a static string — safe as text node */}
        {label}
      </div>

      {/*
       * SECURITY (ADR-0029 D3 / OWASP LLM05):
       * The <pre> element renders `visibleText` as a React child — this is
       * a TEXT NODE, NOT innerHTML. React sets textContent, not innerHTML.
       * Hostile HTML/JS/ANSI in the text is inert.
       * DO NOT add dangerouslySetInnerHTML here.
       */}
      <pre
        data-testid={testId}
        style={{
          margin: 0,
          padding: '8px 10px',
          fontSize: 'var(--fw-fs-xs)',
          fontFamily: 'var(--fw-font-mono)',
          color: 'var(--fw-t2)',
          whiteSpace: 'pre-wrap',
          wordBreak: 'break-word',
          background: 'transparent',
          // overflowX:'hidden' prevents the nested-scrollbar UX issue (#575).
          // Long lines wrap via whiteSpace:'pre-wrap' + wordBreak:'break-word'
          // above, so a horizontal scroll region is never needed.
          overflowX: 'hidden',
        }}
      >
        {/* visibleText is a React text node — never HTML (ADR-0029 D3). */}
        {visibleText}
        {needsCollapse && !expanded && (
          <span style={{ color: 'var(--fw-t3)' }}>{'\n…'}</span>
        )}
      </pre>

      {/* Expand / collapse toggle */}
      {needsCollapse && (
        <div style={{ padding: '4px 10px', borderTop: '1px solid var(--fw-border)' }}>
          <button
            type="button"
            onClick={() => setExpanded((v) => !v)}
            style={{
              background: 'none',
              border: 'none',
              padding: 0,
              cursor: 'pointer',
              fontSize: 'var(--fw-fs-xs)',
              color: 'var(--fw-accent)',
              fontFamily: 'var(--fw-font-ui)',
            }}
          >
            {expanded ? 'Show less' : `Show full ${label.toLowerCase()} (${lines.length} lines)`}
          </button>
        </div>
      )}

      {/* Truncation notice */}
      {truncated && (
        <div
          data-testid={testId ? `${testId}-truncated` : undefined}
          style={{
            padding: '4px 10px',
            fontSize: 'var(--fw-fs-2xs)',
            color: 'var(--fw-orange)',
            borderTop: '1px solid var(--fw-border)',
            fontStyle: 'italic',
          }}
        >
          {/* TRUNCATED_NOTICE is a static string constant — safe as text node */}
          {TRUNCATED_NOTICE}
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Stats row
// ---------------------------------------------------------------------------

interface StatPillProps {
  label: string
  value: string | number
  testId?: string
}

function StatPill({ label, value, testId }: StatPillProps) {
  return (
    <span
      data-testid={testId}
      style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: 4,
        padding: '2px 8px',
        borderRadius: 'var(--fw-r-xs)',
        background: 'var(--fw-bg-input)',
        border: '1px solid var(--fw-border)',
        fontSize: 'var(--fw-fs-xs)',
        color: 'var(--fw-t2)',
        fontFamily: 'var(--fw-font-mono)',
      }}
    >
      <span
        style={{
          color: 'var(--fw-t3)',
          fontSize: 'var(--fw-fs-2xs)',
          fontFamily: 'var(--fw-font-ui)',
          textTransform: 'uppercase',
          letterSpacing: 'var(--fw-ls-label)',
          fontWeight: 'var(--fw-fw-medium)',
        }}
      >
        {/* label is a static string — safe */}
        {label}
      </span>
      {/* value is rendered as a text node — no HTML interpretation */}
      {String(value)}
    </span>
  )
}

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

export interface PromptDrawerProps {
  /** The analysis id — used to fetch and cache GET /ai/analyses/{id}. */
  analysisId: number
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

/**
 * PromptDrawer — the "What the model saw" disclosure.
 *
 * Mounts as a narrow trigger button; expands inline (not a modal/portal) when
 * clicked. Fetches on expand (lazy). Sections collapse individually for long texts.
 *
 * SECURITY: NO dangerouslySetInnerHTML anywhere in this subtree.
 * All attacker-influenced strings (prompt_text, response_text, validated_json
 * field values) are rendered as React text nodes.
 */
export function PromptDrawer({ analysisId }: PromptDrawerProps) {
  const { open, triggerRef, contentRef, triggerProps, contentProps, close } =
    useDismissableDisclosure()

  const { status, detail, error, fetch: triggerFetch } = useAnalysisDetail(analysisId)

  // Fetch on open (lazy — only when expanded for the first time).
  const handleTriggerClick = (e: React.MouseEvent) => {
    triggerProps.onClick(e)
    if (!open) {
      // Trigger fetch when opening (idempotent — hook guards duplicate fetches).
      triggerFetch()
    }
  }

  // ---------------------------------------------------------------------------
  // Render
  // ---------------------------------------------------------------------------

  return (
    <div
      // MK-7 localized block — clearly delimited so concurrent VerdictCard edits
      // (e.g. MK-11 re-run control) can be rebased cleanly around this block.
      data-mk7-prompt-drawer
      style={{ marginTop: 8 }}
    >
      {/* "What the model saw" trigger button */}
      <button
        ref={triggerRef as React.RefObject<HTMLButtonElement>}
        type="button"
        data-testid="prompt-drawer-trigger"
        aria-expanded={open}
        aria-controls={`prompt-drawer-content-${analysisId}`}
        {...triggerProps}
        onClick={handleTriggerClick}
        style={{
          background: 'none',
          border: '1px solid var(--fw-border)',
          borderRadius: 'var(--fw-r-xs)',
          padding: '3px 10px',
          cursor: 'pointer',
          fontSize: 'var(--fw-fs-xs)',
          color: 'var(--fw-t2)',
          fontFamily: 'var(--fw-font-ui)',
          display: 'inline-flex',
          alignItems: 'center',
          gap: 6,
        }}
        onFocus={(e) => {
          e.currentTarget.style.boxShadow = '0 0 0 2px var(--fw-accent)'
        }}
        onBlur={(e) => {
          e.currentTarget.style.boxShadow = 'none'
        }}
      >
        <span aria-hidden="true" style={{ fontSize: '0.85em' }}>
          {open ? '▾' : '▸'}
        </span>
        What the model saw
      </button>

      {/* Drawer content — rendered in-flow (no portal, no inner scrollbar) */}
      {open && (
        <div
          id={`prompt-drawer-content-${analysisId}`}
          ref={contentRef as React.RefObject<HTMLDivElement>}
          role="region"
          aria-label="What the model saw"
          data-testid="prompt-drawer-content"
          {...contentProps}
          style={{
            marginTop: 8,
            borderRadius: 'var(--fw-r-card)',
            border: '1px solid var(--fw-border)',
            background: 'var(--fw-bg-card)',
            padding: '12px 14px',
          }}
        >
          {/* Close button */}
          <div
            style={{
              display: 'flex',
              justifyContent: 'flex-end',
              marginBottom: 8,
            }}
          >
            <button
              type="button"
              data-testid="prompt-drawer-close"
              onClick={close}
              aria-label="Close prompt drawer"
              style={{
                background: 'none',
                border: 'none',
                cursor: 'pointer',
                padding: '2px 6px',
                fontSize: 'var(--fw-fs-xs)',
                color: 'var(--fw-t3)',
                fontFamily: 'var(--fw-font-ui)',
              }}
            >
              ✕
            </button>
          </div>

          {/* Loading state */}
          {status === 'loading' && (
            <div
              data-testid="prompt-drawer-loading"
              style={{
                padding: '16px 0',
                textAlign: 'center',
                color: 'var(--fw-t3)',
                fontSize: 'var(--fw-fs-xs)',
              }}
            >
              Loading analysis…
            </div>
          )}

          {/* Error state */}
          {status === 'error' && (
            <div
              data-testid="prompt-drawer-error"
              role="alert"
              style={{
                padding: '12px 10px',
                borderRadius: 'var(--fw-r-xs)',
                background: 'var(--fw-bg-input)',
                color: 'var(--fw-red)',
                fontSize: 'var(--fw-fs-xs)',
              }}
            >
              {/*
               * error is a static string constructed by useAnalysisDetail —
               * never includes attacker-controlled content (ADR-0029 D3).
               */}
              {error ?? "couldn't load the stored analysis"}
            </div>
          )}

          {/* Idle state — should not appear (fetch triggered on open) */}
          {status === 'idle' && (
            <div
              data-testid="prompt-drawer-idle"
              style={{
                color: 'var(--fw-t3)',
                fontSize: 'var(--fw-fs-xs)',
              }}
            >
              Loading…
            </div>
          )}

          {/* Data loaded */}
          {status === 'ok' && detail !== null && (
            <div data-testid="prompt-drawer-data">
              {/* Stats row: model, latency, tokens */}
              <div
                style={{
                  display: 'flex',
                  flexWrap: 'wrap',
                  gap: 6,
                  marginBottom: 14,
                }}
              >
                {/* model is from the ledger — render as text node (ADR-0029 D3) */}
                <StatPill
                  label="model"
                  value={String(detail.model)}
                  testId="drawer-stat-model"
                />
                {/* latency_ms: always present (required field) */}
                <StatPill
                  label="latency"
                  value={`${detail.latency_ms} ms`}
                  testId="drawer-stat-latency"
                />
                {/*
                 * Token counts: omit when null — never fabricate a 0.
                 * null indicates the endpoint didn't return usage data.
                 */}
                {detail.prompt_tokens !== null && (
                  <StatPill
                    label="prompt tokens"
                    value={detail.prompt_tokens}
                    testId="drawer-stat-prompt-tokens"
                  />
                )}
                {detail.completion_tokens !== null && (
                  <StatPill
                    label="completion tokens"
                    value={detail.completion_tokens}
                    testId="drawer-stat-completion-tokens"
                  />
                )}
              </div>

              {/* Prompt text — split into sections */}
              {detail.prompt_text !== null ? (
                (() => {
                  const sections = splitPromptSections(detail.prompt_text)
                  return (
                    <>
                      {sections.instructions && (
                        <CollapsibleText
                          label="Instructions"
                          text={sections.instructions}
                          testId="drawer-section-instructions"
                        />
                      )}
                      {sections.samples !== null && (
                        <CollapsibleText
                          label="Attack samples (sentinel-delimited)"
                          text={sections.samples}
                          testId="drawer-section-samples"
                          truncated={detail.prompt_truncated}
                        />
                      )}
                      {sections.schema !== null && (
                        <CollapsibleText
                          label="Output schema"
                          text={sections.schema}
                          testId="drawer-section-schema"
                        />
                      )}
                      {/* If no sections were split, show the whole prompt */}
                      {!sections.samples && !sections.schema && !sections.instructions && (
                        <CollapsibleText
                          label="Prompt"
                          text={detail.prompt_text}
                          truncated={detail.prompt_truncated}
                          testId="drawer-section-prompt"
                        />
                      )}
                      {/* Truncation notice when only truncated flag set but no samples section */}
                      {sections.samples === null && detail.prompt_truncated && (
                        <div
                          data-testid="drawer-prompt-truncated"
                          style={{
                            fontSize: 'var(--fw-fs-2xs)',
                            color: 'var(--fw-orange)',
                            fontStyle: 'italic',
                            marginBottom: 8,
                          }}
                        >
                          {TRUNCATED_NOTICE}
                        </div>
                      )}
                    </>
                  )
                })()
              ) : (
                <div
                  data-testid="drawer-prompt-null"
                  style={{
                    color: 'var(--fw-t3)',
                    fontSize: 'var(--fw-fs-xs)',
                    fontStyle: 'italic',
                    marginBottom: 12,
                  }}
                >
                  Prompt text not stored for this analysis.
                </div>
              )}

              {/* Raw response text */}
              {detail.response_text !== null ? (
                <CollapsibleText
                  label="Raw model response"
                  text={detail.response_text}
                  truncated={detail.response_truncated}
                  testId="drawer-section-response"
                />
              ) : (
                <div
                  data-testid="drawer-response-null"
                  style={{
                    color: 'var(--fw-t3)',
                    fontSize: 'var(--fw-fs-xs)',
                    fontStyle: 'italic',
                    marginBottom: 12,
                  }}
                >
                  Response text not stored for this analysis.
                </div>
              )}

              {/* Validated JSON — projected fields the product consumed */}
              {detail.validated_json !== null ? (
                <CollapsibleText
                  label="Validated JSON (consumed by product)"
                  text={JSON.stringify(detail.validated_json, null, 2)}
                  testId="drawer-section-validated-json"
                />
              ) : (
                <div
                  data-testid="drawer-validated-json-null"
                  style={{
                    color: 'var(--fw-t3)',
                    fontSize: 'var(--fw-fs-xs)',
                    fontStyle: 'italic',
                  }}
                >
                  Validated JSON not available (response may have failed validation).
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
