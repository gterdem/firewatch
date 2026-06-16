/**
 * CursorPager — cursor-pagination controls for the Logs explorer.
 *
 * Consumes the envelope {next_cursor, has_more, total_matching} directly.
 * Clients MUST echo next_cursor from the previous envelope — never offset math.
 *
 * ADR-0029 D2: cursor (keyset) pagination; never compute offsets client-side.
 * ADR-0028 D6: all colors via --fw-* tokens; no Tailwind utility classes for
 *   token-owned concerns (MF-4 v2 kit alignment).
 */

import type React from 'react'

interface CursorPagerProps {
  /** Opaque token from the last envelope; null/undefined = first page. */
  currentCursor?: string | null
  /** next_cursor from the current envelope — passed back on "Next". */
  nextCursor: string | null
  has_more: boolean
  total_matching: number
  pageSize: number
  /** Push the next cursor to load the next page. */
  onNext: (cursor: string) => void
  /** Return to first page (cursor = undefined). */
  onFirst: () => void
}

const BTN_BASE: React.CSSProperties = {
  background: 'var(--fw-bg-input)',
  border: '1px solid var(--fw-border-l)',
  borderRadius: 'var(--fw-r-xs)',
  color: 'var(--fw-t2)',
  cursor: 'pointer',
  fontFamily: 'var(--fw-font-ui)',
  fontSize: 'var(--fw-fs-sm)',
  padding: '4px 12px',
}

const BTN_DISABLED: React.CSSProperties = {
  ...BTN_BASE,
  opacity: 0.4,
  cursor: 'default',
}

export default function CursorPager({
  currentCursor,
  nextCursor,
  has_more,
  total_matching,
  pageSize,
  onNext,
  onFirst,
}: CursorPagerProps) {
  const isFirst = !currentCursor
  const nextDisabled = !has_more || nextCursor === null

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        fontFamily: 'var(--fw-font-ui)',
        fontSize: 'var(--fw-fs-sm)',
        color: 'var(--fw-t3)',
        padding: '6px 2px',
      }}
      data-testid="cursor-pager"
    >
      <span
        style={{ fontFamily: 'var(--fw-font-mono)', fontSize: 'var(--fw-fs-sm)' }}
        data-testid="pager-count"
      >
        {total_matching.toLocaleString()} matching events
        {pageSize > 0 && (
          <span style={{ marginLeft: 6, color: 'var(--fw-t3)' }}>(showing {pageSize})</span>
        )}
      </span>

      <div style={{ display: 'flex', gap: 6 }}>
        <button
          type="button"
          disabled={isFirst}
          style={isFirst ? BTN_DISABLED : BTN_BASE}
          data-testid="pager-first"
          aria-label="Go to first page"
          onClick={onFirst}
        >
          First
        </button>

        <button
          type="button"
          disabled={nextDisabled}
          style={nextDisabled ? BTN_DISABLED : BTN_BASE}
          data-testid="pager-next"
          aria-label="Go to next page"
          onClick={() => {
            if (nextCursor) onNext(nextCursor)
          }}
        >
          Next
        </button>
      </div>
    </div>
  )
}
