/**
 * CopyButton — reusable Copy affordance for detail panel fields (ADR-0063 D3).
 *
 * Mirrors the CopyButton pattern from CellDetailPopover.tsx but is extracted
 * as a standalone module so detail-panel components can import it directly
 * without pulling in the full CellDetailPopover (which portals to body and
 * requires additional refs).
 *
 * SECURITY (ADR-0029 D3): value is written to clipboard only — never echoed
 * back into the DOM as HTML.
 */

import { useState, useRef, useEffect } from 'react'

interface CopyButtonProps {
  /** Value to write to the clipboard. Attacker-controlled — written to clipboard only. */
  value: string
  /** Optional data-testid for the button. */
  'data-testid'?: string
}

/**
 * Inline Copy button. On click: writes `value` to clipboard and briefly
 * shows "Copied!" before resetting to "Copy".
 */
export function CopyButton({ value, 'data-testid': testId = 'detail-copy-btn' }: CopyButtonProps) {
  const [copied, setCopied] = useState(false)
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  function handleCopy() {
    if (typeof navigator !== 'undefined' && navigator.clipboard) {
      void navigator.clipboard.writeText(value).then(() => {
        setCopied(true)
        if (timerRef.current) clearTimeout(timerRef.current)
        timerRef.current = setTimeout(() => setCopied(false), 1500)
      })
    }
  }

  useEffect(() => {
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current)
    }
  }, [])

  return (
    <button
      type="button"
      data-testid={testId}
      onClick={(e) => {
        e.stopPropagation()
        handleCopy()
      }}
      style={{
        background: 'var(--fw-bg-input)',
        border: '1px solid var(--fw-border)',
        borderRadius: 'var(--fw-r-sm)',
        padding: '1px 6px',
        cursor: 'pointer',
        fontFamily: 'var(--fw-font-ui)',
        fontSize: 10,
        color: copied ? 'var(--fw-accent, var(--fw-blue))' : 'var(--fw-t3)',
        transition: 'color 0.1s',
        whiteSpace: 'nowrap',
        flexShrink: 0,
      }}
      aria-live="polite"
      aria-label={copied ? 'Copied to clipboard' : 'Copy value to clipboard'}
    >
      {copied ? 'Copied!' : 'Copy'}
    </button>
  )
}
