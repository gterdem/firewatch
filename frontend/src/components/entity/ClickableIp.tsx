/**
 * ClickableIp — the shared entity token for IP addresses (ADR-0037).
 *
 * Renders an IP address as a mono-blue, focusable element that opens
 * the entity slide-over panel when clicked or activated via Enter/Space.
 *
 * Usage:
 *   <ClickableIp value="192.0.2.1" />
 *
 * Keyboard: Enter and Space activate the same as a click.
 * Wave-2 note: hover micro-menu (Analyze · Filter · Copy) is additive on
 * the same token — this issue delivers the base token only.
 *
 * SECURITY (ADR-0029 D3): IP address is rendered as a text node.
 */

import { useRef, type KeyboardEvent, type CSSProperties } from 'react'
import { useEntityPanel } from './EntityPanelContext'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ClickableIpProps {
  value: string
  /** Optional className for consumer overrides. */
  className?: string
  /**
   * Override font-size (and other style properties) for contexts where the
   * token must match a smaller surrounding text (e.g. triage banner chips).
   * The component's base mono/blue/underline styling is preserved; only the
   * properties provided here are merged on top.
   */
  style?: React.CSSProperties
  /**
   * Accessible label override.  Defaults to the IP value itself.
   * Useful when the surrounding context adds meaning (e.g. "Investigate 192.0.2.1").
   */
  'aria-label'?: string
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function ClickableIp({
  value,
  className,
  style: styleOverride,
  'aria-label': ariaLabel,
}: ClickableIpProps) {
  const { openEntity } = useEntityPanel()
  const ref = useRef<HTMLButtonElement>(null)

  function handleClick() {
    openEntity({ kind: 'ip', value })
  }

  function handleKeyDown(e: KeyboardEvent<HTMLButtonElement>) {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      openEntity({ kind: 'ip', value })
    }
  }

  const baseStyle: CSSProperties = {
    background: 'none',
    border: 'none',
    cursor: 'pointer',
    fontFamily: 'var(--fw-font-mono)',
    color: 'var(--fw-blue)',
    fontSize: 'inherit',
    padding: 0,
    textDecoration: 'underline',
    textDecorationStyle: 'dotted',
    textUnderlineOffset: 2,
  }

  return (
    <button
      ref={ref}
      type="button"
      data-testid="clickable-ip"
      className={className}
      style={styleOverride ? { ...baseStyle, ...styleOverride } : baseStyle}
      aria-label={ariaLabel ?? value}
      onClick={handleClick}
      onKeyDown={handleKeyDown}
    >
      {value}
    </button>
  )
}
