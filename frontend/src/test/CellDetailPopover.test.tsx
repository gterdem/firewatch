/**
 * Tests for CellDetailPopover — shared full-value popover for Signature and
 * Payload cells (issue #329, part-4 P5.4).
 *
 * EARS criteria covered (mapped 1:1 to issue #329 spec):
 *
 * 1. Full value rendered:
 *    WHEN CellDetailPopover is rendered, the full untruncated value SHALL appear
 *    in `cell-detail-full-value`.
 *
 * 2. Metadata rows:
 *    WHEN metadata is provided, each row SHALL appear as `cell-detail-meta-{label}`.
 *    WHEN metadata is empty, the metadata section SHALL NOT render.
 *
 * 3. Copy action:
 *    WHEN the Copy button is clicked, the `cell-detail-copy` button SHALL be present
 *    and the button text SHALL change to "Copied!" after a successful clipboard write.
 *
 * 4. "View in Network Logs" deep-link:
 *    WHEN `onNavigate` is provided, `cell-detail-view-in-logs` SHALL render.
 *    WHEN `onNavigate` is absent, the link SHALL NOT render.
 *    WHEN the link is clicked, `onNavigate` SHALL be called and `onClose` SHALL be called.
 *
 * 5. XSS safety (ADR-0029 D3):
 *    WHEN fullValue contains HTML/script, it SHALL render as inert text, never live DOM.
 *    WHEN metadata values contain HTML, they SHALL render as inert text.
 *
 * 6. Outside-click dismiss:
 *    WHEN a pointer-down event fires outside both trigger and content, the popover
 *    SHALL close (via useDismissableDisclosure). Tested at RuleCellTooltip level.
 *
 * 7. Esc dismiss:
 *    WHEN Esc is pressed, the popover SHALL close (via useDismissableDisclosure).
 *    Tested at RuleCellTooltip level (RuleCellTooltip.test.tsx, RulePopupEsc.test.tsx).
 *
 * Note: dismiss tests (outside-click, Esc) are exercised at the RuleCellTooltip /
 * PayloadCellTooltip level because CellDetailPopover is a pure renderer with no
 * dismiss logic of its own. Its contract: caller wires useDismissableDisclosure and
 * passes contentRef for outside-click detection.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor, act } from '@testing-library/react'
import { useRef } from 'react'
import { CellDetailPopover } from '../components/logs/CellDetailPopover'
import type { CellDetailMetaRow } from '../components/logs/CellDetailPopover'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Minimal wrapper that supplies contentRef and triggerRef.
 * CellDetailPopover is a pure renderer — it needs refs from the caller.
 */
function PopoverWrapper({
  fullValue,
  metadata = [],
  onNavigate,
  onClose = vi.fn(),
}: {
  fullValue: string
  metadata?: CellDetailMetaRow[]
  onNavigate?: () => void
  onClose?: () => void
}) {
  const contentRef = useRef<HTMLElement | null>(null)
  const triggerRef = useRef<HTMLElement | null>(null)
  return (
    <CellDetailPopover
      fullValue={fullValue}
      metadata={metadata}
      onNavigate={onNavigate}
      contentRef={contentRef}
      triggerRef={triggerRef}
      onClose={onClose}
      data-testid="cell-detail-popover"
    />
  )
}

beforeEach(() => {
  vi.clearAllMocks()
})

// ---------------------------------------------------------------------------
// 1. Full value rendered
// ---------------------------------------------------------------------------

describe('CellDetailPopover — full value', () => {
  it('renders the full untruncated value in cell-detail-full-value', () => {
    render(<PopoverWrapper fullValue="ET SCAN Potential VNC Scan 2001219" />)
    expect(screen.getByTestId('cell-detail-full-value'))
      .toHaveTextContent('ET SCAN Potential VNC Scan 2001219')
  })

  it('renders long payload values without truncation', () => {
    // Use a plain long string without \r\n (toHaveTextContent normalizes whitespace)
    const longValue = 'GET /api/v1/users?filter=admin&sort=desc&page=1&limit=100 HTTP/1.1 Host: 198.51.100.99 User-Agent: Mozilla/5.0 (compatible; scanner/1.0)'
    render(<PopoverWrapper fullValue={longValue} />)
    expect(screen.getByTestId('cell-detail-full-value')).toHaveTextContent(longValue)
  })

  it('portals to document.body (escapes stacking context)', () => {
    const { baseElement } = render(<PopoverWrapper fullValue="test value" />)
    // The portal renders into document.body, not the React root div.
    // baseElement IS document.body, so queryByTestId on body finds it.
    const popover = screen.getByTestId('cell-detail-popover')
    expect(document.body.contains(popover)).toBe(true)
    // The React root div should NOT contain the portal.
    const root = baseElement.querySelector('div')
    expect(root?.contains(popover)).toBe(false)
  })
})

// ---------------------------------------------------------------------------
// 2. Metadata rows
// ---------------------------------------------------------------------------

describe('CellDetailPopover — metadata rows', () => {
  it('renders each metadata row with correct testid cell-detail-meta-{label}', () => {
    const meta: CellDetailMetaRow[] = [
      { label: 'sid', value: '2001219' },
      { label: 'category', value: 'Port Scan' },
      { label: 'source', value: 'suricata' },
    ]
    render(<PopoverWrapper fullValue="ET SCAN" metadata={meta} />)
    expect(screen.getByTestId('cell-detail-meta-sid')).toHaveTextContent('2001219')
    expect(screen.getByTestId('cell-detail-meta-category')).toHaveTextContent('Port Scan')
    expect(screen.getByTestId('cell-detail-meta-source')).toHaveTextContent('suricata')
  })

  it('renders cell-detail-metadata container when rows present', () => {
    const meta: CellDetailMetaRow[] = [{ label: 'sid', value: '9999' }]
    render(<PopoverWrapper fullValue="test" metadata={meta} />)
    expect(screen.getByTestId('cell-detail-metadata')).toBeInTheDocument()
  })

  it('does NOT render cell-detail-metadata when metadata is empty', () => {
    render(<PopoverWrapper fullValue="test" metadata={[]} />)
    expect(screen.queryByTestId('cell-detail-metadata')).not.toBeInTheDocument()
  })

  it('description row visible when desc metadata is provided', () => {
    const meta: CellDetailMetaRow[] = [
      { label: 'desc', value: 'Detects potential VNC scanning activity.' },
    ]
    render(<PopoverWrapper fullValue="ET SCAN" metadata={meta} />)
    expect(screen.getByTestId('cell-detail-meta-desc'))
      .toHaveTextContent('Detects potential VNC scanning activity.')
  })
})

// ---------------------------------------------------------------------------
// 3. Copy action
// ---------------------------------------------------------------------------

describe('CellDetailPopover — Copy button', () => {
  it('renders cell-detail-copy button', () => {
    render(<PopoverWrapper fullValue="some value" />)
    expect(screen.getByTestId('cell-detail-copy')).toBeInTheDocument()
    expect(screen.getByTestId('cell-detail-copy')).toHaveTextContent('Copy')
  })

  it('Copy button label changes to "Copied!" after clipboard write', async () => {
    // Mock clipboard
    const writeText = vi.fn().mockResolvedValue(undefined)
    Object.defineProperty(navigator, 'clipboard', {
      value: { writeText },
      configurable: true,
    })

    render(<PopoverWrapper fullValue="ET SCAN Potential VNC Scan" />)
    const btn = screen.getByTestId('cell-detail-copy')
    expect(btn).toHaveTextContent('Copy')

    await act(async () => {
      fireEvent.click(btn)
    })

    await waitFor(() => {
      expect(screen.getByTestId('cell-detail-copy')).toHaveTextContent('Copied!')
    })
    expect(writeText).toHaveBeenCalledWith('ET SCAN Potential VNC Scan')
  })

  it('renders cell-detail-actions container', () => {
    render(<PopoverWrapper fullValue="test" />)
    expect(screen.getByTestId('cell-detail-actions')).toBeInTheDocument()
  })
})

// ---------------------------------------------------------------------------
// 4. "View in Network Logs" deep-link
// ---------------------------------------------------------------------------

describe('CellDetailPopover — View in Network Logs', () => {
  it('renders cell-detail-view-in-logs when onNavigate is provided', () => {
    render(<PopoverWrapper fullValue="ET SCAN" onNavigate={vi.fn()} />)
    expect(screen.getByTestId('cell-detail-view-in-logs')).toBeInTheDocument()
    expect(screen.getByTestId('cell-detail-view-in-logs')).toHaveTextContent('View in Network Logs')
  })

  it('does NOT render cell-detail-view-in-logs when onNavigate is absent', () => {
    render(<PopoverWrapper fullValue="ET SCAN" />)
    expect(screen.queryByTestId('cell-detail-view-in-logs')).not.toBeInTheDocument()
  })

  it('calls onNavigate and onClose when View in Network Logs is clicked', () => {
    const onNavigate = vi.fn()
    const onClose = vi.fn()
    render(<PopoverWrapper fullValue="ET SCAN" onNavigate={onNavigate} onClose={onClose} />)

    fireEvent.click(screen.getByTestId('cell-detail-view-in-logs'))

    expect(onNavigate).toHaveBeenCalledTimes(1)
    expect(onClose).toHaveBeenCalledTimes(1)
  })
})

// ---------------------------------------------------------------------------
// 5. XSS safety (ADR-0029 D3)
// ---------------------------------------------------------------------------

describe('CellDetailPopover — XSS safety (ADR-0029 D3)', () => {
  it('renders HTML in fullValue as inert literal text — never live DOM', () => {
    render(<PopoverWrapper fullValue='<script>alert("xss")</script>' />)
    const el = screen.getByTestId('cell-detail-full-value')
    // Must appear as literal text
    expect(el.textContent).toContain('<script>alert("xss")</script>')
    // Must NOT inject live script element
    expect(document.querySelectorAll('script[data-xss]').length).toBe(0)
  })

  it('renders img onerror in fullValue as inert literal text', () => {
    render(<PopoverWrapper fullValue='<img src=x onerror=alert(1)>' />)
    const el = screen.getByTestId('cell-detail-full-value')
    expect(el.textContent).toContain('<img src=x onerror=alert(1)>')
    expect(document.querySelectorAll('img[onerror]').length).toBe(0)
  })

  it('renders HTML in metadata value as inert literal text', () => {
    const meta: CellDetailMetaRow[] = [
      { label: 'desc', value: '<script>alert("meta-xss")</script>' },
    ]
    render(<PopoverWrapper fullValue="safe name" metadata={meta} />)
    const el = screen.getByTestId('cell-detail-meta-desc')
    expect(el.textContent).toContain('<script>alert("meta-xss")</script>')
    expect(document.querySelectorAll('script').length).toBe(0)
  })

  it('does not use dangerouslySetInnerHTML — only text nodes', () => {
    // Render with dangerous content and verify no innerHTML injection
    const dangerous = '"><svg onload=alert(1)>'
    render(<PopoverWrapper fullValue={dangerous} />)
    const el = screen.getByTestId('cell-detail-full-value')
    // Text content should be the raw string, not parsed HTML
    expect(el.textContent).toBe(dangerous)
    expect(document.querySelectorAll('svg[onload]').length).toBe(0)
  })
})

// ---------------------------------------------------------------------------
// 6. ARIA / accessibility
// ---------------------------------------------------------------------------

describe('CellDetailPopover — ARIA', () => {
  it('has role="dialog" on the root popover div', () => {
    render(<PopoverWrapper fullValue="test" />)
    const popover = screen.getByRole('dialog')
    expect(popover).toHaveAttribute('data-testid', 'cell-detail-popover')
  })

  it('has aria-label on the popover', () => {
    render(<PopoverWrapper fullValue="test" />)
    const popover = screen.getByRole('dialog')
    expect(popover).toHaveAttribute('aria-label', 'Cell detail')
  })
})
