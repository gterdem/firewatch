/**
 * SectionChips — in-panel section jump-chip strip (issue #270, ADR-0037).
 *
 * Renders a horizontal strip of chips at the top of the panel body.
 * WHEN a chip is activated (click or keyboard Enter/Space/Arrow), the panel
 * scrolls to the section with the matching id.
 *
 * WAI-ARIA tablist semantics (UT-03, #503):
 *   The strip uses role="tablist" + role="tab" per WAI-ARIA 1.2 §3.26.
 *   Each chip carries aria-selected (true for the most-recently-activated chip).
 *   Left/Right arrow keys move focus between chips (roving tabindex pattern).
 *   Home/End jump to first/last chip.
 *   Enter/Space activate the focused chip (scroll to section).
 *
 *   NOTE: these chips scroll to visible sections — they do not hide/show panels.
 *   aria-controls is intentionally omitted because the sections are always in the
 *   DOM; the tablist role is used for its keyboard-navigation contract, not for
 *   show/hide semantics. This mirrors VS Code's breadcrumb tab pattern.
 *
 * Generic (panel-scoped): chips are caller-defined; SectionChips has zero
 * knowledge of IP-panel sections. Reusable for future entity panels.
 *
 * Scroll strategy: uses scrollIntoView({ behavior: 'smooth', block: 'start' })
 * which scrolls the nearest scrollable ancestor — i.e. the slide-over body
 * (overflow-y: auto), not the window. This avoids a third scrollbar.
 *
 * ADR-0037: right-side slide-over panel.
 * UT-03 (#503): WAI-ARIA role=tablist/tab, aria-selected, keyboard arrow nav.
 */

import { useRef, useState } from 'react'

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface SectionChip {
  /** Short label shown on the chip button, e.g. "Score". */
  label: string
  /** The id attribute of the section element to scroll to. */
  targetId: string
}

interface SectionChipsProps {
  chips: SectionChip[]
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function SectionChips({ chips }: SectionChipsProps) {
  // Hooks MUST be called unconditionally (Rules of Hooks) — before any early return.

  // Track the index of the most-recently-activated (selected) chip.
  // Used for aria-selected. Defaults to 0 (first chip) — mirrors WAI-ARIA
  // roving tabindex convention: first item has tabIndex=0 on initial render.
  const [activeIndex, setActiveIndex] = useState(0)

  // Refs to all chip buttons for programmatic focus (roving tabindex pattern).
  const chipRefs = useRef<(HTMLButtonElement | null)[]>([])

  if (chips.length === 0) return null

  function scrollToSection(targetId: string) {
    const el = document.getElementById(targetId)
    if (!el) return
    el.scrollIntoView({ behavior: 'smooth', block: 'start' })
  }

  function handleChipClick(index: number) {
    setActiveIndex(index)
    scrollToSection(chips[index].targetId)
  }

  /** Move focus to the chip at `index`, wrapping at boundaries. */
  function moveFocus(index: number) {
    const clamped = (index + chips.length) % chips.length
    chipRefs.current[clamped]?.focus()
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLButtonElement>, index: number) {
    switch (e.key) {
      case 'ArrowRight':
      case 'ArrowDown':
        e.preventDefault()
        moveFocus(index + 1)
        break
      case 'ArrowLeft':
      case 'ArrowUp':
        e.preventDefault()
        moveFocus(index - 1)
        break
      case 'Home':
        e.preventDefault()
        moveFocus(0)
        break
      case 'End':
        e.preventDefault()
        moveFocus(chips.length - 1)
        break
      // Enter and Space use the native button click — no override needed.
    }
  }

  return (
    <div
      role="tablist"
      aria-label="Jump to section"
      data-testid="section-chips"
      style={{
        display: 'flex',
        gap: 6,
        flexWrap: 'wrap',
        marginBottom: 14,
      }}
    >
      {chips.map((chip, index) => {
        const isSelected = index === activeIndex
        return (
          <button
            key={chip.targetId}
            type="button"
            role="tab"
            ref={(el) => { chipRefs.current[index] = el }}
            data-testid={`section-chip-${chip.targetId}`}
            aria-label={`Jump to ${chip.label} section`}
            aria-selected={isSelected}
            // Roving tabindex: only the active chip is in the tab order.
            // Arrow keys move focus within the strip without adding stops
            // to the overall page tab order.
            tabIndex={isSelected ? 0 : -1}
            onClick={() => handleChipClick(index)}
            onKeyDown={(e) => handleKeyDown(e, index)}
            style={{
              padding: '3px 10px',
              background: 'var(--fw-bg-input)',
              border: '1px solid var(--fw-border)',
              borderRadius: 'var(--fw-r-sm)',
              color: 'var(--fw-blue)',
              fontSize: 12,
              cursor: 'pointer',
              fontFamily: 'var(--fw-font-ui)',
            }}
          >
            {chip.label}
          </button>
        )
      })}
    </div>
  )
}
