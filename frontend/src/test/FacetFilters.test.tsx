/**
 * Tests for src/components/logs/FacetFilters.tsx (#112, #252)
 *
 * EARS criteria covered:
 *   - Filter bar renders Combobox for Source / Category / Action / Severity + search.
 *   - WHEN a server Combobox changes, onFilterChange fires with cursor reset.
 *   - WHEN the Action Combobox changes, onFilterChange fires with action= (server-side, #252).
 *   - WHEN a FilterChip ✕ is clicked, the facet clears (onFilterChange).
 *   - WHEN Clear all is clicked, all facets reset.
 *   - Active chips render for each active facet.
 *   - "blocked" option appears in the Action dropdown labeled "Blocked (BLOCK + DROP)" (#252).
 */

import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent } from '@testing-library/react'
import FacetFilters from '../components/logs/FacetFilters'
import type { LogsFilter } from '../api/types'

const noop = vi.fn()

function renderFilters(
  filter: LogsFilter = {},
  onFilterChange = vi.fn(),
) {
  return render(
    <FacetFilters
      filter={filter}
      onFilterChange={onFilterChange}
    />,
  )
}

describe('FacetFilters — render', () => {
  it('renders all four Comboboxes and the search input', () => {
    renderFilters()
    expect(screen.getByTestId('filter-source-combo')).toBeInTheDocument()
    expect(screen.getByTestId('filter-category-combo')).toBeInTheDocument()
    expect(screen.getByTestId('filter-action-combo')).toBeInTheDocument()
    expect(screen.getByTestId('filter-severity-combo')).toBeInTheDocument()
    expect(screen.getByTestId('filter-search')).toBeInTheDocument()
  })

  it('renders export CSV and JSON buttons', () => {
    renderFilters()
    expect(screen.getByTestId('export-csv')).toBeInTheDocument()
    expect(screen.getByTestId('export-json')).toBeInTheDocument()
  })

  it('shows the total matching count when provided', () => {
    render(
      <FacetFilters
        filter={{}}
        onFilterChange={noop}
        totalMatching={1287}
      />,
    )
    expect(screen.getByTestId('filter-count')).toHaveTextContent('1,287 logs')
  })

  it('"blocked" option is available in the Action dropdown (issue #252)', () => {
    renderFilters()
    const actionInput = screen.getByTestId('filter-action-combo').querySelector('input')!
    fireEvent.focus(actionInput)
    expect(screen.getByTestId('combobox-option-blocked')).toBeInTheDocument()
    expect(screen.getByTestId('combobox-option-blocked')).toHaveTextContent(
      'Blocked (BLOCK + DROP)',
    )
  })
})

describe('FacetFilters — search input', () => {
  it('calls onFilterChange with q= (not search=) and cursor reset (issue #177)', () => {
    const onChange = vi.fn()
    renderFilters({ cursor: 'some-cursor' }, onChange)
    fireEvent.change(screen.getByTestId('filter-search'), { target: { value: 'injection' } })
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ q: 'injection', cursor: undefined }),
    )
    // Regression guard: must NOT send the ignored ?search= param
    const call = onChange.mock.calls[0][0] as LogsFilter
    expect('search' in call).toBe(false)
  })

  it('sets undefined (not empty string) when search is cleared', () => {
    const onChange = vi.fn()
    renderFilters({ q: 'existing' }, onChange)
    fireEvent.change(screen.getByTestId('filter-search'), { target: { value: '' } })
    const call = onChange.mock.calls[0][0] as LogsFilter
    expect(call.q).toBeUndefined()
  })
})

describe('FacetFilters — Action combobox (server-side, issue #252)', () => {
  it('calls onFilterChange with action= when Action combobox option is picked', () => {
    const onFilter = vi.fn()
    renderFilters({}, onFilter)
    // Open the Action combobox
    const actionInput = screen.getByTestId('filter-action-combo').querySelector('input')!
    fireEvent.focus(actionInput)
    // Pick "Alert (IDS)"
    const alertOption = screen.getByTestId('combobox-option-ALERT')
    fireEvent.mouseDown(alertOption)
    // onFilterChange is called with action=ALERT and cursor reset
    expect(onFilter).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'ALERT', cursor: undefined }),
    )
  })

  it('calls onFilterChange with action=blocked when "blocked" option is picked', () => {
    const onFilter = vi.fn()
    renderFilters({}, onFilter)
    const actionInput = screen.getByTestId('filter-action-combo').querySelector('input')!
    fireEvent.focus(actionInput)
    fireEvent.mouseDown(screen.getByTestId('combobox-option-blocked'))
    expect(onFilter).toHaveBeenCalledWith(
      expect.objectContaining({ action: 'blocked', cursor: undefined }),
    )
  })

  it('calls onFilterChange with action=undefined when action chip is removed', () => {
    const onFilter = vi.fn()
    renderFilters({ action: 'ALERT' }, onFilter)
    // Remove via the chip (chip removal is the clearing path for server-side filters)
    const chip = screen.getByTestId('chip-action')
    fireEvent.click(chip.querySelector('[role="button"]')!)
    expect(onFilter).toHaveBeenCalledWith(
      expect.objectContaining({ action: undefined }),
    )
  })
})

describe('FacetFilters — FilterChips', () => {
  it('shows no chips when no filter is active', () => {
    renderFilters()
    expect(screen.queryByTestId('filter-chips')).not.toBeInTheDocument()
  })

  it('shows a chip for active search filter (q field)', () => {
    renderFilters({ q: 'payload-test' })
    expect(screen.getByTestId('chip-search')).toHaveTextContent('Search: payload-test')
  })

  it('shows a chip for active severity filter', () => {
    renderFilters({ severity: 'high' })
    expect(screen.getByTestId('chip-severity')).toHaveTextContent('Severity: high')
  })

  it('shows a chip for active action filter with label from ACTION_OPTIONS', () => {
    renderFilters({ action: 'blocked' })
    expect(screen.getByTestId('chip-action')).toHaveTextContent(
      'Action: Blocked (BLOCK + DROP)',
    )
  })

  it('shows a chip for exact action value (ALERT) with its label', () => {
    renderFilters({ action: 'ALERT' })
    expect(screen.getByTestId('chip-action')).toHaveTextContent('Action: Alert (IDS)')
  })

  it('removing search chip calls onFilterChange with q undefined', () => {
    const onChange = vi.fn()
    renderFilters({ q: 'foo' }, onChange)
    const chip = screen.getByTestId('chip-search')
    fireEvent.click(chip.querySelector('[role="button"]')!)
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ q: undefined }),
    )
  })

  it('removing action chip calls onFilterChange with action undefined', () => {
    const onFilter = vi.fn()
    renderFilters({ action: 'BLOCK' }, onFilter)
    const chip = screen.getByTestId('chip-action')
    fireEvent.click(chip.querySelector('[role="button"]')!)
    expect(onFilter).toHaveBeenCalledWith(
      expect.objectContaining({ action: undefined }),
    )
  })

  it('Clear all resets all server filters including action', () => {
    const onFilter = vi.fn()
    renderFilters({ q: 'foo', severity: 'high', action: 'ALERT' }, onFilter)
    fireEvent.click(screen.getByTestId('filter-clear'))
    expect(onFilter).toHaveBeenCalledWith({})
  })
})
