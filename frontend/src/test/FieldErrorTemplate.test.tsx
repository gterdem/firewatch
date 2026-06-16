/**
 * Tests for src/widgets/FieldErrorTemplate.tsx (F4 re-skin, #110)
 *
 * EARS criteria covered (#67 — validation a11y; F4 — DS error look):
 *   - Ubiquitous: renders nothing when errors array is empty.
 *   - Event-driven: renders error messages in a role="alert" container (WCAG 4.1.3).
 *   - Ubiquitous: aria-live="assertive" ensures immediate screen reader announcement.
 *   - Ubiquitous (DS re-skin): error spans have --fw-red color (DS critical token).
 *   - Ubiquitous (DS re-skin): error spans have data-fw-error attribute for targeting.
 */

import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import FieldErrorTemplate from '../widgets/FieldErrorTemplate'
import type { FieldErrorProps } from '@rjsf/utils'

/** Minimal FieldErrorProps stub. */
function makeProps(overrides: Partial<FieldErrorProps> = {}): FieldErrorProps {
  return {
    errors: [],
    fieldPathId: { $id: 'root_port', $idPrefix: 'root', path: ['port'] } as FieldErrorProps['fieldPathId'],
    schema: {},
    uiSchema: {},
    idSchema: { $id: 'root_port' },
    registry: {} as FieldErrorProps['registry'],
    formContext: {},
    ...overrides,
  } as FieldErrorProps
}

describe('FieldErrorTemplate', () => {
  it('renders nothing when errors is empty', () => {
    const { container } = render(<FieldErrorTemplate {...makeProps({ errors: [] })} />)
    expect(container.firstChild).toBeNull()
  })

  it('renders nothing when errors is undefined', () => {
    const { container } = render(<FieldErrorTemplate {...makeProps({ errors: undefined })} />)
    expect(container.firstChild).toBeNull()
  })

  // A11y (#67): error container must have role="alert" so screen readers
  // announce the error immediately when it appears (WCAG 4.1.3 / ARIA 1.1).
  it('renders error messages in a role="alert" container (#67 a11y)', () => {
    render(
      <FieldErrorTemplate
        {...makeProps({ errors: ['Value must be ≤ 65535', 'Value is required'] })}
      />,
    )
    const alertEl = screen.getByRole('alert')
    expect(alertEl).toBeInTheDocument()
    expect(alertEl).toHaveTextContent('Value must be ≤ 65535')
    expect(alertEl).toHaveTextContent('Value is required')
  })

  it('has aria-live="assertive" on the error container (#67 a11y)', () => {
    render(
      <FieldErrorTemplate {...makeProps({ errors: ['Port out of range'] })} />,
    )
    const alertEl = screen.getByRole('alert')
    expect(alertEl.getAttribute('aria-live')).toBe('assertive')
  })

  it('renders each error in a separate span', () => {
    render(
      <FieldErrorTemplate
        {...makeProps({ errors: ['Error one', 'Error two'] })}
      />,
    )
    expect(screen.getByText('Error one')).toBeInTheDocument()
    expect(screen.getByText('Error two')).toBeInTheDocument()
  })

  // DS re-skin (#110): error spans use --fw-red (DS critical token), not shadcn text-destructive.
  it('renders error spans with DS --fw-red color [F4 re-skin]', () => {
    render(
      <FieldErrorTemplate {...makeProps({ errors: ['Invalid value'] })} />,
    )
    const errorSpan = document.querySelector('[data-fw-error]') as HTMLElement
    expect(errorSpan).not.toBeNull()
    expect(errorSpan.style.color).toBe('var(--fw-red)')
  })

  // DS re-skin (#110): data-fw-error attribute on each error span.
  it('has data-fw-error attribute on error spans [F4 re-skin]', () => {
    render(
      <FieldErrorTemplate {...makeProps({ errors: ['Err A', 'Err B'] })} />,
    )
    const errorSpans = document.querySelectorAll('[data-fw-error]')
    expect(errorSpans.length).toBe(2)
  })
})
