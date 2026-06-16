/**
 * SelectWidget — DS-styled native <select> for rjsf enum fields (F4, #110).
 *
 * Replaces @rjsf/shadcn's FancySelect (Combobox overlay) with a native <select>
 * styled to match the DS Select component (src/components/ds/forms/Select.tsx):
 *   --fw-bg-input inset well, 1px --fw-border-l border, --fw-font-mono,
 *   amber (--fw-accent) focus ring, --fw-red on validation error.
 *
 * A native <select> is preferred over the Combobox overlay because:
 *   - Better mobile/keyboard accessibility (browser-native dropdown behaviour).
 *   - Matches the DS Select recipe which also uses native <select>.
 *   - No FancySelect dependency from @rjsf/shadcn internals.
 *
 * Preserved behaviors:
 *   - Single and multiple selection modes.
 *   - aria-invalid="true" DOM attribute when rawErrors is non-empty (ARIA 1.1 §6.6.5).
 *   - aria-describedby linked to field description.
 *   - disabled, readonly, required forwarded.
 *   - enumDisabled marks individual options as disabled.
 *
 * ADR-0028: part of the project-local widget/template registry.
 * ADR-0010: schema-driven; this widget renders for ALL source types with enum fields.
 */

import type {
  WidgetProps,
  FormContextType,
  RJSFSchema,
  StrictRJSFSchema,
} from '@rjsf/utils'
import { ariaDescribedByIds } from '@rjsf/utils'
import type { ChangeEvent } from 'react'

/** DS Select base style — mirrors src/components/ds/forms/Select.tsx BASE_SELECT_STYLE. */
const SELECT_BASE_STYLE: React.CSSProperties = {
  width: '100%',
  padding: '8px 12px',
  background: 'var(--fw-bg-input)',
  border: '1px solid var(--fw-border-l)',
  borderRadius: 'var(--fw-r-sm)',
  color: 'var(--fw-t1)',
  fontSize: 'var(--fw-fs-body)',
  fontFamily: 'var(--fw-font-mono)',
  outline: 'none',
  cursor: 'pointer',
  transition:
    'border-color var(--fw-dur-fast) var(--fw-ease), box-shadow var(--fw-dur-fast) var(--fw-ease)',
  boxSizing: 'border-box',
  appearance: 'auto',
}

/** Error state: --fw-red border + subtle red ring. */
const SELECT_ERROR_STYLE: React.CSSProperties = {
  borderColor: 'var(--fw-red)',
  boxShadow: '0 0 0 2px rgba(239, 68, 68, 0.2)',
}

/** Disabled overrides. */
const SELECT_DISABLED_STYLE: React.CSSProperties = {
  opacity: 0.5,
  cursor: 'not-allowed',
  pointerEvents: 'none',
}

/**
 * SelectWidget — DS-styled native select for rjsf enum/const-enum fields.
 *
 * Supports single and multiple selection. In single-select mode, an empty option
 * is prepended when the field is not required (to let the user clear the value).
 */
export default function SelectWidget<
  T = unknown,
  S extends StrictRJSFSchema = RJSFSchema,
  F extends FormContextType = object,
>({
  id,
  required,
  disabled,
  readonly,
  value,
  multiple,
  autofocus,
  onChange,
  onBlur,
  onFocus,
  placeholder,
  rawErrors = [],
  options,
}: WidgetProps<T, S, F>) {
  const { enumOptions = [], enumDisabled = [] } = options

  const hasErrors = rawErrors.length > 0

  const computedStyle: React.CSSProperties = {
    ...SELECT_BASE_STYLE,
    ...(hasErrors ? SELECT_ERROR_STYLE : {}),
    ...((disabled || readonly) ? SELECT_DISABLED_STYLE : {}),
  }

  function handleSingleChange(e: ChangeEvent<HTMLSelectElement>) {
    const selected = e.target.value
    const matchedOption = (enumOptions as Array<{ value: unknown; label: string }>).find(
      (opt) => String(opt.value) === selected,
    )
    onChange(matchedOption ? (matchedOption.value as T) : (selected as T))
  }

  function handleMultiChange(e: ChangeEvent<HTMLSelectElement>) {
    const selectedValues = Array.from(e.target.selectedOptions).map((opt) => opt.value)
    const matchedValues = selectedValues.map((sel) => {
      const matched = (enumOptions as Array<{ value: unknown; label: string }>).find(
        (opt) => String(opt.value) === sel,
      )
      return matched ? matched.value : sel
    })
    onChange(matchedValues as T)
  }

  // Current string value(s) for matching to <option> elements
  const currentValue = multiple
    ? (Array.isArray(value) ? (value as unknown[]).map(String) : [])
    : value !== undefined && value !== null
      ? String(value)
      : ''

  return (
    <div className="p-0.5">
      <select
        data-fw-select=""
        id={id}
        multiple={multiple}
        required={required}
        disabled={disabled || readonly}
        autoFocus={autofocus}
        style={computedStyle}
        value={currentValue as string | string[]}
        aria-invalid={hasErrors ? ('true' as const) : undefined}
        aria-describedby={ariaDescribedByIds(id)}
        onChange={multiple ? handleMultiChange : handleSingleChange}
        onBlur={(e) => {
          if (e.currentTarget.style) {
            e.currentTarget.style.borderColor = hasErrors ? 'var(--fw-red)' : 'var(--fw-border-l)'
            e.currentTarget.style.boxShadow = hasErrors
              ? '0 0 0 2px rgba(239, 68, 68, 0.2)'
              : 'none'
          }
          onBlur(id, e.target.value)
        }}
        onFocus={(e) => {
          if (e.currentTarget.style) {
            e.currentTarget.style.borderColor = hasErrors ? 'var(--fw-red)' : 'var(--fw-accent)'
            e.currentTarget.style.boxShadow = hasErrors
              ? '0 0 0 2px rgba(239, 68, 68, 0.2)'
              : '0 0 0 2px rgba(245, 158, 11, 0.25)'
          }
          onFocus(id, e.target.value)
        }}
      >
        {/* Empty option for non-required single selects to allow clearing */}
        {!multiple && !required && (
          <option value="">{placeholder ?? ''}</option>
        )}
        {(enumOptions as Array<{ value: unknown; label: string }>).map((opt, i) => {
          const optValue = String(opt.value)
          const isDisabled = (enumDisabled as unknown[]).includes(opt.value)
          return (
            <option key={i} value={optValue} disabled={isDisabled}>
              {opt.label}
            </option>
          )
        })}
      </select>
    </div>
  )
}
