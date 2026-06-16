/**
 * BaseInputTemplate — re-skinned to the DS Input look (F4, #110).
 *
 * Visual target: matches src/components/ds/forms/Input.tsx —
 *   monospace font on --fw-bg-input inset well, 1px --fw-border-l border,
 *   --fw-r-sm radius, amber (--fw-accent) focus ring, --fw-red border on error.
 *
 * Preserved behaviors (all tested):
 *   - aria-invalid="true" DOM attribute when rawErrors non-empty (ARIA 1.1 §6.6.5 / WCAG 4.1.3)
 *   - aria-invalid absent when valid
 *   - id, type, disabled, required forwarded to the input
 *   - onChange, onBlur, onFocus wired correctly
 *
 * ADR-0028: part of the project-local widget/template registry.
 * ADR-0010: schema-driven; this template renders for ALL source types.
 */

import { type ChangeEvent, type FocusEvent, type MouseEvent, useCallback } from 'react'
import type {
  BaseInputTemplateProps,
  FormContextType,
  RJSFSchema,
  StrictRJSFSchema,
} from '@rjsf/utils'
import { ariaDescribedByIds, examplesId, getInputProps } from '@rjsf/utils'
import { SchemaExamples } from '@rjsf/core'

/**
 * DS Input base style — mirrors src/components/ds/forms/Input.tsx BASE_INPUT_STYLE.
 * Monospace on inset well; amber focus ring applied imperatively via onFocus/onBlur.
 */
const INPUT_BASE_STYLE: React.CSSProperties = {
  width: '100%',
  background: 'var(--fw-bg-input)',
  border: '1px solid var(--fw-border-l)',
  borderRadius: 'var(--fw-r-sm)',
  color: 'var(--fw-t1)',
  fontFamily: 'var(--fw-font-mono)',
  fontSize: 'var(--fw-fs-body)',
  padding: '8px 12px',
  outline: 'none',
  transition:
    'border-color var(--fw-dur-fast) var(--fw-ease), box-shadow var(--fw-dur-fast) var(--fw-ease)',
  boxSizing: 'border-box',
}

/** Error state: --fw-red border + subtle red ring. */
const INPUT_ERROR_STYLE: React.CSSProperties = {
  borderColor: 'var(--fw-red)',
  boxShadow: '0 0 0 2px rgba(239, 68, 68, 0.2)',
}

/** Disabled overrides. */
const INPUT_DISABLED_STYLE: React.CSSProperties = {
  opacity: 0.5,
  cursor: 'not-allowed',
  pointerEvents: 'none',
}

/**
 * BaseInputTemplate — DS-styled text/number/etc. input for rjsf.
 *
 * Replaces shadcn Tailwind classes with DS --fw-* token inline styles matching
 * the DS Input recipe. The amber focus ring is applied imperatively via
 * onFocus/onBlur so it works without Tailwind focus-visible variant.
 *
 * The real `aria-invalid` DOM attribute is preserved: only "true" when rawErrors
 * is non-empty; absent when valid (ARIA 1.1 §6.6.5).
 */
export default function BaseInputTemplate<
  T = unknown,
  S extends StrictRJSFSchema = RJSFSchema,
  F extends FormContextType = object,
>({
  id,
  htmlName,
  placeholder,
  required,
  readonly,
  disabled,
  type,
  value,
  onChange,
  onChangeOverride,
  onBlur,
  onFocus,
  autofocus,
  options,
  schema,
  rawErrors = [],
  children,
  extraProps,
  registry,
}: BaseInputTemplateProps<T, S, F>) {
  const { ClearButton } = registry.templates.ButtonTemplates
  const inputProps = {
    ...extraProps,
    ...getInputProps<T, S, F>(schema, type, options),
  }

  const _onChange = ({ target: { value: v } }: ChangeEvent<HTMLInputElement>) =>
    onChange(v === '' ? options.emptyValue : (v as T))

  const _onBlur = ({ target }: FocusEvent<HTMLInputElement>) =>
    onBlur(id, target && target.value)

  const _onFocus = ({ target }: FocusEvent<HTMLInputElement>) =>
    onFocus(id, target && target.value)

  const _onClear = useCallback(
    (e: MouseEvent) => {
      e.preventDefault()
      e.stopPropagation()
      onChange(options.emptyValue ?? ('' as T))
    },
    [onChange, options.emptyValue],
  )

  const hasErrors = rawErrors.length > 0

  const computedStyle: React.CSSProperties = {
    ...INPUT_BASE_STYLE,
    ...(hasErrors ? INPUT_ERROR_STYLE : {}),
    ...(disabled ? INPUT_DISABLED_STYLE : {}),
  }

  return (
    <div className="p-0.5">
      {/*
       * DS-styled input: --fw-bg-input inset well, --fw-font-mono, amber focus ring.
       * data-fw-input attribute enables targeted CSS and test assertions.
       */}
      <input
        data-fw-input=""
        id={id}
        name={htmlName || id}
        type={type}
        placeholder={placeholder}
        autoFocus={autofocus}
        required={required}
        disabled={disabled}
        readOnly={readonly}
        style={computedStyle}
        list={schema.examples ? examplesId(id) : undefined}
        {...inputProps}
        value={value || value === 0 ? (value as string | number) : ''}
        onChange={onChangeOverride || _onChange}
        onBlur={(e) => {
          // Restore base border on blur (clear focus ring)
          if (e.currentTarget.style) {
            e.currentTarget.style.borderColor = hasErrors
              ? 'var(--fw-red)'
              : 'var(--fw-border-l)'
            e.currentTarget.style.boxShadow = hasErrors
              ? '0 0 0 2px rgba(239, 68, 68, 0.2)'
              : 'none'
          }
          _onBlur(e)
        }}
        onFocus={(e) => {
          // Apply amber (--fw-accent) focus ring
          if (e.currentTarget.style) {
            e.currentTarget.style.borderColor = hasErrors ? 'var(--fw-red)' : 'var(--fw-accent)'
            e.currentTarget.style.boxShadow = hasErrors
              ? '0 0 0 2px rgba(239, 68, 68, 0.2)'
              : '0 0 0 2px rgba(245, 158, 11, 0.25)'
          }
          _onFocus(e)
        }}
        aria-describedby={ariaDescribedByIds(id, !!schema.examples)}
        // The real `aria-invalid` DOM attribute is required for ARIA 1.1 screen
        // reader support. Only set to "true" when errors exist; omit when valid
        // (per ARIA 1.1 §6.6.5 — invalid state should not be "false" by default).
        {...(hasErrors ? { 'aria-invalid': 'true' as const } : {})}
      />
      {options.allowClearTextInputs && !readonly && !disabled && value && (
        <ClearButton onClick={_onClear} registry={registry} />
      )}
      {children}
      <SchemaExamples id={id} schema={schema} />
    </div>
  )
}
