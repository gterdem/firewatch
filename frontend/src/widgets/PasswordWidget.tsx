/**
 * PasswordWidget — re-skinned to DS Input look (F4, #110).
 *
 * Visual: matches BaseInputTemplate — --fw-bg-input inset well, --fw-font-mono,
 * 1px --fw-border-l border, amber focus ring, --fw-red on error.
 *
 * Security contract (ADR-0006 / EARS ubiquitous) — UNCHANGED:
 *   - Never echoes a stored secret. The server returns null for SecretStr on GET
 *     (config.py _mask_secrets). When formData is null/undefined the widget shows
 *     a "•••• set" placeholder instead of a real value.
 *   - Never logs the value. No console.log / console.error calls touch the value.
 *   - Only sends a new value if the user has typed one.
 *
 * Write-only / empty-but-set behaviour — UNCHANGED:
 *   - null (server-masked) → placeholder "•••• set", onChange(undefined) — omit from PUT.
 *   - user clears → onChange(undefined) — omit from PUT.
 *   - user types → onChange(newValue) normally.
 *
 * Reveal toggle (#498, UT-14) — NEW:
 *   - A keyboard-operable eye button toggles the input between type="password"
 *     and type="text" so the operator can verify a typed value.
 *   - Default: masked (type="password").
 *   - When server-masked (null value, nothing typed): reveal has nothing to show;
 *     the masked placeholder stays; the toggle is present but does not echo the
 *     stored secret (ADR-0006: secret never echoed unless user has typed a new value).
 *   - The toggle button has aria-pressed reflecting current state and an
 *     aria-label that reflects the action ("Show value" / "Hide value").
 *   - The value is NEVER logged (ADR-0006).
 *
 * Description handling (#489, R1) — CHANGED:
 *   - The placeholder no longer falls back to schema.description. A neutral
 *     placeholder is shown instead. The description is routed through the
 *     DescriptionFieldTemplate two-tier disclosure (registered in widgets/registry.ts)
 *     which rjsf renders via its DescriptionFieldTemplate hook.
 *
 * Secret-hygiene clear after save (R9 / issue #497) — NEW:
 *   - SourceConfigForm injects `secretClearNonce` into the uiSchema `ui:options`
 *     for each password field. When this nonce increments (after a successful save),
 *     a useEffect clears localValue and resets reveal state, ensuring the typed
 *     plaintext secret does not persist in component state (ADR-0006 NB-1).
 *   - The Form is NOT remounted — only this widget's local state is reset.
 *
 * rjsf v6 WidgetProps.onChange signature: (value: any, es?, id?) => void
 */

import { useState, useEffect, useCallback, type ChangeEvent, type FocusEvent } from 'react'
import type { WidgetProps } from '@rjsf/utils'
import { ariaDescribedByIds, errorId } from '@rjsf/utils'

/**
 * Placeholder shown when the server has masked a stored secret (null value).
 * Visually communicates "a value is stored but not shown" without echoing it.
 */
const MASKED_PLACEHOLDER = '•••• set — type to replace'

/**
 * Neutral placeholder shown when there is no stored secret and no value typed.
 * Does NOT use schema.description (#489 R1: description routes to DescriptionFieldTemplate).
 */
const NEUTRAL_PLACEHOLDER = 'Enter value'

export default function PasswordWidget({
  id,
  value,
  required,
  disabled,
  readonly,
  onChange,
  onBlur,
  onFocus,
  rawErrors = [],
  fieldPathId,
  options,
}: WidgetProps) {
  /**
   * Whether the server returned null (secret is set but masked).
   * We track this so we can pass onChange(undefined) when the user hasn't typed,
   * keeping the stored secret intact on PUT.
   */
  const isServerMasked = value === null || value === undefined

  /**
   * localValue is what the user is typing in the input.
   * We keep it separate from the rjsf form data so we can detect "user has
   * typed something" vs "still showing the masked placeholder".
   */
  const [localValue, setLocalValue] = useState<string>('')
  const [hasFocus, setHasFocus] = useState(false)

  /**
   * Reveal state — toggles between type="password" (masked) and type="text".
   * Default: false (masked). ADR-0006: value never echoed unless user has typed.
   */
  const [revealed, setRevealed] = useState(false)

  /**
   * NB-1 secret-hygiene clear (ADR-0006, R9 / issue #497).
   *
   * SourceConfigForm injects `secretClearNonce` into the uiSchema ui:options
   * for each password field after a successful save. Because uiSchema is a
   * direct <Form> prop, rjsf re-renders this widget with updated options,
   * which triggers this effect to wipe localValue and reset reveal.
   *
   * This replaces the previous "remount the entire Form" approach (saveNonce key)
   * with a targeted per-widget state reset, preserving scroll and non-secret
   * field state while still guaranteeing the typed plaintext secret is gone.
   *
   * Security guarantee: after this effect fires, localValue is '' and the input
   * returns to the masked-placeholder state. The typed secret no longer exists
   * in any React state reachable from this component.
   */
  const secretClearNonce = typeof options?.secretClearNonce === 'number'
    ? options.secretClearNonce
    : 0
  useEffect(() => {
    // Only fire when secretClearNonce is > 0 (skip the mount run at 0).
    // Every successful save increments it by 1, triggering this effect.
    if (secretClearNonce > 0) {
      // Intentional setState in effect: this effect synchronises PasswordWidget's
      // local input state with an external save event signalled by secretClearNonce.
      // This is the correct React pattern for "reset controlled input state when
      // an external nonce changes" — analogous to using `key` but scoped to this
      // widget's state only (ADR-0006 NB-1, R9 / issue #497).
      // eslint-disable-next-line react-hooks/set-state-in-effect
      setLocalValue('')
      setRevealed(false)
      // ADR-0006: do NOT call onChange here. The parent (SourceConfigForm) has
      // already reloaded formData from the server after the save. Calling onChange
      // here would overwrite the freshly-loaded formData with undefined.
    }
  }, [secretClearNonce])

  const handleChange = useCallback(
    (e: ChangeEvent<HTMLInputElement>) => {
      const typed = e.target.value
      setLocalValue(typed)
      // Only propagate a real value to rjsf; empty → undefined (omit from PUT)
      onChange(typed === '' ? undefined : typed)
    },
    [onChange],
  )

  const handleBlur = useCallback(
    (e: FocusEvent<HTMLInputElement>) => {
      setHasFocus(false)
      onBlur(id, e.target.value || undefined)
    },
    [id, onBlur],
  )

  const handleFocus = useCallback(
    (e: FocusEvent<HTMLInputElement>) => {
      setHasFocus(true)
      onFocus(id, e.target.value || undefined)
    },
    [id, onFocus],
  )

  /**
   * Toggle reveal state.
   * ADR-0006: never log the value under any code path.
   */
  const handleRevealToggle = useCallback(() => {
    setRevealed((prev) => !prev)
  }, [])

  /**
   * Display value logic:
   *   - User is typing → show localValue
   *   - Server-masked, not yet typed → show '' (placeholder text handles it)
   *   - Non-null rjsf value (user typed something) → show that value
   */
  const displayValue = hasFocus || localValue !== ''
    ? localValue
    : isServerMasked
      ? ''
      : String(value ?? '')

  /**
   * Placeholder logic (#489 R1):
   *   - Server-masked and nothing typed → MASKED_PLACEHOLDER
   *   - Otherwise → NEUTRAL_PLACEHOLDER (no longer uses schema.description)
   */
  const placeholder = isServerMasked && !hasFocus && localValue === ''
    ? MASKED_PLACEHOLDER
    : NEUTRAL_PLACEHOLDER

  const hasErrors = rawErrors.length > 0

  /**
   * Effective input type (#498 UT-14):
   *   - "text" when revealed is true AND the user has a typed value to show.
   *     (ADR-0006: when server-masked and nothing typed, reveal has nothing to
   *     show — do NOT echo the stored secret from the server.)
   *   - "password" otherwise (default masked state).
   */
  const hasTypedValue = localValue !== '' || (!isServerMasked && value !== '' && value != null)
  const inputType = revealed && hasTypedValue ? 'text' : 'password'

  /**
   * aria-describedby: include the error element id (from FieldErrorTemplate)
   * when there are errors, so screen readers read both the field description
   * and the error message. errorId() produces the same id used by FieldErrorTemplate.
   */
  const describedBy = hasErrors && fieldPathId
    ? `${ariaDescribedByIds(id)} ${errorId(fieldPathId)}`
    : ariaDescribedByIds(id)

  /**
   * DS Input style — matches BASE_INPUT_STYLE in src/components/ds/forms/Input.tsx.
   * Monospace inset well; amber focus ring applied via onFocus/onBlur handlers.
   * Error state: --fw-red border + subtle red ring.
   * Note: borderWidth/borderStyle/borderColor are set separately (not via the `border`
   * shorthand) so that JSDOM can read `style.borderColor` in tests without shorthand
   * decomposition issues.
   * Right padding expanded to make room for the reveal toggle button.
   */
  const inputStyle: React.CSSProperties = {
    width: '100%',
    background: 'var(--fw-bg-input)',
    borderWidth: 1,
    borderStyle: 'solid',
    borderColor: hasErrors ? 'var(--fw-red)' : 'var(--fw-border-l)',
    borderRadius: 'var(--fw-r-sm)',
    color: 'var(--fw-t1)',
    fontFamily: 'var(--fw-font-mono)',
    fontSize: 'var(--fw-fs-body)',
    padding: '8px 40px 8px 12px',
    outline: 'none',
    transition:
      'border-color var(--fw-dur-fast) var(--fw-ease), box-shadow var(--fw-dur-fast) var(--fw-ease)',
    boxSizing: 'border-box',
    ...(hasErrors ? { boxShadow: '0 0 0 2px rgba(239, 68, 68, 0.2)' } : {}),
    ...(disabled ? { opacity: 0.5, cursor: 'not-allowed', pointerEvents: 'none' as const } : {}),
  }

  const wrapperStyle: React.CSSProperties = {
    position: 'relative',
    display: 'block',
  }

  const toggleButtonStyle: React.CSSProperties = {
    position: 'absolute',
    right: 8,
    top: '50%',
    transform: 'translateY(-50%)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    background: 'none',
    border: 'none',
    padding: 4,
    cursor: disabled || readonly ? 'not-allowed' : 'pointer',
    color: 'var(--fw-t3)',
    opacity: disabled ? 0.5 : 1,
    borderRadius: 'var(--fw-r-sm)',
    lineHeight: 1,
  }

  // Accessible label reflects the current action (what clicking will do)
  const toggleAriaLabel = revealed ? 'Hide value' : 'Show value'

  return (
    <div style={wrapperStyle}>
      <input
        data-fw-input=""
        id={id}
        name={id}
        type={inputType}
        value={displayValue}
        placeholder={placeholder}
        required={required}
        disabled={disabled}
        readOnly={readonly}
        autoComplete="new-password"
        aria-invalid={hasErrors || undefined}
        aria-describedby={describedBy}
        style={inputStyle}
        onChange={handleChange}
        onBlur={(e) => {
          // Restore base border on blur (clear focus ring)
          if (e.currentTarget.style) {
            e.currentTarget.style.borderColor = hasErrors ? 'var(--fw-red)' : 'var(--fw-border-l)'
            e.currentTarget.style.boxShadow = hasErrors
              ? '0 0 0 2px rgba(239, 68, 68, 0.2)'
              : 'none'
          }
          handleBlur(e)
        }}
        onFocus={(e) => {
          // Apply amber (--fw-accent) focus ring
          if (e.currentTarget.style) {
            e.currentTarget.style.borderColor = hasErrors ? 'var(--fw-red)' : 'var(--fw-accent)'
            e.currentTarget.style.boxShadow = hasErrors
              ? '0 0 0 2px rgba(239, 68, 68, 0.2)'
              : '0 0 0 2px rgba(245, 158, 11, 0.25)'
          }
          handleFocus(e)
        }}
      />

      {/*
       * Reveal toggle button (#498, UT-14) — keyboard-operable, always present.
       * aria-pressed reflects whether the field is currently revealed.
       * aria-label reflects the action ("Show value" / "Hide value").
       * ADR-0006: clicking this never logs or echoes the stored server secret.
       */}
      <button
        type="button"
        aria-pressed={revealed}
        aria-label={toggleAriaLabel}
        data-fw-reveal-toggle=""
        style={toggleButtonStyle}
        disabled={disabled || readonly}
        onClick={handleRevealToggle}
        tabIndex={0}
      >
        {revealed ? (
          /* Eye-slash icon — indicates field is currently revealed */
          <svg
            aria-hidden="true"
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94" />
            <path d="M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19" />
            <line x1="1" y1="1" x2="23" y2="23" />
          </svg>
        ) : (
          /* Eye icon — indicates field is currently masked */
          <svg
            aria-hidden="true"
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          >
            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
            <circle cx="12" cy="12" r="3" />
          </svg>
        )}
      </button>
    </div>
  )
}
