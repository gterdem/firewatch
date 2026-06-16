/**
 * SourceConfigForm — the rjsf config form for one installed source type.
 *
 * ADR-0010 / ADR-0028: The config form is generated entirely from the plugin's
 * JSON Schema returned by the discovery endpoint. Zero per-source code for the
 * config form itself.
 *
 * Behaviour:
 *   - Loads existing config via GET /config/sources/{type_key} on mount.
 *   - Renders a rjsf Form using @rjsf/shadcn theme + project-local widget registry.
 *   - On submit: strips null-valued keys (server-masked secrets not re-typed) and
 *     PUTs the validated payload. Invalid form is blocked client-side by rjsf/AJV.
 *   - Displays server-side 422 validation errors (input-stripped by server, ADR-0006).
 *     Field-scoped errors (Pydantic loc resolves to a schema property) are shown
 *     inline under their field via rjsf `extraErrors` (R8 / issue #495).
 *     Non-field errors are shown as a card-level summary.
 *   - SecretStr fields rendered via PasswordWidget (masked, never echoed/logged).
 *   - if/then/else conditional reveal driven by @rjsf/validator-ajv8 (ADR-0028 D5).
 *   - After a successful save, `secretClearNonce` is incremented in `formContext`
 *     so each PasswordWidget resets its localValue individually (NB-1 secret hygiene).
 *     The Form is NOT remounted — scroll and non-secret field state are preserved
 *     (R9 / issue #497). Prior approach used key=saveNonce to remount the entire Form.
 *
 * Feedback rendering (R9 / issue #497):
 *   - When onServerErrors callback is provided, the parent owns error/success display
 *     (DS SourceCard shell error/success props).
 *   - When no callbacks are provided (standalone use), this component renders a
 *     transient DS Toast on success and a role="alert" on error.
 *
 * Renamed from SourceCard.tsx in P5 (#116): the DS SourceCard shell (F3) now wraps
 * this form as its body. This component is the rjsf form body only — no card chrome.
 *
 * Payload helpers (stripNullValues, buildPutPayload) live in schema/configPayload.ts
 * to satisfy react-refresh/only-export-components.
 */

import { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import Form from '@rjsf/shadcn'
import type { IChangeEvent } from '@rjsf/core'
import validator from '@rjsf/validator-ajv8'
import type { ErrorSchema, RJSFSchema, UiSchema } from '@rjsf/utils'
import type { SourceTypeEntry } from '../schema/types'
import { buildUiSchema } from '../schema/uiSchema'
import { stripNullValues, buildPutPayload } from '../schema/configPayload'
import { normalizeConfigSchema } from '../schema/schemaTransform'
import { widgetRegistry, fieldRegistry, templateOverrides } from '../widgets/registry'
import { fetchSourceConfig, putSourceConfig, ApiError } from '../api/client'
import { mapPydanticErrors } from '../schema/pydanticErrors'
import { Toast } from './ds'

/**
 * Merge `secretClearNonce` into the `ui:options` of every password-widget field
 * in a uiSchema. When the nonce changes, PasswordWidget's useEffect fires and
 * clears localValue — the targeted secret-hygiene reset (NB-1 / ADR-0006 / R9 #497).
 *
 * We only mutate entries that have a `ui:widget` or `ui:field` that deals with
 * secrets (PasswordWidget / NullablePasswordField). Other entries are left alone.
 *
 * Returns a new uiSchema object (shallow copy + per-field shallow copy for
 * modified entries) so React detects the change and re-renders the Form.
 */
function injectSecretClearNonce(uiSchema: UiSchema, nonce: number): UiSchema {
  if (nonce === 0) return uiSchema   // nothing to inject on initial render
  const result: UiSchema = { ...uiSchema }
  for (const [key, entry] of Object.entries(uiSchema)) {
    if (key.startsWith('ui:') || typeof entry !== 'object' || entry === null) continue
    const fieldEntry = entry as Record<string, unknown>
    const isPasswordField =
      fieldEntry['ui:widget'] === 'PasswordWidget' ||
      fieldEntry['ui:field'] === 'NullablePasswordField'
    if (isPasswordField) {
      result[key] = {
        ...fieldEntry,
        'ui:options': {
          ...(typeof fieldEntry['ui:options'] === 'object' && fieldEntry['ui:options'] !== null
            ? (fieldEntry['ui:options'] as Record<string, unknown>)
            : {}),
          secretClearNonce: nonce,
        },
      }
    }
  }
  return result
}

/** Duration (ms) the success toast is visible before auto-dismissing. */
const TOAST_DISMISS_MS = 3000

interface SourceConfigFormProps {
  source: SourceTypeEntry
  /** Called after each successful save (allows parent to refresh status). */
  onSaved?: () => void
  /** If provided, parent owns error/success display — this component skips its own alert. */
  onServerErrors?: (errors: string | null) => void
}

type SaveStatus = 'idle' | 'loading' | 'saved' | 'error'

export default function SourceConfigForm({
  source,
  onSaved,
  onServerErrors,
}: SourceConfigFormProps) {
  const [formData, setFormData] = useState<Record<string, unknown>>({})
  const [loadError, setLoadError] = useState<string | null>(null)
  const [saveStatus, setSaveStatus] = useState<SaveStatus>('idle')
  const [serverErrors, setServerErrors] = useState<string | null>(null)
  /**
   * Field-scoped 422 errors from the server, keyed by field name.
   * Passed to rjsf as `extraErrors` so each message renders inline under
   * its field rather than in a card-level blob (R8 / issue #495).
   */
  const [fieldExtraErrors, setFieldExtraErrors] = useState<ErrorSchema>({})

  /**
   * NB-1 secret-hygiene nonce (ADR-0006, R9 / issue #497).
   *
   * Replaces the previous `saveNonce` / `key={saveNonce}` approach that remounted
   * the entire rjsf Form (causing a visible flash and scroll reset) after every save.
   *
   * Instead: this nonce is passed to rjsf via `formContext.secretClearNonce`.
   * Each PasswordWidget watches this value in a useEffect and resets its
   * `localValue` to '' when it changes — clearing the typed secret without
   * remounting the Form, preserving scroll and non-secret field state.
   *
   * Security guarantee: incrementing this nonce causes every PasswordWidget
   * to discard its in-memory typed value. The typed secret does not survive
   * a successful save in any React state reachable from this component.
   */
  const [secretClearNonce, setSecretClearNonce] = useState(0)

  /**
   * Ref for the toast dismiss timer so it can be cleared if the component
   * unmounts before the timer fires.
   */
  const toastTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (toastTimerRef.current !== null) {
        clearTimeout(toastTimerRef.current)
      }
    }
  }, [])

  // R4 fix (D3): normalizeConfigSchema collapses anyOf[{type:"string"},{type:"null"}]
  // into type:["string","null"] so rjsf does not render a discriminator dropdown for
  // nullable plain strings (e.g. Suricata remote_user: Optional[str]).
  // Nullable password fields are left intact — those are handled by NullablePasswordField.
  //
  // Memoized (#523): source.config_schema is stable per mounted card (discovery API payload
  // does not change during a session), so normalizedSchema and baseUiSchema compute exactly
  // once per mounted card. Memoizing them allows uiSchema below to declare all its deps
  // properly — no eslint-disable needed (#523 uiSchema-memo follow-up).
  const normalizedSchema = useMemo(
    () => normalizeConfigSchema(source.config_schema),
    [source.config_schema],
  )
  const baseUiSchema = useMemo(
    () => buildUiSchema(normalizedSchema),
    [normalizedSchema],
  )
  const schema = normalizedSchema as RJSFSchema

  /**
   * Effective uiSchema — the base uiSchema with secretClearNonce merged into
   * password-field entries (R9 / issue #497).
   *
   * When secretClearNonce > 0 (after a save), each PasswordWidget receives an
   * updated `options.secretClearNonce` through the rjsf options pipeline, which
   * triggers its useEffect to clear localValue (typed secret gone, NB-1 / ADR-0006).
   * The Form is NOT remounted — only the widget-level local state is reset.
   *
   * useMemo: recomputes only when baseUiSchema identity or nonce changes.
   * baseUiSchema is stable between renders (computed from the fixed source.config_schema);
   * secretClearNonce changes only on successful save.
   * All deps are now declared explicitly — no eslint-disable needed (#523).
   */
  const uiSchema = useMemo(
    () => injectSecretClearNonce(baseUiSchema, secretClearNonce),
    [baseUiSchema, secretClearNonce],
  )

  // Load existing config on mount
  useEffect(() => {
    let cancelled = false
    fetchSourceConfig(source.type_key)
      .then((data) => {
        if (!cancelled) {
          // Strip null values: server masks SecretStr fields as null.
          // rjsf/AJV validates formData on render; null in a type:string field
          // would fail validation. Stripping null → undefined lets rjsf use the
          // schema default or leave the field empty (PasswordWidget shows "•••• set").
          setFormData(stripNullValues(data))
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setLoadError(
            err instanceof ApiError
              ? `Failed to load config: ${err.status}`
              : 'Failed to load config',
          )
        }
      })
    return () => {
      cancelled = true
    }
  }, [source.type_key])

  const handleChange = useCallback(({ formData: next }: IChangeEvent) => {
    setFormData((next as Record<string, unknown>) ?? {})
  }, [])

  const handleSubmit = useCallback(
    async ({ formData: submitted }: IChangeEvent) => {
      if (!submitted) return
      setSaveStatus('loading')
      setServerErrors(null)
      setFieldExtraErrors({})
      onServerErrors?.(null)
      try {
        const payload = buildPutPayload(submitted as Record<string, unknown>, uiSchema)
        await putSourceConfig(source.type_key, payload)
        setSaveStatus('saved')
        // Reload so masked secrets show "•••• set" again (server masks them as null)
        const fresh = await fetchSourceConfig(source.type_key)
        setFormData(stripNullValues(fresh))
        // NB-1 secret hygiene (ADR-0006, R9 #497): increment secretClearNonce.
        // Each PasswordWidget's useEffect fires, wiping its localValue so the typed
        // plaintext secret does not persist in component state after a save.
        // The Form itself is NOT remounted — scroll and non-secret state are preserved.
        setSecretClearNonce((n) => n + 1)
        // Auto-dismiss the success toast after TOAST_DISMISS_MS
        if (toastTimerRef.current !== null) clearTimeout(toastTimerRef.current)
        toastTimerRef.current = setTimeout(() => setSaveStatus('idle'), TOAST_DISMISS_MS)
        onSaved?.()
      } catch (err: unknown) {
        setSaveStatus('error')
        if (err instanceof ApiError) {
          // Surface server validation errors (422). Server strips "input" field
          // from Pydantic errors, so we can safely display them (ADR-0006).
          //
          // R8 (issue #495): map field-scoped Pydantic errors to rjsf extraErrors
          // so they render inline under the correct field. Non-field errors remain
          // as a card-level summary (formErrors). No per-source branching.
          const detail = err.detail
          if (typeof detail === 'object' && detail !== null && 'detail' in detail) {
            const detailArr = (detail as { detail: unknown }).detail
            if (Array.isArray(detailArr)) {
              const { fieldErrors, formErrors } = mapPydanticErrors(
                detailArr,
                source.config_schema,
              )
              setFieldExtraErrors(fieldErrors)
              const formErrText = formErrors.length > 0 ? formErrors.join('; ') : null
              setServerErrors(formErrText)
              onServerErrors?.(formErrText)
            } else {
              const errText = String((detail as Record<string, unknown>).detail)
              setServerErrors(errText)
              onServerErrors?.(errText)
            }
          } else {
            const errText = `Save failed (${err.status})`
            setServerErrors(errText)
            onServerErrors?.(errText)
          }
        } else {
          const errText = 'Save failed'
          setServerErrors(errText)
          onServerErrors?.(errText)
        }
      }
    },
    [source.type_key, source.config_schema, uiSchema, onSaved, onServerErrors],
  )

  // When parent provides callbacks, it owns the feedback display.
  const parentOwnsErrors = onServerErrors !== undefined

  return (
    <div
      data-testid={`source-config-form-${source.type_key}`}
      style={{ position: 'relative' }}
    >
      {/* Load error — always shown here (not delegated to parent) */}
      {loadError && (
        <p
          role="alert"
          style={{ fontSize: 'var(--fw-fs-sm)', color: 'var(--fw-red)', marginBottom: 8 }}
        >
          {loadError}
        </p>
      )}

      {/* rjsf form — schema-driven, no per-source code.
          uiSchema (effectiveUiSchema): after each successful save, secretClearNonce
          is injected into the ui:options of each password field so PasswordWidget's
          useEffect fires to clear localValue (NB-1 secret hygiene, ADR-0006, R9 #497).
          The Form is NOT keyed by a nonce — no full remount, scroll preserved.
          noHtml5Validate: disables browser native HTML5 constraint validation
          so rjsf/AJV surfaces errors via aria-invalid + role=alert elements (#67 a11y).
          extraErrors: field-scoped 422 messages from the server (R8 / issue #495). */}
      <Form
        schema={schema}
        uiSchema={uiSchema}
        formData={formData}
        validator={validator}
        widgets={widgetRegistry}
        fields={fieldRegistry}
        templates={templateOverrides}
        noHtml5Validate
        extraErrors={fieldExtraErrors}
        onChange={handleChange}
        onSubmit={handleSubmit}
      />

      {/* Card-level error summary — non-field 422 errors and non-422 failures.
          Only shown when no field-only errors cover the full error surface,
          and only when this component owns error display (parent absent). */}
      {!parentOwnsErrors && serverErrors && (
        <p
          role="alert"
          style={{ fontSize: 'var(--fw-fs-sm)', color: 'var(--fw-red)', marginTop: 8 }}
        >
          {serverErrors}
        </p>
      )}

      {/* Success toast (R9 / issue #497) — transient DS Toast, auto-dismisses.
          Replaces the previous static "Settings saved." text row.
          Only shown when this component owns feedback display (parent absent). */}
      {!parentOwnsErrors && saveStatus === 'saved' && (
        <div
          data-testid="save-success-toast"
          style={{
            position: 'absolute',
            top: 0,
            right: 0,
            zIndex: 10,
          }}
        >
          <Toast tone="ok">Settings saved.</Toast>
        </div>
      )}
    </div>
  )
}
