/**
 * NullablePasswordField — custom rjsf field for SecretStr | None (anyOf) fields.
 *
 * Problem: Pydantic `SecretStr | None` emits a JSON Schema of the form:
 *   anyOf: [{type: "string", format: "password", writeOnly: true}, {type: "null"}]
 *
 * rjsf's default anyOf handling (AnyOfField / MultiSchemaField) renders a type
 * selector dropdown first, requiring the user to explicitly choose "string" before
 * the password input appears. This is poor UX — the user expects a password field.
 *
 * Solution: This custom field is registered as 'NullablePasswordField' in the field
 * registry and referenced via `'ui:field': 'NullablePasswordField'` and
 * `'ui:fieldReplacesAnyOrOneOf': true` in the uiSchema for such fields.
 * `ui:fieldReplacesAnyOrOneOf: true` tells rjsf to use this field directly instead
 * of the AnyOfField selector, bypassing the type selector entirely.
 *
 * Rendering: delegates entirely to PasswordWidget, which handles:
 *   - Masked placeholder when server returns null (SecretStr masked on GET)
 *   - onChange(undefined) when value is empty (omit from PUT payload)
 *   - aria-invalid + error linking for a11y
 *
 * Label rendering (#695): rjsf's getDisplayLabel() returns false when ui:field is
 * set, so FieldTemplate skips the label for this field. NullablePasswordField owns
 * the label rendering here, using the same DS token styles as Input.tsx.
 *
 * Security: does NOT weaken any existing SecretStr masking. The field simply skips
 * the anyOf selector; the PasswordWidget's masking contract is unchanged.
 *
 * ADR-0028 / ADR-0010: schema-driven, zero per-source code.
 */

import type { FieldProps, UIOptionsType } from '@rjsf/utils'
import PasswordWidget from './PasswordWidget'

/**
 * DS label style — matches the <label> element in src/components/ds/forms/Input.tsx.
 * Applied to every NullablePasswordField label so secret fields look identical to
 * non-secret fields.
 */
const LABEL_STYLE: React.CSSProperties = {
  display: 'block',
  fontSize: 'var(--fw-fs-sm)',
  color: 'var(--fw-t2)',
  marginBottom: 4,
  fontWeight: 'var(--fw-fw-medium)',
  fontFamily: 'var(--fw-font-ui)',
}

/**
 * NullablePasswordField — renders a label + PasswordWidget directly for anyOf
 * nullable secret fields, bypassing the rjsf AnyOfField type-selector dropdown.
 *
 * Receives FieldProps (from rjsf's field pipeline) and adapts them to
 * WidgetProps expected by PasswordWidget. The adaptation is straightforward
 * because PasswordWidget only uses a subset of the props that FieldProps provides.
 *
 * The label is rendered here (not inside PasswordWidget) because this is a
 * custom *field*, not a widget: rjsf suppresses displayLabel in FieldTemplate
 * whenever ui:field is set, so no outer label is produced. Rendering the label
 * here restores the title+description UX that non-secret fields receive via
 * FieldTemplate. (#695)
 */
export default function NullablePasswordField({
  id,
  name,
  formData,
  schema,
  uiSchema,
  required,
  disabled,
  readonly,
  autofocus,
  rawErrors = [],
  errorSchema,
  onChange,
  onBlur,
  onFocus,
  registry,
  fieldPathId,
}: FieldProps) {
  /**
   * Adapt FieldProps.onChange to WidgetProps.onChange signature.
   * WidgetProps.onChange: (value: any, es?, id?) => void
   * FieldProps.onChange: (newValue: T | undefined, path, es?, id?) => void
   *
   * IMPORTANT: pass fieldPathId.path (e.g. ['remote_key']), NOT an empty array [].
   * rjsf v6 Form.onChange treats path=[] as the root path and replaces the ENTIRE
   * formData with `value`, turning the root object into a string (regression #85/D2).
   * Using fieldPathId.path tells the Form to update only the specific key in the
   * parent object formData, which is the correct semantic for a leaf property field.
   */
  function handleWidgetChange(value: unknown) {
    // When the user clears the field, PasswordWidget passes undefined.
    // Pass through to FieldProps.onChange so the key is omitted from the PUT payload.
    onChange(value as never, fieldPathId.path, errorSchema)
  }

  /**
   * Extract ui:options from the field uiSchema and pass them to PasswordWidget.
   * This propagates secretClearNonce (injected by SourceConfigForm for R9/#497)
   * so PasswordWidget's useEffect can clear localValue after a successful save.
   * If no ui:options are present, fall back to an empty object.
   */
  const resolvedOptions: UIOptionsType =
    uiSchema && typeof uiSchema['ui:options'] === 'object' && uiSchema['ui:options'] !== null
      ? (uiSchema['ui:options'] as UIOptionsType)
      : {}

  const widgetId = id ?? `root_${name}`
  const fieldLabel = String(schema.title ?? name)

  return (
    <div>
      {/*
       * Label rendered here because rjsf suppresses FieldTemplate's label when
       * ui:field is present (getDisplayLabel returns false). Mirrors the DS
       * Input.tsx label style so secret fields look identical to non-secret fields.
       * htmlFor links to the input id so clicking the label focuses the input.
       * (#695)
       */}
      <label htmlFor={widgetId} style={LABEL_STYLE} data-fw-field-label="">
        {fieldLabel}
        {required && ' *'}
      </label>

      <PasswordWidget
        id={widgetId}
        name={name}
        value={formData}
        label={fieldLabel}
        hideLabel={true}
        hideError={false}
        required={required ?? false}
        disabled={disabled ?? false}
        readonly={readonly ?? false}
        autofocus={autofocus ?? false}
        schema={schema}
        uiSchema={uiSchema ?? {}}
        options={resolvedOptions}
        formContext={registry.formContext}
        registry={registry}
        rawErrors={rawErrors}
        fieldPathId={fieldPathId}
        onChange={handleWidgetChange}
        onBlur={onBlur}
        onFocus={onFocus}
      />
    </div>
  )
}
