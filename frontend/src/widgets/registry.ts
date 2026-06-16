/**
 * Project-local widget, field, and template override registry (F4, #110).
 *
 * ADR-0028 D4: The official @rjsf/shadcn theme is the base; this thin registry
 * layers DS-re-skinned overrides on top via widgets/fields/templates props.
 * The registry is the single seam — if the theme changes, only this file and
 * widget implementations change, not the card/form code.
 *
 * Currently registered:
 *   - PasswordWidget: DS-styled masked input for SecretStr / writeOnly fields.
 *     Security: never echoes/logs secrets (ADR-0006).
 *   - SelectWidget: DS-styled native <select> for enum fields. Replaces shadcn's
 *     FancySelect (Combobox overlay) with a native select on the --fw-* inset well.
 *   - NullablePasswordField: bypasses the anyOf type-selector for SecretStr | None
 *     fields — presents the password input directly.
 *   - FieldErrorTemplate: role="alert" + aria-live + DS --fw-red error text.
 *   - BaseInputTemplate: DS-styled text/number input; adds real aria-invalid DOM
 *     attribute when rawErrors is non-empty (ARIA 1.1 §6.6.5, #85/D1 a11y fix).
 *   - SubmitButton: renders "Save" instead of rjsf default "Submit" (MF-6, F10).
 *     Uses DS Button variant="primary" for consistent amber CTA styling.
 *   - DescriptionFieldTemplate: two-tier field help (#489, R1). Renders the field's
 *     description as a single clamped lead sentence with a keyboard-operable "Details"
 *     disclosure (native <details>) that expands the full prose. No per-source code —
 *     driven entirely by schema.description (ADR-0010, ADR-0028).
 *   - ObjectFieldTemplate: Essential/Advanced field grouping (#490, R2). Partitions
 *     fields into an always-visible Essential group and a collapsed Advanced/Optional
 *     disclosure. Partition driven entirely by schema metadata (required, default,
 *     writeOnly) — no field-name allowlists, no per-source branching.
 */

import type { RegistryWidgetsType, RegistryFieldsType } from '@rjsf/utils'
import PasswordWidget from './PasswordWidget'
import SelectWidget from './SelectWidget'
import NullablePasswordField from './NullablePasswordField'
import FieldErrorTemplate from './FieldErrorTemplate'
import BaseInputTemplate from './BaseInputTemplate'
import SubmitButton from './SubmitButton'
import DescriptionFieldTemplate from './DescriptionFieldTemplate'
import ObjectFieldTemplate from './ObjectFieldTemplate'

/**
 * Widget overrides to pass as `widgets={widgetRegistry}` to the rjsf Form.
 *   - PasswordWidget: ui:widget name matches buildUiSchema() output.
 *   - SelectWidget: overrides the default FancySelect with a DS-styled native select.
 */
export const widgetRegistry: RegistryWidgetsType = {
  PasswordWidget,
  SelectWidget,
}

/**
 * Custom field overrides to pass as `fields={fieldRegistry}` to the rjsf Form.
 * NullablePasswordField bypasses the anyOf type selector for SecretStr | None fields.
 */
export const fieldRegistry: RegistryFieldsType = {
  NullablePasswordField,
}

/**
 * Template overrides to pass as `templates={templateOverrides}` to the rjsf Form.
 * FieldErrorTemplate adds role="alert" + aria-live to validation error containers.
 * BaseInputTemplate adds the real `aria-invalid` DOM attribute on invalid inputs.
 * DescriptionFieldTemplate renders field descriptions as a clamped one-line lead
 *   with a keyboard-operable "Details" disclosure for the full prose (#489, R1).
 * SubmitButton renders "Save" instead of rjsf default "Submit" (MF-6, F10).
 *
 * Note: the rjsf Form.templates prop type is:
 *   Partial<Omit<TemplatesType, 'ButtonTemplates'>> & {
 *     ButtonTemplates?: Partial<TemplatesType['ButtonTemplates']>;
 *   }
 * which permits a partial ButtonTemplates override — only SubmitButton is overridden here;
 * the other button templates (AddButton, CopyButton, etc.) remain at shadcn defaults.
 */
export const templateOverrides = {
  FieldErrorTemplate,
  BaseInputTemplate,
  DescriptionFieldTemplate,
  ObjectFieldTemplate,
  ButtonTemplates: { SubmitButton },
} as const
