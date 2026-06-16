/**
 * ObjectFieldTemplate — required-first grouping with collapsed Advanced section
 * (R2, #490).
 *
 * Partitions a source's config fields into:
 *   - Essential group: always visible (required fields + fields with no/null/"" default).
 *   - Advanced group: collapsed under a keyboard-operable <details> disclosure
 *     (writeOnly/secret fields + fields with a meaningful non-null default).
 *
 * The partition is derived ENTIRELY from JSON Schema metadata
 * (`required`, `default`, `writeOnly`) — no field-name allowlists, no
 * per-source branching (ADR-0010, ADR-0028).
 *
 * ui:order: rjsf applies ui:order to the `properties` array before this
 * template is called, so relative order within each group is preserved
 * automatically without extra work here.
 *
 * Accessibility:
 *   - Uses native <details>/<summary>; browsers expose these as
 *     role="group" + disclosure button natively (keyboard-operable).
 *   - WCAG 1.4.13: keyboard-operable without custom JS.
 *   - Expanding the Advanced group grows the card height with no inner
 *     scroll region (ADR-0043 D3).
 *
 * Composition:
 *   - The DescriptionFieldTemplate (R1, #489) is NOT called directly here;
 *     rjsf calls it automatically for each individual field via the registry.
 *   - Title and description for the top-level object are rendered via the
 *     registry templates (accessed from props.registry.templates).
 *
 * ADR-0028: registered in widgets/registry.ts as ObjectFieldTemplate.
 */

import { canExpand, buttonId, titleId, descriptionId, getUiOptions } from '@rjsf/utils'
import type {
  ObjectFieldTemplateProps,
  ObjectFieldTemplatePropertyType,
} from '@rjsf/utils'

import { partitionFields } from './partitionFields'

// ---------------------------------------------------------------------------
// Style constants — DS token-based
// ---------------------------------------------------------------------------

const FIELDS_STACK: React.CSSProperties = {
  display: 'flex',
  flexDirection: 'column',
  gap: 8,
}

const ADVANCED_DETAILS: React.CSSProperties = {
  marginTop: 4,
}

const ADVANCED_SUMMARY: React.CSSProperties = {
  cursor: 'pointer',
  userSelect: 'none',
  listStyle: 'none',
  display: 'inline-flex',
  alignItems: 'center',
  gap: 4,
  fontSize: 'var(--fw-fs-sm)',
  fontWeight: 'var(--fw-fw-medium)',
  color: 'var(--fw-accent)',
  padding: '4px 0',
}

const ADVANCED_CONTENT: React.CSSProperties = {
  display: 'flex',
  flexDirection: 'column',
  gap: 8,
  marginTop: 8,
  paddingTop: 8,
  borderTop: '1px solid var(--fw-border)',
}

const ADVANCED_LABEL: React.CSSProperties = {
  fontSize: 'var(--fw-fs-xs)',
  fontWeight: 'var(--fw-fw-medium)',
  color: 'var(--fw-t3)',
  textTransform: 'uppercase',
  letterSpacing: '0.05em',
  marginBottom: 4,
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

/**
 * ObjectFieldTemplate — generic grouped layout for all source config objects.
 *
 * Applies the Essential/Advanced split only at the top-level object
 * (fieldPathId.path.length === 0). Nested objects (e.g. rjsf sub-schemas)
 * render flat using the same shadcn-compatible output structure to avoid
 * double-grouping.
 */
export default function ObjectFieldTemplate({
  title,
  description,
  properties,
  required,
  uiSchema,
  fieldPathId,
  schema,
  formData,
  onAddProperty,
  disabled,
  readonly,
  registry,
}: ObjectFieldTemplateProps) {
  const uiOptions = getUiOptions(uiSchema)

  // Access templates directly from registry (stable references; not new components).
  // Note: registry.templates is an object of stable component references, not factories.
  const { TitleFieldTemplate, DescriptionFieldTemplate } = registry.templates
  const TitleTemplate =
    (uiOptions.TitleFieldTemplate as typeof TitleFieldTemplate | undefined) ?? TitleFieldTemplate
  const DescTemplate =
    (uiOptions.DescriptionFieldTemplate as typeof DescriptionFieldTemplate | undefined) ??
    DescriptionFieldTemplate

  const {
    ButtonTemplates: { AddButton },
  } = registry.templates

  const showOptionalDataControlInTitle = !readonly && !disabled

  // Only apply Essential/Advanced grouping at the top-level object.
  //
  // Bug fixed (#526): the previous `!title` heuristic failed for real plugin
  // schemas because rjsf passes `schema.title` ("AzureWAFConfig") as the
  // `title` prop to ObjectFieldTemplate for the root object — not an empty
  // string.  `!title` therefore evaluated to false, making every object render
  // flat with no Advanced disclosure.
  //
  // The correct signal is `fieldPathId.path.length === 0`: rjsf assigns an
  // empty path array to the root form object and non-empty paths to nested
  // objects (e.g. sub-schemas, if/then/else-revealed properties).  This is
  // stable regardless of whether the schema sets a `title`.
  const isTopLevel = fieldPathId.path.length === 0

  const orderedNames = properties.map((p: ObjectFieldTemplatePropertyType) => p.name)
  const { essential, advanced } = isTopLevel
    ? partitionFields(orderedNames, schema)
    : { essential: orderedNames.map((n) => ({ name: n, hidden: false })), advanced: [] }

  // Build lookup: name → property element.
  const propByName = new Map<string, ObjectFieldTemplatePropertyType>(
    properties.map((p: ObjectFieldTemplatePropertyType) => [p.name, p]),
  )

  // Render non-hidden field slots.
  function renderSlots(slots: Array<{ name: string; hidden: boolean }>) {
    return slots.map((slot) => {
      const prop = propByName.get(slot.name)
      if (!prop || prop.hidden) return null
      return (
        <div key={prop.name} className="flex w-full">
          {prop.content}
        </div>
      )
    })
  }

  const essentialNodes = renderSlots(essential)
  const advancedNodes = renderSlots(advanced)
  const hasAdvanced = advancedNodes.some((n) => n !== null)

  return (
    <>
      {title && (
        <TitleTemplate
          id={titleId(fieldPathId)}
          title={title}
          required={required}
          schema={schema}
          uiSchema={uiSchema}
          registry={registry}
          optionalDataControl={showOptionalDataControlInTitle ? undefined : undefined}
        />
      )}
      {description && (
        <DescTemplate
          id={descriptionId(fieldPathId)}
          description={description}
          schema={schema}
          uiSchema={uiSchema}
          registry={registry}
        />
      )}

      <div style={FIELDS_STACK} data-fw-object-fields="">
        {/* Essential group — always visible */}
        {essentialNodes}

        {/* Advanced group — collapsed by default */}
        {hasAdvanced && (
          <details style={ADVANCED_DETAILS} data-fw-advanced-group="">
            {/* #573: chevron SVG gives a visible expand/collapse affordance.
                `details[open] .fw-chevron` rotates 90° via CSS details[open]
                selector — no JS needed (native <details> toggles the attribute). */}
            <summary style={ADVANCED_SUMMARY} data-fw-advanced-toggle="">
              <svg
                className="fw-chevron"
                aria-hidden="true"
                width="12"
                height="12"
                viewBox="0 0 12 12"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
                style={{
                  transition: 'transform 0.15s ease',
                  flexShrink: 0,
                }}
              >
                <polyline points="3 4.5 6 7.5 9 4.5" />
              </svg>
              Advanced / Optional
            </summary>
            <div style={ADVANCED_CONTENT} data-fw-advanced-content="">
              <span style={ADVANCED_LABEL}>Advanced settings</span>
              {advancedNodes}
            </div>
          </details>
        )}

        {/* Add-property button for schemas with additionalProperties */}
        {canExpand(schema, uiSchema, formData) && (
          <div className="mt-2 flex justify-end">
            <AddButton
              id={buttonId(fieldPathId, 'add')}
              onClick={onAddProperty}
              disabled={disabled || readonly}
              className="rjsf-object-property-expand"
              uiSchema={uiSchema}
              registry={registry}
            />
          </div>
        )}
      </div>
    </>
  )
}
