/**
 * JSON Schema → rjsf uiSchema adaptation.
 *
 * Derives a rjsf uiSchema from a plugin's config_schema, handling:
 *   - SecretStr / writeOnly / format:password → "password" widget (PasswordWidget)
 *   - SecretStr | None (anyOf with null branch) → NullablePasswordField (#67)
 *     bypasses the anyOf type-selector so the user sees the password input directly.
 *
 * NOTE (R4 fix, #195 D3): nullable plain strings (Optional[str]) are handled at the
 * SCHEMA level via normalizeConfigSchema() in schemaTransform.ts — which collapses
 * anyOf:[{type:"string"},{type:"null"}] into type:["string","null"] before rjsf sees
 * it.  No uiSchema override is needed for that case.
 * buildUiSchema() is always called with the already-normalized schema.
 *
 * ADR-0028 D4: the PasswordWidget is registered in the project-local
 * override registry (src/widgets/registry.ts) and named here via ui:widget.
 *
 * ADR-0028 D5: if/then/else conditional reveal is handled entirely by
 * @rjsf/validator-ajv8 (AJV 2020-12) at render time — no uiSchema changes
 * needed; rjsf drives field visibility from the schema itself.
 */

import type { UiSchema } from '@rjsf/utils'

/** The widget name used for non-nullable secret / password fields. */
const PASSWORD_WIDGET = 'PasswordWidget'

/** The custom field name for nullable secret fields (SecretStr | None). */
const NULLABLE_PASSWORD_FIELD = 'NullablePasswordField'

/**
 * Detect whether a property node is a nullable secret:
 * anyOf/oneOf that has BOTH a password-like branch AND a null branch.
 *
 * Pydantic `SecretStr | None` → anyOf[{type:string, format:password, writeOnly:true}, {type:null}]
 *
 * Returns true when we can confirm the field is nullable + secret so we can
 * use NullablePasswordField (which bypasses the anyOf type-selector) rather
 * than a plain PasswordWidget.
 */
function isNullablePasswordField(prop: Record<string, unknown>): boolean {
  for (const key of ['anyOf', 'oneOf'] as const) {
    const branches = prop[key]
    if (!Array.isArray(branches)) continue
    const typedBranches = branches as Record<string, unknown>[]
    const hasPasswordBranch = typedBranches.some(
      (b) => b['format'] === 'password' || b['writeOnly'] === true,
    )
    const hasNullBranch = typedBranches.some((b) => b['type'] === 'null')
    if (hasPasswordBranch && hasNullBranch) return true
  }
  return false
}

/**
 * Detect whether a JSON Schema property node represents a secret field
 * that should be rendered as a masked password widget.
 *
 * Matches:
 *   - format: "password"  (explicit)
 *   - writeOnly: true     (Pydantic SecretStr emits this)
 *   - type: "string" with title containing "key" / "secret" / "password" / "token"
 *     (heuristic fallback for plugins that do not set format/writeOnly)
 *
 * Note: anyOf/oneOf password fields (Pydantic SecretStr | None) are handled
 * separately by isNullablePasswordField() and mapped to NullablePasswordField,
 * not this function.
 */
function isSimplePasswordField(prop: Record<string, unknown>): boolean {
  if (prop['format'] === 'password') return true
  if (prop['writeOnly'] === true) return true
  // Heuristic: title-based fallback (last resort, not the primary signal)
  const title = String(prop['title'] ?? '').toLowerCase()
  return /\b(key|secret|password|token)\b/.test(title) && prop['type'] === 'string'
}

/**
 * Collect all properties from a JSON Schema including those inside
 * allOf / anyOf / oneOf / if/then/else branches.
 * Returns a flat map: propertyName → property schema dict.
 *
 * We scan nested branches so that properties revealed via if/then/else
 * (ADR-0028 D5) also get the correct widget when they appear.
 */
function collectProperties(
  schema: Record<string, unknown>,
): Map<string, Record<string, unknown>> {
  const result = new Map<string, Record<string, unknown>>()

  function walk(node: Record<string, unknown>): void {
    const props = node['properties'] as Record<string, Record<string, unknown>> | undefined
    if (props) {
      for (const [name, propSchema] of Object.entries(props)) {
        if (!result.has(name)) {
          result.set(name, propSchema)
        }
      }
    }
    // Walk conditional branches for complete property discovery
    for (const key of ['allOf', 'anyOf', 'oneOf', 'then', 'else'] as const) {
      const branch = node[key]
      if (Array.isArray(branch)) {
        for (const sub of branch as Record<string, unknown>[]) {
          walk(sub)
        }
      } else if (branch && typeof branch === 'object') {
        walk(branch as Record<string, unknown>)
      }
    }
  }

  walk(schema)
  return result
}

/**
 * Build a rjsf uiSchema from an already-normalized plugin config_schema.
 *
 * Always call normalizeConfigSchema() on the raw plugin schema before calling
 * this function.  After normalization, nullable plain strings no longer have
 * anyOf/oneOf, so no uiSchema override is needed for them.
 *
 * Maps secret fields to the appropriate widget/field:
 *   - Simple password (format:password / writeOnly:true) → PasswordWidget via ui:widget
 *   - Nullable password (anyOf with null branch, e.g. SecretStr | None) →
 *     NullablePasswordField via ui:field + ui:fieldReplacesAnyOrOneOf:true.
 *     This bypasses the anyOf type-selector dropdown, presenting the password
 *     input directly (#67 polish).
 *
 * Returns an empty object (no overrides) if no overrides are needed.
 */
export function buildUiSchema(
  configSchema: Record<string, unknown>,
): UiSchema {
  const uiSchema: UiSchema = {}
  const allProps = collectProperties(configSchema)

  for (const [name, propSchema] of allProps) {
    if (isNullablePasswordField(propSchema)) {
      // Nullable secret (anyOf with null): use custom field that bypasses the
      // anyOf type-selector and presents the password input directly.
      // ui:fieldReplacesAnyOrOneOf:true tells rjsf to skip AnyOfField entirely.
      uiSchema[name] = {
        'ui:field': NULLABLE_PASSWORD_FIELD,
        'ui:fieldReplacesAnyOrOneOf': true,
      }
    } else if (isSimplePasswordField(propSchema)) {
      // Non-nullable secret: standard widget override.
      uiSchema[name] = { 'ui:widget': PASSWORD_WIDGET }
    }
    // Nullable plain strings (Optional[str]) were normalised by normalizeConfigSchema()
    // into type:["string","null"] before this function was called.  rjsf does not add
    // a discriminator dropdown for multi-type arrays, so no uiSchema entry is needed.
  }

  return uiSchema
}
