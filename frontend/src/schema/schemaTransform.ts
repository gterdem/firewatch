/**
 * JSON Schema normalization for rjsf rendering.
 *
 * R4 fix (issue #195 re-verification D3): rjsf v6 renders anyOf/oneOf fields
 * with a "type-selector" discriminator dropdown by default.  For nullable plain
 * strings — Pydantic `Optional[str]` emitting:
 *
 *   anyOf: [{ type: "string" }, { type: "null" }]
 *
 * this dropdown is pure noise: the user never needs to choose between string
 * and null — an empty input means null, a typed value means string.
 *
 * The previous attempt used `ui:fieldReplacesAnyOrOneOf: true` without a
 * corresponding `ui:field` key.  rjsf v6 source (MultiSchemaField.tsx L2420):
 *
 *   const isReplacingAnyOrOneOf =
 *     uiOptions.field && uiOptions.fieldReplacesAnyOrOneOf === true;
 *
 * The flag is ONLY honoured when `uiOptions.field` is also truthy.  Without
 * a `ui:field`, the discriminator dropdown still renders — the previous fix
 * was silently a no-op.
 *
 * The clean, generic solution: collapse
 *   anyOf: [{ type: "string" }, { type: "null" }]
 * into the equivalent
 *   type: ["string", "null"]
 * at the schema level BEFORE handing the schema to rjsf.  rjsf does not
 * add a discriminator for multi-type arrays — it simply renders the
 * appropriate widget for the first concrete type.  This is semantically
 * equivalent JSON Schema (Draft 2020-12 §10.3.2.1 / Draft 7 §§6.1) and
 * requires zero uiSchema override.
 *
 * Nullable password fields (anyOf with a writeOnly/format:password branch)
 * are intentionally LEFT UNCHANGED — those are handled by NullablePasswordField
 * via uiSchema and must keep the anyOf structure so the custom field can see it.
 */

/**
 * Returns true if an anyOf/oneOf array is EXACTLY the nullable-plain-string
 * pattern: two branches, one `{type:"string"}` and one `{type:"null"}`, and
 * NO password/writeOnly marker in either branch.
 */
function isCollapseableNullableString(branches: unknown[]): boolean {
  if (branches.length !== 2) return false
  const typed = branches as Record<string, unknown>[]
  const hasPasswordMarker = typed.some(
    (b) => b['format'] === 'password' || b['writeOnly'] === true,
  )
  if (hasPasswordMarker) return false
  const hasStringBranch = typed.some((b) => b['type'] === 'string')
  const hasNullBranch = typed.some((b) => b['type'] === 'null')
  return hasStringBranch && hasNullBranch
}

/**
 * Deep-clone a JSON Schema object (plain JSON-compatible structure).
 * We need a clone so we do not mutate the original discovery response.
 */
function cloneSchema(schema: Record<string, unknown>): Record<string, unknown> {
  return JSON.parse(JSON.stringify(schema)) as Record<string, unknown>
}

/**
 * Normalize a single property schema node:
 *   anyOf/oneOf [{ type: "string" }, { type: "null" }] → type: ["string", "null"]
 *
 * Mutates the node in place (called on the cloned schema).
 */
function normalizePropertyNode(node: Record<string, unknown>): void {
  for (const key of ['anyOf', 'oneOf'] as const) {
    const branches = node[key]
    if (!Array.isArray(branches)) continue
    if (isCollapseableNullableString(branches)) {
      // Collapse to multi-type array; remove the anyOf/oneOf key.
      node['type'] = ['string', 'null']
      delete node[key]
      // Preserve scalar metadata from the string branch (e.g. title, description, default).
      // The null branch is { type: "null" } — no other metadata to preserve.
      const stringBranch = (branches as Record<string, unknown>[]).find(
        (b) => b['type'] === 'string',
      )
      if (stringBranch) {
        for (const [k, v] of Object.entries(stringBranch)) {
          if (k !== 'type' && !(k in node)) {
            node[k] = v
          }
        }
      }
      // Only one key can be anyOf or oneOf on the same node — stop after the first match.
      break
    }
  }
}

/**
 * Walk a JSON Schema and normalize all nullable-plain-string properties.
 * Recurses into properties, allOf, then, else branches so that fields inside
 * if/then/else conditional sections are also normalized.
 */
function walkAndNormalize(node: Record<string, unknown>): void {
  const props = node['properties'] as Record<string, Record<string, unknown>> | undefined
  if (props) {
    for (const propSchema of Object.values(props)) {
      normalizePropertyNode(propSchema)
    }
  }
  // Recurse into structural branches (not anyOf/oneOf at the schema root —
  // those are not properties and should not be touched here).
  for (const key of ['allOf', 'then', 'else'] as const) {
    const branch = node[key]
    if (Array.isArray(branch)) {
      for (const sub of branch as Record<string, unknown>[]) {
        walkAndNormalize(sub)
      }
    } else if (branch && typeof branch === 'object') {
      walkAndNormalize(branch as Record<string, unknown>)
    }
  }
}

/**
 * Return a normalized copy of a plugin config_schema with nullable-plain-string
 * properties collapsed from anyOf/oneOf to multi-type arrays.
 *
 * Nullable password fields are left unchanged (handled by NullablePasswordField).
 * The original schema is never mutated.
 */
export function normalizeConfigSchema(
  schema: Record<string, unknown>,
): Record<string, unknown> {
  const cloned = cloneSchema(schema)
  walkAndNormalize(cloned)
  return cloned
}
