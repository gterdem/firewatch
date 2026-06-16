/**
 * partitionFields — pure helper for ObjectFieldTemplate (R2, #490).
 *
 * Partitions a flat list of rjsf property entries into Essential and Advanced
 * groups based purely on JSON Schema metadata:
 *
 *   Essential  — fields the operator MUST examine on first run:
 *     • listed in schema.required, OR
 *     • are the if/then/else discriminator (present in schema.if.properties), OR
 *     • have no `default` key at all, OR
 *     • have a default of null or "" (empty string) that signals "must be filled"
 *       AND are NOT writeOnly/secret.
 *
 *   Advanced   — fields that are safe to ignore on first run:
 *     • marked writeOnly (or contain a writeOnly branch in anyOf/oneOf), OR
 *     • have a non-null, non-empty-string default value AND are not in required
 *       AND are not the if/then/else discriminator.
 *
 * Design decisions:
 *   - No field-name allowlists, no per-source branching (ADR-0010, ADR-0028).
 *   - writeOnly/secret fields always go to Advanced even when they lack a
 *     "meaningful" default — these are optional credentials (e.g. Azure SP fields)
 *     the operator leaves blank when using managed identity.
 *   - ui:order is NOT handled here — rjsf applies ui:order to the `properties`
 *     array BEFORE calling ObjectFieldTemplate, so the relative order inside each
 *     group is already correct when partitionFields is called.
 *   - #574 empty-card guard: when partitioning would leave the Essential group
 *     empty (all non-writeOnly fields have meaningful defaults, e.g. Syslog),
 *     all non-writeOnly Advanced fields are promoted to Essential so the card
 *     never appears blank. writeOnly/secret fields stay in Advanced regardless.
 *   - #696 if/then/else discriminator: any field referenced in schema.if.properties
 *     is the master control that reveals/hides entire conditional field groups.
 *     It MUST be Essential regardless of default. The check is generic — it reads
 *     the discriminator from schema.if.properties without hardcoding field names.
 *
 * ADR-0028: part of the project-local widget/template registry.
 */

import type { RJSFSchema } from '@rjsf/utils'

/** Minimal representation of a property slot passed to ObjectFieldTemplate. */
export interface FieldSlot {
  name: string
  hidden: boolean
}

/** Result of partitioning properties into Essential / Advanced groups. */
export interface PartitionResult {
  essential: FieldSlot[]
  advanced: FieldSlot[]
}

/**
 * Returns true when a property schema is writeOnly or contains a writeOnly
 * branch inside an anyOf/oneOf union (e.g. Pydantic SecretStr | None).
 */
export function isWriteOnlyField(propSchema: RJSFSchema): boolean {
  if (propSchema.writeOnly === true) return true

  const variants =
    (propSchema.anyOf as RJSFSchema[] | undefined) ??
    (propSchema.oneOf as RJSFSchema[] | undefined) ??
    []

  return variants.some((branch) => branch.writeOnly === true)
}

/**
 * Returns the set of field names that act as if/then/else discriminators in
 * the given object schema.
 *
 * JSON Schema `if/then/else` uses a sub-schema under `if` to pick a branch.
 * The keys of `schema.if.properties` are the fields that drive that conditional
 * — they must be visible (Essential) because changing them reveals or hides the
 * entire conditional field group.
 *
 * Generic: reads the discriminator from the schema without any field-name
 * allowlist or per-source branching (ADR-0010, ADR-0028, #696).
 */
export function getDiscriminatorFields(schema: RJSFSchema): Set<string> {
  const ifClause = schema.if as RJSFSchema | undefined
  if (!ifClause || typeof ifClause !== 'object') return new Set()
  const ifProps = ifClause.properties as Record<string, unknown> | undefined
  if (!ifProps || typeof ifProps !== 'object') return new Set()
  return new Set(Object.keys(ifProps))
}

/**
 * Returns true when a property schema has a "meaningful" default — i.e. a
 * default that is non-null and non-empty-string, signalling that the field is
 * safe to leave at its preset value on first run.
 *
 * null → "not configured" (optional credential / disabled feature)
 * ""   → "must be filled in" (e.g. Azure workspace_id placeholder)
 * 0    → meaningful integer/numeric default (e.g. overlap_minutes = 0)
 *
 * Note: the number 0 IS considered meaningful (it is an explicit choice).
 * Only null and "" signal "no value set."
 */
export function hasMeaningfulDefault(propSchema: RJSFSchema): boolean {
  if (!('default' in propSchema)) return false
  const def = propSchema.default
  if (def === null) return false
  if (def === '') return false
  return true
}

/**
 * Partition an ordered property name list into Essential and Advanced slots.
 *
 * @param names     Ordered field names (already sorted by ui:order if supplied).
 * @param schema    The parent object's JSON Schema (for `required` array and
 *                  per-property sub-schemas).
 * @returns         Two arrays, preserving the relative order from `names`.
 */
export function partitionFields(names: string[], schema: RJSFSchema): PartitionResult {
  const required = new Set<string>(
    Array.isArray(schema.required) ? (schema.required as string[]) : [],
  )

  // #696: fields named in schema.if.properties are the if/then/else discriminator.
  // They control which conditional field group is revealed and MUST be Essential
  // regardless of whether they carry a meaningful default.
  const discriminators = getDiscriminatorFields(schema)

  const properties = (schema.properties ?? {}) as Record<string, RJSFSchema>

  const essential: FieldSlot[] = []
  const advanced: FieldSlot[] = []

  for (const name of names) {
    const propSchema: RJSFSchema = properties[name] ?? {}
    const slot: FieldSlot = { name, hidden: false }

    // writeOnly/secret fields always collapse — they are optional credentials.
    if (isWriteOnlyField(propSchema)) {
      advanced.push(slot)
      continue
    }

    // Required fields are always Essential.
    if (required.has(name)) {
      essential.push(slot)
      continue
    }

    // #696: if/then/else discriminator fields are always Essential — they are the
    // master toggle that reveals/hides the conditional field group. This check
    // MUST run before hasMeaningfulDefault so the discriminator wins even when
    // the field has a non-null, non-empty default (e.g. mode="local").
    if (discriminators.has(name)) {
      essential.push(slot)
      continue
    }

    // Fields with a meaningful non-null, non-empty default go to Advanced.
    if (hasMeaningfulDefault(propSchema)) {
      advanced.push(slot)
      continue
    }

    // Everything else (no default, null default, empty-string default) is Essential.
    essential.push(slot)
  }

  // #574 — guard against an "empty card" appearance.
  //
  // If all non-writeOnly fields ended up in Advanced (e.g. Syslog where every
  // field has a meaningful default but none are marked `required`), the card
  // body would appear blank with only a collapsed "Advanced / Optional" toggle.
  //
  // Fix: when the Essential group is empty, split the Advanced group into
  // writeOnly credentials (stay in Advanced) and all others (promoted to
  // Essential).  If there are no non-writeOnly fields to promote (edge case:
  // every field is writeOnly), return as-is so the Advanced toggle still renders.
  //
  // This is schema-metadata-only (ADR-0010, ADR-0028) — no field-name
  // allowlists and no per-source branching.
  if (essential.length === 0 && advanced.length > 0) {
    const promotable: FieldSlot[] = []
    const writeOnlyOnly: FieldSlot[] = []
    for (const slot of advanced) {
      const propSchema: RJSFSchema = properties[slot.name] ?? {}
      if (isWriteOnlyField(propSchema)) {
        writeOnlyOnly.push(slot)
      } else {
        promotable.push(slot)
      }
    }
    // If there are non-writeOnly fields to promote, do so; leave writeOnly in Advanced.
    if (promotable.length > 0) {
      return { essential: promotable, advanced: writeOnlyOnly }
    }
    // Edge case: every field is writeOnly — keep everything in Advanced.
    // The card will show only the Advanced toggle; no essential-field body.
  }

  return { essential, advanced }
}
