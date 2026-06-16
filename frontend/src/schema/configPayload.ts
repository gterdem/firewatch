/**
 * Config payload utilities — strip/build helpers for rjsf form data.
 *
 * Extracted to a separate module so they can be shared between
 * SourceConfigForm.tsx and tests without triggering the
 * react-refresh/only-export-components lint rule.
 */

import type { UiSchema } from '@rjsf/utils'

/**
 * Strip null/undefined-valued keys from a config dict.
 * Used when loading GET response into formData: server-masked secrets arrive as null.
 * rjsf/AJV validates formData; null in a type:string field fails validation.
 * Stripping null → undefined lets rjsf use the schema default or leave the field empty.
 */
export function stripNullValues(obj: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(obj).filter(([, v]) => v !== null && v !== undefined),
  )
}

/**
 * Build the PUT payload from submitted formData.
 *
 * Strips keys that should not be sent to the server:
 * - null/undefined values (server-masked secrets not re-typed by user)
 * - empty string ('') for secret fields — omit to preserve the stored value.
 *   Covers both widget kinds used for secrets:
 *     • ui:widget === 'PasswordWidget'        — non-nullable SecretStr
 *     • ui:field  === 'NullablePasswordField' — SecretStr | None (#523)
 *   NullablePasswordField currently emits undefined (not '') when the user hasn't typed,
 *   but guarding '' here too removes a latent hazard if that ever changes.
 *
 * uiSchema is used to identify secret fields.
 * Non-password fields with '' are preserved (e.g. remote_host = '' is a valid empty string).
 */
export function buildPutPayload(
  obj: Record<string, unknown>,
  uiSchema: UiSchema,
): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(obj).filter(([key, v]) => {
      if (v === null || v === undefined) return false
      // For secret fields, empty string means "no new value typed" — omit from PUT
      // to preserve the currently-stored secret on the server.
      if (v === '') {
        const fieldUi = uiSchema[key]
        if (fieldUi && typeof fieldUi === 'object') {
          const ui = fieldUi as Record<string, unknown>
          if (
            ui['ui:widget'] === 'PasswordWidget' ||
            ui['ui:field'] === 'NullablePasswordField'
          ) {
            return false
          }
        }
      }
      return true
    }),
  )
}
