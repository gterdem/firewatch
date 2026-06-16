/**
 * actionHints — pure helper for the missing-rule-name hint modal (ADR-0034 / issue #169).
 *
 * Given the discovery cache (SourceTypeEntry[]) and a log event's source_type +
 * missing rule_name, returns the hint data needed to render the generic modal:
 *   "Rule descriptions for this source aren't loaded — download in
 *    Settings → {display_name} ({size text from confirm})"
 *
 * Returns null when:
 *   - The source is not found in the discovery cache.
 *   - The source declares no actions with "rule_descriptions" in provides.
 *   - The rule_name is already present (hint not needed).
 *
 * ZERO per-source branching — no `type_key` comparisons here or in callers.
 * The hint surfaces whenever ANY plugin declares an action that provides
 * "rule_descriptions". Installing a new plugin that declares such an action
 * automatically enables hint display for its rules, with no UI edits required.
 *
 * This module is a pure function — no side effects, no React, no fetch calls.
 */

import type { SourceTypeEntry, SourceActionDeclaration } from '../schema/types'

/** Capability token that identifies a rule-descriptions provider (ADR-0034). */
const RULE_DESCRIPTIONS_TOKEN = 'rule_descriptions'

/**
 * Hint data returned when a rule has no name but a providing action exists.
 */
export interface ActionHint {
  /** Human-readable source name for the hint label, e.g. "Suricata IDS/IPS". */
  displayName: string
  /** The action's button label, e.g. "Download rule descriptions". */
  actionLabel: string
  /**
   * The full confirm prose from the declaration — contains the size warning.
   * May be null when the action has no confirm prose.
   */
  confirmProse: string | null
  /**
   * The providing action declaration — callers may need additional fields
   * (e.g. action id for deep-linking to Settings).
   */
  action: SourceActionDeclaration
  /** The source entry for deep-linking. */
  source: SourceTypeEntry
}

/**
 * Find the hint for a rule that has no name.
 *
 * @param discoveryCache  All entries from GET /sources/types.
 * @param sourceType      The source_type field of the log event.
 * @param ruleName        The rule_name field of the log event (null / undefined = missing).
 * @returns ActionHint when a providing action exists, null otherwise.
 */
export function findActionHint(
  discoveryCache: SourceTypeEntry[],
  sourceType: string,
  ruleName: string | null | undefined,
): ActionHint | null {
  // Only hint when rule_name is absent (null, undefined, or empty string).
  if (ruleName != null && String(ruleName) !== '') return null

  // Look up the source entry — linear scan, short list (installed plugins only).
  const source = discoveryCache.find((s) => s.type_key === sourceType)
  if (!source) return null

  // Find the first declared action that provides rule_descriptions.
  const actions = source.actions ?? []
  const providing = actions.find(
    (a) => Array.isArray(a.provides) && a.provides.includes(RULE_DESCRIPTIONS_TOKEN),
  )
  if (!providing) return null

  return {
    displayName: source.display_name,
    actionLabel: providing.label,
    confirmProse: providing.confirm,
    action: providing,
    source,
  }
}
