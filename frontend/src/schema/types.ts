/**
 * TypeScript types for the FireWatch discovery API response.
 *
 * Mirrors the shape returned by GET /sources/types
 * (packages/firewatch-api/src/firewatch_api/routes/sources.py).
 *
 * ADR-0010: the config_schema field is a JSON Schema dict that drives
 * the rjsf Settings card — zero per-source frontend code.
 */

/** Flavor of the source plugin: pull (e.g. Suricata SSH) or push (e.g. webhook). */
export type SourceFlavor = 'pull' | 'push'

/**
 * A declared maintenance action from the discovery response (ADR-0034).
 * Mirrors the SourceAction model in firewatch-sdk.
 *
 * `provides` lists capability tokens — e.g. "rule_descriptions" — that
 * the action produces. Consumers use this for generic hint logic; no
 * per-source branching is permitted.
 *
 * `confirm` is the prose shown in the confirm dialog before the POST fires.
 * When null, the action executes without a confirmation step.
 *
 * `long_running` marks actions that may take 40–60 s (e.g. ruleset download).
 * The UI shows an in-progress spinner and disables re-click while running.
 */
export interface SourceActionDeclaration {
  /** Unique action identifier within the plugin (^[a-z][a-z0-9_]*$). */
  id: string
  /** Human-readable button label, e.g. "Download rule descriptions". */
  label: string
  /** Longer tooltip/description text. */
  description: string
  /**
   * Whether this action is long-running (e.g. a large download).
   * When true, the button shows a spinner and is disabled until complete.
   */
  long_running: boolean
  /**
   * Confirm-dialog prose shown BEFORE the POST fires.
   * Carries size warnings ("~40–60 MB") and other cautions.
   * null means no confirmation is required.
   */
  confirm: string | null
  /**
   * Capability tokens this action produces.
   * e.g. ["rule_descriptions"] for the ruleset-download action.
   * Used by actionHints.ts for generic missing-rule-name hints — no
   * per-source branching.
   */
  provides: string[]
}

/**
 * One entry in the GET /sources/types discovery response.
 * Mirrors the Python dict built in routes/sources.py _build_entry().
 */
export interface SourceTypeEntry {
  /** Unique lowercase key, e.g. "suricata" (^[a-z][a-z0-9_]*$). */
  type_key: string
  /** Human-readable name, e.g. "Suricata IDS/IPS". */
  display_name: string
  /** SemVer string, e.g. "0.1.0". */
  version: string
  /** pull | push */
  flavor: SourceFlavor
  /**
   * The plugin's JSON Schema (from Pydantic model_json_schema()).
   * This is the only input to the Settings card — no per-source code.
   * May include if/then/else for conditional reveal (ADR-0028 D5).
   */
  config_schema: Record<string, unknown>
  /**
   * Declared maintenance actions for this source (ADR-0034).
   * Absent or empty → no action buttons rendered on the Settings card.
   * The field is optional so consumers remain compatible with older
   * discovery responses that pre-date ADR-0034.
   */
  actions?: SourceActionDeclaration[]
  /**
   * Canonical SecurityEvent field names this source can emit (ADR-0060).
   *
   * Empty array (or absent) means "does not declare / produces-all" — treated
   * as producing every field, so no columns are hidden. A source opts in to
   * column-hiding by declaring its set. Additive; resilient-discovery posture
   * unchanged (absent on older discovery responses = produces-all).
   */
  produces?: string[]
}
