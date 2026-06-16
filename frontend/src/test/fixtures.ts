/**
 * Test fixtures — discovery API response shapes.
 *
 * The Suricata schema is the exact output of SuricataConfig.model_json_schema()
 * (generated from the live plugin, not hand-crafted) so tests exercise the
 * real contract.
 *
 * A minimal fixture schema is also included for generic card-render tests
 * that do not need the full Suricata complexity.
 *
 * ADR-0034 / issue #169: fictional plugin fixtures for SourceActions tests.
 * Tests use a fictional type_key ("demo_ids") to prove genericity — no
 * suricata-specific branches anywhere in the new code.
 */

import type { SourceTypeEntry, SourceActionDeclaration } from '../schema/types'
import type { ActionEntry } from '../api/types'

// ---------------------------------------------------------------------------
// ADR-0034 — Action declaration fixtures (fictional type_key: "demo_ids")
// ---------------------------------------------------------------------------

/**
 * A fictional action that provides "rule_descriptions" — used to prove
 * that the hint modal and SourceActions are fully generic (no per-source code).
 */
export const DEMO_FETCH_RULES_ACTION: SourceActionDeclaration = {
  id: 'fetch_rules',
  label: 'Download rule descriptions',
  description: 'Downloads the latest rule catalog (~40–60 MB).',
  long_running: true,
  confirm: 'This will download approximately 40–60 MB of rule description data. Continue?',
  provides: ['rule_descriptions'],
}

/** A second action that provides nothing special — no hint applies. */
export const DEMO_PURGE_CACHE_ACTION: SourceActionDeclaration = {
  id: 'purge_cache',
  label: 'Purge cache',
  description: 'Removes locally cached data.',
  long_running: false,
  confirm: null,
  provides: [],
}

/**
 * A fictional discovery entry with two declared actions.
 * type_key is "demo_ids" — proves genericity, no suricata-specific path.
 */
export const DEMO_IDS_SOURCE_ENTRY: SourceTypeEntry = {
  type_key: 'demo_ids',
  display_name: 'Demo IDS',
  version: '0.2.0',
  flavor: 'pull',
  config_schema: {
    title: 'DemoIdsConfig',
    type: 'object',
    properties: {
      host: { type: 'string', title: 'Host', default: 'localhost' },
    },
  },
  actions: [DEMO_FETCH_RULES_ACTION, DEMO_PURGE_CACHE_ACTION],
}

/**
 * ActionEntry fixture with stale=true (simulates an outdated ruleset).
 * Mirrors the shape returned by GET /sources/{type_key}/actions?source_id=
 */
export const DEMO_FETCH_RULES_ENTRY_STALE: ActionEntry = {
  id: 'fetch_rules',
  label: 'Download rule descriptions',
  description: 'Downloads the latest rule catalog (~40–60 MB).',
  long_running: true,
  confirm: 'This will download approximately 40–60 MB of rule description data. Continue?',
  provides: ['rule_descriptions'],
  last_run_at: '2026-05-01T10:00:00Z',
  stale: true,
  status_message: 'Ruleset updated on sensor since last download',
  status_detail: {},
}

/**
 * ActionEntry fixture with stale=false (up-to-date).
 */
export const DEMO_FETCH_RULES_ENTRY_OK: ActionEntry = {
  ...DEMO_FETCH_RULES_ENTRY_STALE,
  stale: false,
  status_message: null,
}

/**
 * ActionEntry fixture with a real API epoch-seconds timestamp (R2 fix).
 * The API returns last_run_at as a Unix epoch float (seconds), not an ISO string.
 * fmtDate must multiply by 1000 to produce a correct date — not a 1970 date.
 *
 * Value 1781162501.16 corresponds to approximately 2026-06-10T03:01:41Z.
 */
export const DEMO_FETCH_RULES_ENTRY_EPOCH: ActionEntry = {
  ...DEMO_FETCH_RULES_ENTRY_STALE,
  last_run_at: 1781162501.16,  // Unix epoch seconds — the real API shape
  stale: false,
  status_message: null,
}

/**
 * ActionEntry fixture with a healthy (non-null) status_message and stale=null (R3 fix).
 * A healthy catalog reports success ("50723 rules loaded") even when stale is null.
 * The status_message MUST be shown — it was wrongly hidden by the old stale===true gate.
 */
export const DEMO_FETCH_RULES_ENTRY_HEALTHY_MSG: ActionEntry = {
  ...DEMO_FETCH_RULES_ENTRY_STALE,
  stale: null,
  status_message: '50723 rules loaded; downloaded 2026-06-11',
}

/**
 * ActionEntry fixture with null status (degraded / never run).
 */
export const DEMO_FETCH_RULES_ENTRY_NULL: ActionEntry = {
  id: 'fetch_rules',
  label: 'Download rule descriptions',
  description: 'Downloads the latest rule catalog (~40–60 MB).',
  long_running: true,
  confirm: 'This will download approximately 40–60 MB of rule description data. Continue?',
  provides: ['rule_descriptions'],
  last_run_at: null,
  stale: null,
  status_message: null,
  status_detail: {},
}

/** A source entry with NO declared actions — verifies no action UI is rendered. */
export const NO_ACTIONS_SOURCE_ENTRY: SourceTypeEntry = {
  type_key: 'syslog_plain',
  display_name: 'Plain Syslog',
  version: '1.0.0',
  flavor: 'push',
  config_schema: {
    title: 'SyslogConfig',
    type: 'object',
    properties: { port: { type: 'integer', title: 'Port', default: 514 } },
  },
  actions: [],
}

/**
 * Schema that properly implements "reveal not require" (ADR-0028 D5).
 *
 * SSH fields are ONLY in the then.properties branch (not in top-level properties).
 * local_path is ONLY in the else.properties branch.
 * This causes rjsf to show/hide the branches based on the mode value.
 *
 * Note: the current SuricataConfig Python plugin emits "require not reveal" (all
 * fields at top-level, only required changes per branch). The proper reveal schema
 * requires backend changes — tracked as #45. This fixture tests the correct
 * frontend behavior once the backend emits the reveal schema.
 */
export const SURICATA_REVEAL_SCHEMA: Record<string, unknown> = {
  if: {
    properties: { mode: { const: 'remote' } },
    required: ['mode'],
  },
  then: {
    properties: {
      remote_host: {
        default: '',
        description: 'Hostname or IP of the Suricata host (remote mode only).',
        title: 'Remote host',
        type: 'string',
      },
      remote_port: {
        default: 22,
        description: 'SSH port (remote mode only).',
        maximum: 65535,
        minimum: 1,
        title: 'SSH port',
        type: 'integer',
      },
    },
    required: ['remote_host'],
  },
  else: {
    properties: {
      local_path: {
        default: '/var/log/suricata/eve.json',
        description: 'Path to the Suricata eve.json file (local mode only).',
        title: 'EVE JSON path',
        type: 'string',
      },
    },
    required: ['local_path'],
  },
  properties: {
    mode: {
      default: 'local',
      description: "'local' reads eve.json; 'remote' pulls via SSH.",
      enum: ['local', 'remote'],
      title: 'Collection Mode',
      type: 'string',
    },
  },
  title: 'SuricataRevealConfig',
  type: 'object',
}

/** Suricata source entry with the proper reveal-not-require schema (ADR-0028 D5) */
export const SURICATA_REVEAL_SOURCE_ENTRY: SourceTypeEntry = {
  type_key: 'suricata_reveal',
  display_name: 'Suricata (Reveal Schema)',
  version: '0.1.0',
  flavor: 'pull',
  config_schema: SURICATA_REVEAL_SCHEMA,
}

/** Exact schema emitted by SuricataConfig.model_json_schema() */
export const SURICATA_CONFIG_SCHEMA: Record<string, unknown> = {
  description:
    'Suricata collector configuration.\n\n``mode`` selects local file or remote SSH.',
  if: {
    properties: { mode: { const: 'remote' } },
    required: ['mode'],
  },
  then: {
    properties: {
      remote_host: {},
      remote_port: {},
      remote_user: {},
      remote_key: {},
      remote_path: {},
      verify_host_key: {},
    },
    required: ['remote_host'],
  },
  else: {
    properties: {
      local_path: {},
    },
    required: ['local_path'],
  },
  properties: {
    mode: {
      default: 'local',
      description: "'local' reads eve.json; 'remote' pulls via SSH.",
      enum: ['local', 'remote'],
      title: 'Collection Mode',
      type: 'string',
    },
    local_path: {
      default: '/var/log/suricata/eve.json',
      description: 'Path to the Suricata eve.json file (local mode only).',
      title: 'EVE JSON path',
      type: 'string',
    },
    remote_host: {
      default: '',
      description: 'Hostname or IP of the Suricata host (remote mode only).',
      title: 'Remote host',
      type: 'string',
    },
    remote_port: {
      default: 22,
      description: 'SSH port (remote mode only).',
      maximum: 65535,
      minimum: 1,
      title: 'SSH port',
      type: 'integer',
    },
    remote_user: {
      anyOf: [{ type: 'string' }, { type: 'null' }],
      default: null,
      description: 'SSH username.',
      title: 'SSH user',
    },
    remote_key: {
      anyOf: [{ format: 'password', type: 'string', writeOnly: true }, { type: 'null' }],
      default: null,
      description: 'Path to the SSH private key file.',
      title: 'SSH private key path',
    },
    remote_path: {
      default: '/var/log/suricata/eve.json',
      description: 'Path to eve.json on the remote host.',
      title: 'Remote EVE JSON path',
      type: 'string',
    },
    verify_host_key: {
      default: true,
      description: 'When True, validates the remote host key.',
      title: 'Verify SSH host key',
      type: 'boolean',
    },
  },
  title: 'SuricataConfig',
  type: 'object',
}

/** One entry as returned by GET /sources/types */
export const SURICATA_SOURCE_ENTRY: SourceTypeEntry = {
  type_key: 'suricata',
  display_name: 'Suricata IDS/IPS',
  version: '0.1.0',
  flavor: 'pull',
  config_schema: SURICATA_CONFIG_SCHEMA,
}

/** Minimal schema for generic widget/card render tests */
export const MINIMAL_SOURCE_ENTRY: SourceTypeEntry = {
  type_key: 'test_source',
  display_name: 'Test Source',
  version: '1.0.0',
  flavor: 'push',
  config_schema: {
    title: 'TestSourceConfig',
    type: 'object',
    properties: {
      host: {
        type: 'string',
        title: 'Host',
        default: 'localhost',
      },
      // api_key: simple writeOnly/format:password string field.
      // Tests PasswordWidget rendering without anyOf complexity.
      // The Pydantic SecretStr|None (anyOf) case is tested via the Suricata fixture.
      api_key: {
        type: 'string',
        title: 'API Key',
        format: 'password',
        writeOnly: true,
        // No default: when server returns null, stripNullValues removes api_key from
        // formData. rjsf leaves the field undefined. PasswordWidget shows "•••• set".
      },
    },
  },
}

/**
 * Minimal schema with a simple non-null password field.
 * Used for submit/validation tests where anyOf complexity is not needed.
 */
export const SIMPLE_SECRET_SOURCE_ENTRY: SourceTypeEntry = {
  type_key: 'simple_source',
  display_name: 'Simple Source',
  version: '1.0.0',
  flavor: 'push',
  config_schema: {
    title: 'SimpleSourceConfig',
    type: 'object',
    properties: {
      host: {
        type: 'string',
        title: 'Host',
        default: 'localhost',
      },
      token: {
        type: 'string',
        title: 'API Token',
        format: 'password',
        writeOnly: true,
        // No default: when server returns null, stripNullValues removes token from
        // formData. rjsf leaves the field undefined (not populated from default).
        // PasswordWidget calls onChange(undefined) → PUT omits the field.
      },
    },
  },
}

// ---------------------------------------------------------------------------
// Issue #691 — StagedDetailChecklist fixtures
// ActionResult.detail shapes for generic stage_* / stage_*_msg rendering.
// Uses fictional action_id "run_connectivity_check" on fictional type_key
// "demo_ids" — proves no per-source branching.
// ---------------------------------------------------------------------------

import type { ActionResult } from '../api/types'

/**
 * ActionResult with stage_ssh=pass, stage_evejson=fail, stage_activity=skip.
 * Mix of all three status values for checklist rendering tests.
 */
export const STAGED_RESULT_MIXED: ActionResult = {
  ok: false,
  message: 'Connectivity check failed: eve.json stage failed.',
  detail: {
    stage_ssh: 'pass',
    stage_ssh_msg: 'SSH connection established successfully.',
    stage_evejson: 'fail',
    stage_evejson_msg:
      'eve.json not found at /var/log/suricata/eve.json. Verify Suricata is installed and EVE output is enabled.',
    stage_activity: 'skip',
    stage_activity_msg: 'Skipped: eve.json stage did not pass.',
  },
  source_type: 'demo_ids',
  source_id: 'demo_ids',
  action_id: 'run_connectivity_check',
}

/**
 * ActionResult with all stages passing.
 */
export const STAGED_RESULT_ALL_PASS: ActionResult = {
  ok: true,
  message: 'All connectivity checks passed.',
  detail: {
    stage_ssh: 'pass',
    stage_ssh_msg: 'SSH connection established successfully.',
    stage_evejson: 'pass',
    stage_evejson_msg: 'eve.json found and readable.',
    stage_activity: 'pass',
    stage_activity_msg: 'Recent activity detected (events in the last 5 minutes).',
  },
  source_type: 'demo_ids',
  source_id: 'demo_ids',
  action_id: 'run_connectivity_check',
}

/**
 * ActionResult with only plain (non-stage_*) detail keys.
 * Verifies the old flat rendering remains unaffected (regression test).
 */
export const PLAIN_DETAIL_RESULT: ActionResult = {
  ok: true,
  message: 'Cache purged successfully.',
  detail: {
    items_removed: 42,
    cache_type: 'ruleset',
  },
  source_type: 'demo_ids',
  source_id: 'demo_ids',
  action_id: 'purge_cache',
}
