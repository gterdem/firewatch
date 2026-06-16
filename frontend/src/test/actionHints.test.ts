/**
 * Tests for src/lib/actionHints.ts
 *
 * EARS criteria covered:
 *   - Event-driven: when rule_name is missing AND source declares
 *     rule_descriptions provider → hint is returned.
 *   - Event-driven: when rule_name is present → null returned.
 *   - Event-driven: when source declares no rule_descriptions action → null.
 *   - Event-driven: when source not found in discovery cache → null.
 *   - Ubiquitous: no type_key comparisons in the helper (genericity assertion).
 *   - Unwanted: graceful degradation when actions array is absent.
 */

import { describe, it, expect } from 'vitest'
import { findActionHint } from '../lib/actionHints'
import type { SourceTypeEntry } from '../schema/types'
import {
  DEMO_IDS_SOURCE_ENTRY,
  DEMO_FETCH_RULES_ACTION,
  NO_ACTIONS_SOURCE_ENTRY,
} from './fixtures'

describe('findActionHint', () => {
  // EARS event-driven: missing rule_name + provider action → hint returned.
  it('returns hint when rule_name is null and source declares rule_descriptions action', () => {
    const hint = findActionHint([DEMO_IDS_SOURCE_ENTRY], 'demo_ids', null)
    expect(hint).not.toBeNull()
    expect(hint!.displayName).toBe('Demo IDS')
    expect(hint!.actionLabel).toBe(DEMO_FETCH_RULES_ACTION.label)
    expect(hint!.confirmProse).toBe(DEMO_FETCH_RULES_ACTION.confirm)
    expect(hint!.action.id).toBe('fetch_rules')
    expect(hint!.source.type_key).toBe('demo_ids')
  })

  // EARS event-driven: empty string rule_name is treated as missing.
  it('returns hint when rule_name is empty string', () => {
    const hint = findActionHint([DEMO_IDS_SOURCE_ENTRY], 'demo_ids', '')
    expect(hint).not.toBeNull()
    expect(hint!.displayName).toBe('Demo IDS')
  })

  // EARS event-driven: undefined rule_name treated as missing.
  it('returns hint when rule_name is undefined', () => {
    const hint = findActionHint([DEMO_IDS_SOURCE_ENTRY], 'demo_ids', undefined)
    expect(hint).not.toBeNull()
  })

  // EARS event-driven: rule_name present → no hint needed.
  it('returns null when rule_name is a non-empty string', () => {
    const hint = findActionHint([DEMO_IDS_SOURCE_ENTRY], 'demo_ids', 'ET SCAN Nmap Scripting')
    expect(hint).toBeNull()
  })

  // EARS event-driven: source declares no rule_descriptions action → null.
  it('returns null when source declares no rule_descriptions action', () => {
    const hint = findActionHint([NO_ACTIONS_SOURCE_ENTRY], 'syslog_plain', null)
    expect(hint).toBeNull()
  })

  // EARS event-driven: source not in discovery cache → null.
  it('returns null when source_type is not found in discovery cache', () => {
    const hint = findActionHint([DEMO_IDS_SOURCE_ENTRY], 'unknown_source', null)
    expect(hint).toBeNull()
  })

  // EARS unwanted: actions field absent (older discovery response) → null, no crash.
  it('returns null gracefully when source entry has no actions field', () => {
    const sourceWithoutActions: SourceTypeEntry = {
      type_key: 'legacy_source',
      display_name: 'Legacy Source',
      version: '0.1.0',
      flavor: 'pull',
      config_schema: { type: 'object', properties: {} },
      // actions field deliberately omitted (pre-ADR-0034 discovery response)
    }
    const hint = findActionHint([sourceWithoutActions], 'legacy_source', null)
    expect(hint).toBeNull()
  })

  // EARS ubiquitous: helper works for any type_key (genericity).
  // Uses a fictional "quantum_ids" plugin — proves no per-source hardcoding.
  it('works generically for any fictional type_key (no hardcoded source names)', () => {
    const quantumSource: SourceTypeEntry = {
      type_key: 'quantum_ids',
      display_name: 'Quantum IDS',
      version: '1.0.0',
      flavor: 'pull',
      config_schema: { type: 'object', properties: {} },
      actions: [
        {
          id: 'load_rules',
          label: 'Load rule catalog',
          description: 'Loads the rule catalog.',
          long_running: true,
          confirm: 'Download ~50 MB?',
          provides: ['rule_descriptions'],
        },
      ],
    }
    const hint = findActionHint([quantumSource], 'quantum_ids', null)
    expect(hint).not.toBeNull()
    expect(hint!.displayName).toBe('Quantum IDS')
    expect(hint!.action.id).toBe('load_rules')
  })

  // EARS event-driven: source has action but with different provides token → null.
  it('returns null when action provides only unrelated capability tokens', () => {
    const sourceWithOtherAction: SourceTypeEntry = {
      type_key: 'other_source',
      display_name: 'Other Source',
      version: '1.0.0',
      flavor: 'pull',
      config_schema: { type: 'object', properties: {} },
      actions: [
        {
          id: 'reload_config',
          label: 'Reload config',
          description: 'Reloads runtime config.',
          long_running: false,
          confirm: null,
          provides: ['runtime_config'],  // NOT rule_descriptions
        },
      ],
    }
    const hint = findActionHint([sourceWithOtherAction], 'other_source', null)
    expect(hint).toBeNull()
  })

  // EARS state-driven: multiple sources in cache — only matching type_key is used.
  it('returns correct source when multiple sources are in the discovery cache', () => {
    const cache: SourceTypeEntry[] = [NO_ACTIONS_SOURCE_ENTRY, DEMO_IDS_SOURCE_ENTRY]
    const hint = findActionHint(cache, 'demo_ids', null)
    expect(hint).not.toBeNull()
    expect(hint!.displayName).toBe('Demo IDS')

    // The syslog source has no rule_descriptions action — must still return null.
    const hintSyslog = findActionHint(cache, 'syslog_plain', null)
    expect(hintSyslog).toBeNull()
  })
})
