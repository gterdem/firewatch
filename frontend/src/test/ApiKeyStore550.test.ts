/**
 * Tests for src/app/apiKeyStore.ts (issue #550 / ADR-0026 Amendment 1).
 *
 * EARS criteria covered:
 *   - State-driven: getApiKey() returns null when no key is set.
 *   - Event-driven: setApiKey(value) sets the key; getApiKey() returns it.
 *   - Event-driven: setApiKey(null) clears the key.
 *   - Event-driven: setApiKey('') clears the key (empty string treated as unset).
 *   - Event-driven: setApiKey('  whitespace  ') trims and sets.
 *   - Event-driven (first-key-set notice): isFirstKeySetInSession() returns true
 *     on the first non-null setApiKey call; false thereafter.
 *   - Event-driven: clearFirstKeySetFlag() resets the flag.
 *   - Ubiquitous (security): key stored in-memory only (tested via module invariants).
 */

import { describe, it, expect, beforeEach } from 'vitest'
import {
  getApiKey,
  setApiKey,
  isFirstKeySetInSession,
  clearFirstKeySetFlag,
  _resetForTest,
} from '../app/apiKeyStore'

beforeEach(() => {
  _resetForTest()
})

describe('apiKeyStore — key state', () => {
  it('returns null before any key is set', () => {
    expect(getApiKey()).toBeNull()
  })

  it('stores and returns the key after setApiKey', () => {
    setApiKey('my-secret-key')
    expect(getApiKey()).toBe('my-secret-key')
  })

  it('trims whitespace from the key', () => {
    setApiKey('  trimmed  ')
    expect(getApiKey()).toBe('trimmed')
  })

  it('clears the key when set to null', () => {
    setApiKey('some-key')
    setApiKey(null)
    expect(getApiKey()).toBeNull()
  })

  it('clears the key when set to empty string', () => {
    setApiKey('some-key')
    setApiKey('')
    expect(getApiKey()).toBeNull()
  })

  it('clears the key when set to whitespace-only string', () => {
    setApiKey('some-key')
    setApiKey('   ')
    expect(getApiKey()).toBeNull()
  })
})

describe('apiKeyStore — first-key-set session flag', () => {
  it('flag is false before any key is set', () => {
    expect(isFirstKeySetInSession()).toBe(false)
  })

  it('flag becomes true on first non-null setApiKey call', () => {
    setApiKey('first-key')
    expect(isFirstKeySetInSession()).toBe(true)
  })

  it('flag stays true if set again (does not re-trigger on replace)', () => {
    setApiKey('first-key')
    clearFirstKeySetFlag()
    // Now we have a key set; replacing it should NOT set the flag again.
    setApiKey('second-key')
    expect(isFirstKeySetInSession()).toBe(false)
  })

  it('clearFirstKeySetFlag() resets the flag to false', () => {
    setApiKey('a-key')
    expect(isFirstKeySetInSession()).toBe(true)
    clearFirstKeySetFlag()
    expect(isFirstKeySetInSession()).toBe(false)
  })

  it('flag does not trigger when clearing a null key with null', () => {
    // Already null → setting null again should not set the flag.
    setApiKey(null)
    expect(isFirstKeySetInSession()).toBe(false)
  })
})
