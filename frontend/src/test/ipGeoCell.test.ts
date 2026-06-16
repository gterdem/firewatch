/**
 * Tests for src/lib/ipGeoCell.ts (issues #334, #362).
 *
 * EARS criteria covered:
 *
 * GC1  WHEN a public IP with cached geo renders in a Source IP cell,
 *      the cell SHALL show flag + city/country-code inline.
 *      → formatIpGeoLabel returns "IP 🇩🇪 (Frankfurt am Main, Germany)"
 *
 * GC2  WHEN geo is unknown (null/undefined), the cell SHALL show the bare IP only.
 *      → formatIpGeoLabel returns the bare IP string unchanged
 *
 * GC3  The flag SHALL never appear without its text pair.
 *      → countryCodeToFlag with valid code produces a flag; formatIpGeoLabel
 *         always pairs it with "(City, Country)" text
 *
 * GC4  Invalid / non-alpha-2 country codes SHALL produce no flag.
 *      → countryCodeToFlag("") / ("X") / ("Germany") → ""
 *
 * GC5  RFC-5737 IPs only in test fixtures — no real/routable IPs.
 *
 * GC6  WHEN the ip_geo cache stores geo_country as a full English name (e.g. "Germany"),
 *      extractCountryCode SHALL resolve it to the alpha-2 code via i18n-iso-countries
 *      and formatIpGeoLabel SHALL render the flag (issue #362).
 *      → formatIpGeoLabel("203.0.113.10", "Frankfurt am Main", "Germany")
 *         returns "203.0.113.10 🇩🇪 (Frankfurt am Main, Germany)"
 *
 * GC7  WHEN the full name cannot be resolved, the cell SHALL render text-only (no flag).
 *
 * All IP addresses use RFC 5737 documentation ranges (203.0.113.0/24).
 */

import { describe, it, expect } from 'vitest'
import {
  countryCodeToFlag,
  extractCountryCode,
  formatIpGeoLabel,
} from '../lib/ipGeoCell'

// ---------------------------------------------------------------------------
// countryCodeToFlag
// ---------------------------------------------------------------------------

describe('countryCodeToFlag', () => {
  it('converts BG to the Bulgarian flag emoji', () => {
    expect(countryCodeToFlag('BG')).toBe('\u{1F1E7}\u{1F1EC}')
  })

  it('converts DE to the German flag emoji', () => {
    expect(countryCodeToFlag('DE')).toBe('\u{1F1E9}\u{1F1EA}')
  })

  it('accepts lowercase input by upcasing', () => {
    expect(countryCodeToFlag('bg')).toBe('\u{1F1E7}\u{1F1EC}')
  })

  it('returns empty string for empty input', () => {
    expect(countryCodeToFlag('')).toBe('')
  })

  it('returns empty string for single letter', () => {
    expect(countryCodeToFlag('B')).toBe('')
  })

  it('returns empty string for three letters', () => {
    expect(countryCodeToFlag('BGR')).toBe('')
  })

  it('returns empty string for a full country name', () => {
    expect(countryCodeToFlag('Germany')).toBe('')
  })

  it('returns empty string for code with trailing space', () => {
    expect(countryCodeToFlag('BG ')).toBe('')
  })

  it('returns empty string for digits', () => {
    expect(countryCodeToFlag('12')).toBe('')
  })
})

// ---------------------------------------------------------------------------
// extractCountryCode
// ---------------------------------------------------------------------------

describe('extractCountryCode', () => {
  it('returns the code as-is when input is exactly 2 alpha letters', () => {
    expect(extractCountryCode('DE')).toBe('DE')
  })

  it('upcases lowercase 2-letter code', () => {
    expect(extractCountryCode('de')).toBe('DE')
  })

  it('resolves full English country name "Germany" to "DE" via i18n-iso-countries (issue #362)', () => {
    expect(extractCountryCode('Germany')).toBe('DE')
  })

  it('resolves full English country name "France" to "FR" via i18n-iso-countries', () => {
    expect(extractCountryCode('France')).toBe('FR')
  })

  it('resolves full English country name "United States of America" to "US"', () => {
    expect(extractCountryCode('United States of America')).toBe('US')
  })

  it('returns empty string for empty input', () => {
    expect(extractCountryCode('')).toBe('')
  })

  it('returns empty string for single letter', () => {
    expect(extractCountryCode('D')).toBe('')
  })

  it('returns empty string for an unrecognised name', () => {
    expect(extractCountryCode('Neverland')).toBe('')
  })
})

// ---------------------------------------------------------------------------
// formatIpGeoLabel
// ---------------------------------------------------------------------------

describe('formatIpGeoLabel — GC1: public IP with cached geo', () => {
  it('returns IP + flag + (City, Country) when both city and country are present', () => {
    const label = formatIpGeoLabel('203.0.113.10', 'Frankfurt am Main', 'DE')
    // Flag for DE = 🇩🇪 (\u{1F1E9}\u{1F1EA})
    expect(label).toBe('203.0.113.10 \u{1F1E9}\u{1F1EA} (Frankfurt am Main, DE)')
  })

  it('returns IP + flag + (City, Country) for Bulgaria', () => {
    const label = formatIpGeoLabel('203.0.113.11', 'Sopot', 'BG')
    expect(label).toBe('203.0.113.11 \u{1F1E7}\u{1F1EC} (Sopot, BG)')
  })

  it('returns IP + (Country) when city is absent but country is present', () => {
    const label = formatIpGeoLabel('203.0.113.12', null, 'DE')
    // No city → just the country in parens; flag still shown
    expect(label).toBe('203.0.113.12 \u{1F1E9}\u{1F1EA} (DE)')
  })

  it('returns IP + (City) when city is present but country is absent', () => {
    const label = formatIpGeoLabel('203.0.113.13', 'Sofia', null)
    // No country → no flag; just "(City)"
    expect(label).toBe('203.0.113.13 (Sofia)')
  })

  it('resolves full country name to flag via i18n-iso-countries (issue #362)', () => {
    // ip_geo cache stores full names; i18n-iso-countries maps "Germany" → "DE" → 🇩🇪
    const label = formatIpGeoLabel('203.0.113.14', 'Frankfurt am Main', 'Germany')
    // Flag for DE = 🇩🇪 (\u{1F1E9}\u{1F1EA})
    expect(label).toBe('203.0.113.14 \u{1F1E9}\u{1F1EA} (Frankfurt am Main, Germany)')
  })
})

describe('formatIpGeoLabel — GC2: unknown geo returns bare IP', () => {
  it('returns bare IP when both geo_city and geo_country are null', () => {
    expect(formatIpGeoLabel('203.0.113.20', null, null)).toBe('203.0.113.20')
  })

  it('returns bare IP when both geo_city and geo_country are undefined', () => {
    expect(formatIpGeoLabel('203.0.113.21', undefined, undefined)).toBe('203.0.113.21')
  })

  it('returns bare IP when geo fields are empty strings', () => {
    expect(formatIpGeoLabel('203.0.113.22', '', '')).toBe('203.0.113.22')
  })
})

describe('formatIpGeoLabel — GC3: flag always paired with text', () => {
  it('flag appears only when at least country text is also present', () => {
    const label = formatIpGeoLabel('203.0.113.23', 'Berlin', 'DE')
    const flag = '\u{1F1E9}\u{1F1EA}'
    expect(label).toContain(flag)
    // The flag must be followed by " (Berlin, DE)" — not standalone
    expect(label).toMatch(/🇩🇪 \(Berlin, DE\)/)
  })
})

describe('formatIpGeoLabel — GC6: full country name resolves to flag (issue #362)', () => {
  it('renders flag when geo_country is a full English name stored by ip_geo cache', () => {
    // "Germany" stored in ip_geo.country → resolved to "DE" → 🇩🇪
    const label = formatIpGeoLabel('203.0.113.30', 'Munich', 'Germany')
    expect(label).toBe('203.0.113.30 \u{1F1E9}\u{1F1EA} (Munich, Germany)')
  })

  it('renders flag for "France" full name', () => {
    const label = formatIpGeoLabel('203.0.113.31', 'Paris', 'France')
    // FR flag = 🇫🇷 (\u{1F1EB}\u{1F1F7})
    expect(label).toBe('203.0.113.31 \u{1F1EB}\u{1F1F7} (Paris, France)')
  })

  it('renders flag for "United States of America" full name', () => {
    const label = formatIpGeoLabel('203.0.113.32', 'New York', 'United States of America')
    // US flag = 🇺🇸 (\u{1F1FA}\u{1F1F8})
    expect(label).toBe('203.0.113.32 \u{1F1FA}\u{1F1F8} (New York, United States of America)')
  })
})

describe('formatIpGeoLabel — GC7: unresolvable name renders text-only (no flag)', () => {
  it('renders text without flag when country name cannot be resolved', () => {
    const label = formatIpGeoLabel('203.0.113.40', 'Somewhere', 'Neverland')
    expect(label).toBe('203.0.113.40 (Somewhere, Neverland)')
    // Ensure no regional-indicator codepoints in the output
    expect(label).not.toMatch(/[\u{1F1E6}-\u{1F1FF}]/u)
  })
})
