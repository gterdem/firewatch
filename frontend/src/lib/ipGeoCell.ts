/**
 * ipGeoCell — helpers for rendering inline geo on Source IP table cells (issue #334).
 *
 * Design (issue #334 / strategist rec):
 *   Compact format:  IP 🇧🇬 (Sopot, BG)
 *   The flag ALWAYS pairs with text — never flag alone (Sentinel/CrowdStrike precedent).
 *   Unknown/non-public IPs: bare IP only, no placeholder noise.
 *   Geo is sourced from the local ip_geo cache (server-side JOIN in get_paginated);
 *   no external API call is ever made per cell.
 *
 * SECURITY (ADR-0029 D3):
 *   geo_city and geo_country are GeoIP-resolved from attacker-controlled source_ip.
 *   All values are rendered as React text nodes — never via dangerouslySetInnerHTML.
 *
 * Country flag emoji: ISO 3166-1 alpha-2 country codes are converted to the
 * corresponding regional indicator symbol emoji pair.
 * Reference: Unicode Regional Indicator Symbol Letters U+1F1E6..U+1F1FF.
 * Each letter is offset from 'A' (0x1F1E6) using charCodeAt on the country code.
 * Invalid / non-alpha-2 codes produce an empty string (no flag rendered).
 *
 * Full country name → alpha-2 resolution (issue #362):
 *   The ip_geo cache stores `country` as a full name (e.g. "Germany").
 *   `i18n-iso-countries` (ISO 3166-1 data, MIT licence) resolves full English names
 *   to alpha-2 codes via getAlpha2Code(name, 'en'). This avoids any hand-authored
 *   country list in the codebase.
 */

import countries from 'i18n-iso-countries'
import enLocale from 'i18n-iso-countries/langs/en.json'

// Register the English locale once at module load time.
// This is safe to call multiple times (the library guards against double-registration).
countries.registerLocale(enLocale)

/**
 * Convert an ISO 3166-1 alpha-2 country code (2 uppercase letters) to a flag emoji.
 *
 * Returns an empty string for any input that is not exactly 2 ASCII letters so that
 * malformed values from the cache produce no visible output rather than garbage.
 *
 * Examples:
 *   countryCodeToFlag("BG") → "🇧🇬"
 *   countryCodeToFlag("DE") → "🇩🇪"
 *   countryCodeToFlag("")   → ""
 *   countryCodeToFlag("XX") → "🇽🇽"  (valid Unicode, shown — no block list needed)
 *   countryCodeToFlag("BG ") → ""   (trailing space → rejected)
 */
export function countryCodeToFlag(countryCode: string): string {
  // country names (not codes) from ip-api.com are multi-word strings; reject them.
  // A valid alpha-2 code is exactly 2 ASCII letters.
  if (!countryCode || countryCode.length !== 2) return ''
  const upper = countryCode.toUpperCase()
  if (!/^[A-Z]{2}$/.test(upper)) return ''
  // Unicode Regional Indicator Symbol base: U+1F1E6 = 'A'
  const BASE = 0x1f1e6
  return (
    String.fromCodePoint(BASE + upper.charCodeAt(0) - 65) +
    String.fromCodePoint(BASE + upper.charCodeAt(1) - 65)
  )
}

/**
 * Derive a 2-letter ISO country code from a country *name* string or code.
 *
 * The ip_geo cache stores `country` as the full English name (e.g. "Germany") as
 * returned by ip-api.com. This function resolves full names to alpha-2 codes using
 * the `i18n-iso-countries` library (issue #362 fix) so that the flag emoji renders
 * correctly for cached geo entries.
 *
 * Resolution order:
 *   1. If the value is exactly 2 ASCII alpha letters, treat it as a direct alpha-2 code.
 *   2. Otherwise, pass the value to `countries.getAlpha2Code(name, 'en')` from the
 *      i18n-iso-countries library. Returns undefined when unrecognised.
 *   3. If neither resolves, return '' so no flag is rendered (text-only fallback).
 *
 * Note: This is a best-effort utility. The flag is decorative; rendering plain text
 * (City, Country) is the correct fallback when no code is available.
 */
export function extractCountryCode(geoCountry: string): string {
  if (!geoCountry) return ''
  const trimmed = geoCountry.trim()
  // Fast path: already a 2-letter alpha-2 code (e.g. "DE" stored by some providers)
  if (/^[A-Za-z]{2}$/.test(trimmed)) return trimmed.toUpperCase()
  // Full-name path: resolve via i18n-iso-countries (issue #362)
  const alpha2 = countries.getAlpha2Code(trimmed, 'en')
  return alpha2 ?? ''
}

/**
 * Format an IP cell label with optional inline geo.
 *
 * Returns a plain string suitable for rendering as a React text node.
 *
 * When geo is available: "203.0.113.10 🇩🇪 (Frankfurt am Main, Germany)"
 * When geo is unavailable: "203.0.113.10"
 *
 * The flag + text pair always appears together (never flag alone, per issue #334 spec).
 * Rows remain single-line — truncation is the caller's responsibility (use CSS
 * text-overflow: ellipsis on the containing cell).
 *
 * @param ip           - The source IP string.
 * @param geoCity      - City from the ip_geo cache, or null/undefined when absent.
 * @param geoCountry   - Country from the ip_geo cache, or null/undefined when absent.
 */
export function formatIpGeoLabel(
  ip: string,
  geoCity: string | null | undefined,
  geoCountry: string | null | undefined,
): string {
  const city = geoCity?.trim()
  const country = geoCountry?.trim()

  if (!city && !country) return ip

  const code = extractCountryCode(country ?? '')
  const flag = code ? countryCodeToFlag(code) : ''

  // Build the geo suffix: "(City, Country)" or "(Country)" or "(City)"
  const parts: string[] = []
  if (city) parts.push(city)
  if (country) parts.push(country)
  const geoText = parts.join(', ')

  return flag ? `${ip} ${flag} (${geoText})` : `${ip} (${geoText})`
}
