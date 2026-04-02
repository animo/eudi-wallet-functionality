import type { CredentialMetadata } from '@animo-id/eudi-wallet-ts12-validation'
import Accept from '@hapi/accept'
import { lookup } from 'bcp-47-match'
import type { LocaleCanonicalizer } from './types'

// =============================================================================
// Accept-Language parsing via @hapi/accept (RFC 9110 Section 12.5.4)
// =============================================================================

/** Result of parsing an Accept-Language header. */
export interface ParsedAcceptLanguage {
  /** Language tags in quality-descending order (q=0 excluded). `*` is included when present. */
  locales: string[]
  /** True when `*` was present with q > 0 (client accepts any language). */
  acceptsAll: boolean
}

/**
 * Parse an Accept-Language header.
 *
 * Uses @hapi/accept which:
 * - Throws on malformed headers (caller should catch as 400)
 * - Excludes q=0 entries
 * - Returns `*` when present
 * - Sorts by quality descending
 */
export function parseAcceptLanguage(header: string): ParsedAcceptLanguage {
  const all = Accept.languages(header)
  const acceptsAll = all.includes('*')
  const locales = all.filter((l) => l !== '*')
  return { locales, acceptsAll }
}

// =============================================================================
// Accept header parsing via @hapi/accept (RFC 9110 Section 12.5.1)
// =============================================================================

/** Determine the preferred media type from an Accept header via @hapi/accept. Throws on malformed. */
export function negotiateMediaType(acceptHeader: string, available: string[]): string | undefined {
  const result = Accept.mediaType(acceptHeader, available)
  return result || undefined
}

// =============================================================================
// Locale canonicalization
// =============================================================================

/**
 * Default locale canonicalizer: takes the first locale and returns its
 * primary language subtag.
 *
 * `['en-us', 'de-de']` → `['en']`
 * `['de-de']` → `['de']`
 * `[]` → `[]`
 */
export const defaultLocaleCanonicalizer: LocaleCanonicalizer = (requestedLocales) => {
  if (requestedLocales.length === 0) return []
  const primary = requestedLocales[0].split('-')[0]
  return [primary]
}

/**
 * Build a stable canonical cache key from a locale array.
 * Sorts, deduplicates, and joins with ','.
 */
export function buildLocaleKey(locales: string[]): string {
  return [...new Set(locales)].sort().join(',')
}

// =============================================================================
// RFC 4647 matching (via bcp-47-match)
// =============================================================================

function lookupMatches(range: string, availableTags: string[]): boolean {
  return lookup(availableTags, [range]) !== undefined
}

function lookupMatchesSet(range: string, loweredTags: Set<string>): boolean {
  return lookupMatches(range, [...loweredTags])
}

// =============================================================================
// Display array analysis (pre-computed for efficient locale checks)
// =============================================================================

interface DisplayArrayInfo {
  tags: Set<string>
  hasDefault: boolean
}

function analyzeDisplayArray(entries: Array<{ locale?: string }>): DisplayArrayInfo {
  const tags = new Set<string>()
  let hasDefault = false
  for (const e of entries) {
    if (e.locale) tags.add(e.locale.toLowerCase())
    else hasDefault = true
  }
  return { tags, hasDefault }
}

function localeMatchesInfo(locale: string, info: DisplayArrayInfo): boolean {
  return lookupMatchesSet(locale, info.tags) || info.hasDefault
}

function collectDisplayArrayInfos(metadata: CredentialMetadata): DisplayArrayInfo[] {
  const infos: DisplayArrayInfo[] = []

  if (metadata.display) infos.push(analyzeDisplayArray(metadata.display))

  if (metadata.claims) {
    for (const claim of metadata.claims) {
      if ('display' in claim) infos.push(analyzeDisplayArray(claim.display))
    }
  }

  if (metadata.transaction_data_types) {
    for (const tdType of Object.values(metadata.transaction_data_types)) {
      for (const claim of tdType.claims) {
        if ('display' in claim) infos.push(analyzeDisplayArray(claim.display))
      }
      for (const entries of Object.values(tdType.ui_labels)) {
        if (Array.isArray(entries)) infos.push(analyzeDisplayArray(entries))
      }
    }
  }

  return infos
}

// =============================================================================
// TS12 Section 3.5.4 — Locale resolvability
// =============================================================================

export function localeFullyResolves(locale: string, metadata: CredentialMetadata): boolean {
  return collectDisplayArrayInfos(metadata).every((info) => localeMatchesInfo(locale, info))
}

export function collectMetadataLocales(metadata: CredentialMetadata): string[] {
  const locales = new Set<string>()
  for (const info of collectDisplayArrayInfos(metadata)) {
    for (const tag of info.tags) locales.add(tag)
  }
  return [...locales]
}

export function deriveAllowedLocales(metadata: CredentialMetadata, logger?: { warn(message: string): void }): string[] {
  const infos = collectDisplayArrayInfos(metadata)

  const allLocales = new Set<string>()
  for (const info of infos) {
    for (const tag of info.tags) allLocales.add(tag)
  }

  const resolvable: string[] = []
  for (const locale of allLocales) {
    if (infos.every((info) => localeMatchesInfo(locale, info))) {
      resolvable.push(locale)
    } else {
      logger?.warn(
        `Locale '${locale}' appears in credential metadata but does not fully resolve per TS12 Section 3.5.4 — it is missing from at least one display array`
      )
    }
  }

  return resolvable
}

// =============================================================================
// Locale filtering against allow list
// =============================================================================

export function filterByAllowList(requestedLocales: string[], allowedLocales: string[]): string[] {
  return requestedLocales.filter((l) => lookupMatches(l, allowedLocales))
}

// =============================================================================
// Metadata locale filtering
// =============================================================================

export function filterMetadataByLocales(metadata: CredentialMetadata, locales: string[]): CredentialMetadata {
  const localeSet = new Set(locales.map((l) => l.toLowerCase()))

  function filterLocaleArray<T extends { locale?: string }>(entries: T[]): T[] {
    return entries.filter((e) => !e.locale || localeSet.has(e.locale.toLowerCase()))
  }

  function filterClaims(
    claims: Array<{ display?: Array<{ locale?: string }> } & Record<string, unknown>>
  ): typeof claims {
    return claims.map((claim) => {
      if (!claim.display) return claim
      return { ...claim, display: filterLocaleArray(claim.display) }
    })
  }

  const result = { ...metadata }

  if (result.display) {
    result.display = filterLocaleArray(result.display)
  }

  if (result.claims) {
    result.claims = filterClaims(result.claims) as typeof result.claims
  }

  if (result.transaction_data_types) {
    const filteredTypes: Record<string, unknown> = {}
    for (const [typeKey, typeValue] of Object.entries(result.transaction_data_types)) {
      const tdType = typeValue as {
        claims: Array<{ display?: Array<{ locale?: string }> } & Record<string, unknown>>
        ui_labels: Record<string, Array<{ locale?: string }>>
      } & Record<string, unknown>

      const filteredClaims = filterClaims(tdType.claims)

      const filteredUiLabels: Record<string, unknown> = {}
      for (const [labelKey, labelEntries] of Object.entries(tdType.ui_labels)) {
        filteredUiLabels[labelKey] = filterLocaleArray(labelEntries)
      }

      filteredTypes[typeKey] = { ...tdType, claims: filteredClaims, ui_labels: filteredUiLabels }
    }
    result.transaction_data_types = filteredTypes as CredentialMetadata['transaction_data_types']
  }

  return result
}
