import type { ClaimMetadata, UiLabelEntry } from '@animo-id/eudi-wallet-ts12-validation'
import { selectLocaleEntry } from './locale-lookup'
import { getPayloadValue, resolveTypedValue } from './resolve-value'
import type { ResolvedValue, ValueTypeResolvers } from './types'

/**
 * TS12 Section 3.5.3 — Placeholder interpolation.
 *
 * Replaces `{<index>}` placeholders with formatted claim values:
 * 1. Look up the claim at the zero-based index in the `claims` array.
 *    Out-of-bounds indices are kept as literal text.
 * 2. Resolve the claim's value from the payload using its `path`.
 *    If absent, the entire locale entry must be discarded → returns `undefined`.
 * 3. Format the value according to the claim's `value_type`.
 * 4. Replace the placeholder with the formatted string.
 */
export function interpolatePlaceholders(
  template: string,
  claims: ClaimMetadata[],
  payload: Record<string, unknown>,
  resolvers: ValueTypeResolvers,
  locale: string
): string | undefined {
  let discarded = false

  const result = template.replace(/\{(\d+)\}/g, (_match, indexStr: string) => {
    const index = Number.parseInt(indexStr, 10)

    if (index >= claims.length) return _match // out of bounds → literal

    const claim = claims[index]
    const rawValue = getPayloadValue(payload, claim.path)
    if (rawValue === undefined) {
      discarded = true
      return ''
    }

    const valueType = 'value_type' in claim ? (claim as { value_type?: string }).value_type : undefined
    const resolved = resolveTypedValue(rawValue, valueType, resolvers, locale)
    if (!resolved) {
      discarded = true
      return ''
    }

    return String(resolved.value)
  })

  return discarded ? undefined : result
}

/**
 * Resolve a single UI label for a given locale.
 *
 * Selects the best matching locale entry, interpolates placeholders,
 * then applies the entry's own `value_type` to the resulting string.
 *
 * If the selected entry is discarded (placeholder references a missing claim),
 * falls back to the default entry (no locale) which always matches any locale.
 * If that also fails → `undefined` (try next locale in priority list).
 */
export function resolveUiLabel(
  entries: UiLabelEntry[],
  locale: string,
  claims: ClaimMetadata[],
  payload: Record<string, unknown>,
  resolvers: ValueTypeResolvers
): ResolvedValue | undefined {
  const selected = selectLocaleEntry(entries, locale)
  if (!selected) return undefined

  const result = tryResolveEntry(selected, claims, payload, resolvers, locale)
  if (result) return result

  // Selected entry was discarded — try the default entry (no locale, always valid)
  const defaultEntry = entries.find((e) => e.locale === undefined)
  if (defaultEntry && defaultEntry !== selected) {
    return tryResolveEntry(defaultEntry, claims, payload, resolvers, locale)
  }

  return undefined
}

/**
 * Attempt to resolve a single UI label entry: interpolate placeholders,
 * then apply the entry's `value_type` to the whole string.
 */
function tryResolveEntry(
  entry: UiLabelEntry,
  claims: ClaimMetadata[],
  payload: Record<string, unknown>,
  resolvers: ValueTypeResolvers,
  locale: string
): ResolvedValue | undefined {
  const interpolated = interpolatePlaceholders(entry.value, claims, payload, resolvers, locale)
  if (interpolated === undefined) return undefined

  return resolveTypedValue(interpolated, entry.value_type, resolvers, locale)
}

/**
 * Resolve all UI labels in the catalogue.
 *
 * The `affirmative_action_label` is required — if it fails, returns `undefined`.
 * Optional labels that fail are omitted from the output.
 */
export function resolveAllUiLabels(
  uiLabels: Record<string, UiLabelEntry[]>,
  locale: string,
  claims: ClaimMetadata[],
  payload: Record<string, unknown>,
  resolvers: ValueTypeResolvers
): Record<string, ResolvedValue> | undefined {
  const resolved: Record<string, ResolvedValue> = {}

  for (const [key, entries] of Object.entries(uiLabels)) {
    if (!Array.isArray(entries)) continue

    const result = resolveUiLabel(entries, locale, claims, payload, resolvers)

    if (key === 'affirmative_action_label' && !result) return undefined

    if (result) {
      resolved[key] = result
    }
  }

  // affirmative_action_label must be present
  if (!resolved.affirmative_action_label) return undefined

  return resolved
}
