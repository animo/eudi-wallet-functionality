/**
 * RFC 4647 Section 3.4 — Basic Lookup matching.
 *
 * Progressively truncates subtags from the end of `range` until an exact
 * case-insensitive match is found in `availableTags`.
 * When truncation leaves a single-character subtag at the end, that subtag
 * is also removed (it is an extension/private-use prefix per RFC 5646).
 *
 * Returns the original (un-lowered) tag from `availableTags`, or undefined.
 */
export function lookupLocale(range: string, availableTags: string[]): string | undefined {
  let current = range.toLowerCase()
  const lowered = availableTags.map((t) => t.toLowerCase())

  while (current) {
    const idx = lowered.indexOf(current)
    if (idx !== -1) return availableTags[idx]

    const dash = current.lastIndexOf('-')
    if (dash === -1) break

    current = current.substring(0, dash)

    // If the new trailing subtag is a single character, remove it too
    const nextDash = current.lastIndexOf('-')
    if (nextDash !== -1 && current.length - nextDash - 1 === 1) {
      current = current.substring(0, nextDash)
    }
  }

  return undefined
}

/**
 * TS12 Section 3.5.4 — Select a single entry from a locale-tagged array.
 *
 * 1. Apply RFC 4647 Lookup using `locale` as the range.
 * 2. If multiple entries match at the same truncation step, the first in
 *    array order wins.
 * 3. If no tag matches, fall back to the first entry that omits `locale`
 *    (the default entry per TS12 3.5.4).
 *
 * Returns undefined when no entry matches and no default exists.
 */
export function selectLocaleEntry<T extends { locale?: string }>(entries: T[], locale: string): T | undefined {
  const tagged = entries.filter((e): e is T & { locale: string } => e.locale !== undefined)
  const matched = lookupLocale(
    locale,
    tagged.map((e) => e.locale)
  )

  if (matched) {
    return tagged.find((e) => e.locale.toLowerCase() === matched.toLowerCase())
  }

  // Default entry: first entry without a locale field
  return entries.find((e) => e.locale === undefined)
}
