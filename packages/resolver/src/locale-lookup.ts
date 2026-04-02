import { lookup } from 'bcp-47-match'

/** RFC 4647 Section 3.4 — Basic Lookup. Wraps bcp-47-match. */
export function lookupLocale(range: string, availableTags: string[]): string | undefined {
  return lookup(availableTags, [range]) || undefined
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
  const matched = lookup(
    tagged.map((e) => e.locale),
    [locale]
  )

  if (matched) {
    return tagged.find((e) => e.locale.toLowerCase() === matched.toLowerCase())
  }

  return entries.find((e) => e.locale === undefined)
}
