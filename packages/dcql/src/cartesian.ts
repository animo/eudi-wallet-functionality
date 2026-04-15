/**
 * Build the set of ID pairs that co-occur in at least one alternative.
 * Keys are normalized as `min\0max` for consistent lookup.
 */
export function buildCoOccurrences(alternatives: string[][]): Set<string> {
  const pairs = new Set<string>()
  for (const alt of alternatives) {
    for (let i = 0; i < alt.length; i++) {
      for (let j = i + 1; j < alt.length; j++) {
        pairs.add(pairKey(alt[i], alt[j]))
      }
    }
  }
  return pairs
}

function pairKey(a: string, b: string): string {
  return a < b ? `${a}\0${b}` : `${b}\0${a}`
}

/**
 * Check if two IDs co-occur in any alternative.
 */
function coOccurs(a: string, b: string, pairs: Set<string>): boolean {
  return pairs.has(pairKey(a, b))
}

export interface SlotDecomposition {
  ids: string[]
  optional: boolean
}

/**
 * Assign IDs to slots using co-occurrence analysis.
 *
 * For a valid cartesian product the co-occurrence graph is complete multipartite,
 * so greedy assignment always finds the correct partition:
 * - IDs that co-occur must be in different slots.
 * - IDs that never co-occur are placed in the same slot.
 *
 * IDs are processed in first-appearance order across alternatives,
 * so slot order reflects RP preference per TS12 Section 3.4.
 */
export function assignSlots(alternatives: string[][]): SlotDecomposition[] {
  const seen = new Set<string>()
  const ordered: string[] = []
  for (const alt of alternatives) {
    for (const id of alt) {
      if (!seen.has(id)) {
        seen.add(id)
        ordered.push(id)
      }
    }
  }

  const coOccurrences = buildCoOccurrences(alternatives)
  const slots: string[][] = []
  const slotOf = new Map<string, number>()

  for (const id of ordered) {
    let placed = false
    for (let s = 0; s < slots.length; s++) {
      if (slots[s].every((existing) => !coOccurs(id, existing, coOccurrences))) {
        slots[s].push(id)
        slotOf.set(id, s)
        placed = true
        break
      }
    }
    if (!placed) {
      slotOf.set(id, slots.length)
      slots.push([id])
    }
  }

  return slots.map((ids) => ({
    ids,
    optional: alternatives.some((alt) => !ids.some((id) => alt.includes(id))),
  }))
}

/**
 * Generate the cartesian product of slots.
 * Optional slots contribute a ∅ choice (omitted from the resulting tuple).
 */
export function generateCartesianProduct(slots: SlotDecomposition[]): string[][] {
  if (slots.length === 0) return [[]]

  const [first, ...rest] = slots
  const restProduct = generateCartesianProduct(rest)
  const choices: (string | null)[] = first.optional ? [...first.ids, null] : [...first.ids]
  const result: string[][] = []

  for (const choice of choices) {
    for (const tail of restProduct) {
      result.push(choice === null ? [...tail] : [choice, ...tail])
    }
  }

  return result
}

/** Normalize an alternative to a canonical string for set comparison. */
function normalizeAlt(alt: string[]): string {
  return [...alt].sort().join('\0')
}

/**
 * Verify that a set of alternatives equals the cartesian product of the given slots.
 */
export function verifyCartesianProduct(slots: SlotDecomposition[], alternatives: string[][]): boolean {
  const expected = generateCartesianProduct(slots)
  if (expected.length !== alternatives.length) return false

  const expectedSet = new Set(expected.map(normalizeAlt))
  return alternatives.every((alt) => expectedSet.has(normalizeAlt(alt)))
}

/**
 * TS12 Section 3.4 — Decompose alternatives into slots and verify transposability.
 *
 * Returns the slot decomposition if the alternatives form a valid cartesian product,
 * or `undefined` if they do not (not transposable).
 */
export function decomposeTransposable(alternatives: string[][]): SlotDecomposition[] | undefined {
  if (alternatives.length === 0) return []

  const slots = assignSlots(alternatives)
  if (!verifyCartesianProduct(slots, alternatives)) return undefined

  return slots
}

/**
 * Best-effort decomposition for non-SCA alternatives.
 *
 * Uses the first alternative as the reference structure. Subsequent alternatives
 * that fit the slot pattern are included; those that don't are skipped.
 * Returns the largest valid cartesian product found.
 */
export function bestEffortDecompose(alternatives: string[][]): SlotDecomposition[] {
  if (alternatives.length === 0) return []

  // Try exact decomposition first
  const exact = decomposeTransposable(alternatives)
  if (exact) return exact

  // Fall back: use first alternative as structure, greedily add fitting alternatives
  const first = alternatives[0]
  const slots: string[][] = first.map((id) => [id])
  const slotOf = new Map<string, number>()
  for (let i = 0; i < first.length; i++) {
    slotOf.set(first[i], i)
  }

  const accepted = [first]

  for (const alt of alternatives.slice(1)) {
    const used = new Set<number>()
    let fits = true

    for (const id of alt) {
      const s = slotOf.get(id)
      if (s !== undefined) {
        if (used.has(s)) {
          fits = false
          break
        }
        used.add(s)
      } else {
        // New ID: find an unused slot with no co-occurrence conflict
        let placed = false
        for (let s = 0; s < slots.length; s++) {
          if (!used.has(s) && slots[s].every((e) => !accepted.some((a) => a.includes(e) && a.includes(id)))) {
            slotOf.set(id, s)
            slots[s].push(id)
            used.add(s)
            placed = true
            break
          }
        }
        if (!placed) {
          fits = false
          break
        }
      }
    }

    if (fits) accepted.push(alt)
  }

  return slots.map((ids) => ({
    ids,
    optional: accepted.some((alt) => !ids.some((id) => alt.includes(id))),
  }))
}
