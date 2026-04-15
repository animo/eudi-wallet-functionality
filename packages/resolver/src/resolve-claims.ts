import type { ClaimMetadata, ClaimsPathComponent } from '@animo-id/eudi-wallet-ts12-validation'
import { selectLocaleEntry } from './locale-lookup'
import { getPayloadValue, resolveTypedValue } from './resolve-value'
import type { ResolvedClaim, ValueTypeResolvers } from './types'

/** Narrow to the displayable variant of the ClaimMetadata union. */
function isDisplayable(claim: ClaimMetadata): claim is ClaimMetadata & { display: NonNullable<unknown> } {
  return 'display' in claim && Array.isArray((claim as Record<string, unknown>).display)
}

/**
 * TS12 Section 3.5.2 — Filter out display entries whose `display_type` is not
 * supported by the Wallet Unit (i.e. not present in the resolvers map).
 *
 * Entries without `display_type` (plain text) are always kept.
 */
export function filterSupportedDisplayEntries<T extends { display_type?: string }>(
  entries: T[],
  resolvers: ValueTypeResolvers
): T[] {
  return entries.filter((e) => !e.display_type || e.display_type in resolvers)
}

/**
 * TS12 Section 3.3 step 3 — Check that every mandatory claim is present in the payload.
 * Applies to all claims (displayable and internal).
 */
export function validateMandatoryClaims(claims: ClaimMetadata[], payload: Record<string, unknown>): boolean {
  for (const claim of claims) {
    if (claim.mandatory && getPayloadValue(payload, claim.path) === undefined) {
      return false
    }
  }
  return true
}

// =============================================================================
// Undeclared payload field validation
// =============================================================================

interface DeclaredTree {
  [key: string]: true | DeclaredTree
}

function buildDeclaredTree(claims: ClaimMetadata[]): DeclaredTree {
  const root: DeclaredTree = {}

  for (const claim of claims) {
    let node = root
    for (let i = 0; i < claim.path.length; i++) {
      const segment = claim.path[i]
      if (typeof segment !== 'string') break

      const isLast = i === claim.path.length - 1 || typeof claim.path[i + 1] !== 'string'
      const existing = node[segment]

      if (existing === true) break

      if (isLast) {
        node[segment] = true
      } else {
        if (!existing) {
          node[segment] = {}
        }
        node = node[segment] as DeclaredTree
      }
    }
  }

  return root
}

function validateObject(obj: Record<string, unknown>, tree: DeclaredTree): boolean {
  for (const key of Object.keys(obj)) {
    const declaration = tree[key]
    if (declaration === undefined) return false

    if (declaration === true) continue

    const value = obj[key]
    if (value !== null && typeof value === 'object' && !Array.isArray(value)) {
      if (!validateObject(value as Record<string, unknown>, declaration)) return false
    }
  }
  return true
}

/**
 * TS12 Section 3.3 step 3 — Check that the payload does not contain fields
 * not declared in the claims metadata.
 */
export function validateNoUndeclaredPayloadFields(claims: ClaimMetadata[], payload: Record<string, unknown>): boolean {
  const tree = buildDeclaredTree(claims)
  return validateObject(payload, tree)
}

// =============================================================================
// Wildcard (null) claim expansion — recursive multi-depth
// =============================================================================

/** Split a path at the first null: prefix (before), suffix (after). */
function splitAtFirstNull(
  path: ClaimsPathComponent[]
): { prefix: ClaimsPathComponent[]; suffix: ClaimsPathComponent[] } | undefined {
  const idx = path.indexOf(null)
  if (idx === -1) return undefined
  return { prefix: path.slice(0, idx), suffix: path.slice(idx + 1) }
}

/** Canonical key for grouping: path segments before the first null. */
function groupKey(path: ClaimsPathComponent[]): string {
  const idx = path.indexOf(null)
  const prefix = idx === -1 ? path : path.slice(0, idx)
  return prefix.map((p) => String(p)).join('\0')
}

/** Check if a path contains at least one null (wildcard). */
function hasWildcard(path: ClaimsPathComponent[]): boolean {
  return path.includes(null)
}

interface ExpandedClaim {
  claim: ClaimMetadata
  concretePath: ClaimsPathComponent[]
}

/**
 * Recursively expand wildcard claims, grouping at each wildcard level.
 *
 * Claims sharing the same prefix before their first `null` are grouped.
 * For each array index, the group's members are emitted together.
 * If a member's suffix still contains `null`, it is recursively expanded.
 *
 * Example with two levels:
 * ```
 * ["orders", null, "items", null, "name"]
 * ["orders", null, "items", null, "price"]
 * ["orders", null, "date"]
 * ```
 * With `orders: [{ date: "D1", items: [{name:"A",price:"1"},{name:"B",price:"2"}] },
 *                { date: "D2", items: [{name:"C",price:"3"}] }]`
 *
 * Expands to (outer first, inner grouped closest to leaf):
 * ```
 * ["orders", 0, "date"]
 * ["orders", 0, "items", 0, "name"]
 * ["orders", 0, "items", 0, "price"]
 * ["orders", 0, "items", 1, "name"]
 * ["orders", 0, "items", 1, "price"]
 * ["orders", 1, "date"]
 * ["orders", 1, "items", 0, "name"]
 * ["orders", 1, "items", 0, "price"]
 * ```
 */
export function expandClaims(
  claims: ClaimMetadata[],
  payload: Record<string, unknown>,
  pathPrefix: ClaimsPathComponent[] = []
): ExpandedClaim[] {
  // Separate wildcard and non-wildcard claims
  const wildcardClaims: Array<{ claim: ClaimMetadata; prefix: ClaimsPathComponent[]; suffix: ClaimsPathComponent[] }> =
    []
  const plainClaims: ClaimMetadata[] = []

  for (const claim of claims) {
    const split = splitAtFirstNull(claim.path)
    if (split) {
      wildcardClaims.push({ claim, prefix: split.prefix, suffix: split.suffix })
    } else {
      plainClaims.push(claim)
    }
  }

  // Group wildcard claims by their prefix before the first null
  type WildcardGroup = {
    prefix: ClaimsPathComponent[]
    members: Array<{ claim: ClaimMetadata; suffix: ClaimsPathComponent[] }>
  }
  const groups = new Map<string, WildcardGroup>()
  for (const wc of wildcardClaims) {
    const key = wc.prefix.map((p) => String(p)).join('\0')
    let group = groups.get(key)
    if (!group) {
      group = { prefix: wc.prefix, members: [] }
      groups.set(key, group)
    }
    group.members.push({ claim: wc.claim, suffix: wc.suffix })
  }

  // Emit in original claims array order
  const result: ExpandedClaim[] = []
  const emittedGroups = new Set<string>()

  for (const claim of claims) {
    if (!hasWildcard(claim.path)) {
      result.push({ claim, concretePath: [...pathPrefix, ...claim.path] })
      continue
    }

    const key = groupKey(claim.path)
    if (emittedGroups.has(key)) continue
    emittedGroups.add(key)

    const group = groups.get(key) as WildcardGroup
    const arrayPath = [...pathPrefix, ...group.prefix]
    const arrayValue = getPayloadValue(payload as Record<string, unknown>, arrayPath)
    const arrayLen = Array.isArray(arrayValue) ? arrayValue.length : 0

    for (let idx = 0; idx < arrayLen; idx++) {
      const indexPrefix = [...arrayPath, idx]

      // Check if any members still have wildcards in their suffix (multi-depth)
      const hasDeeper = group.members.some((m) => hasWildcard(m.suffix))

      if (hasDeeper) {
        // Recursively expand: create virtual claims with the suffix as their path
        const subClaims: ClaimMetadata[] = group.members.map((m) => ({
          ...m.claim,
          path: m.suffix,
        }))
        const subExpanded = expandClaims(subClaims, payload, indexPrefix)
        result.push(...subExpanded)
      } else {
        // Leaf level: emit each member with concrete path
        for (const member of group.members) {
          result.push({
            claim: member.claim,
            concretePath: [...indexPrefix, ...member.suffix],
          })
        }
      }
    }
  }

  return result
}

// =============================================================================
// Single claim resolution
// =============================================================================

/**
 * Resolve a single displayable claim at a specific path.
 */
export function resolveDisplayableClaim(
  claim: ClaimMetadata & { display: Array<{ name: string; locale?: string; display_type?: string }> },
  payload: Record<string, unknown>,
  locale: string,
  resolvers: ValueTypeResolvers,
  pathOverride?: ClaimsPathComponent[]
): ResolvedClaim | undefined {
  const supported = filterSupportedDisplayEntries(claim.display, resolvers)
  const entry = selectLocaleEntry(supported, locale)
  if (!entry) return undefined

  const label = resolveTypedValue(entry.name, entry.display_type, resolvers, locale)
  if (!label) return undefined

  const resolvePath = pathOverride ?? claim.path
  const rawValue = getPayloadValue(payload, resolvePath)
  const value = resolveTypedValue(rawValue, (claim as { value_type?: string }).value_type, resolvers, locale)
  if (!value) return undefined

  return { path: resolvePath, mandatory: claim.mandatory, label, value }
}

// =============================================================================
// Full claims resolution with wildcard expansion
// =============================================================================

/**
 * Resolve all displayable claims in array order, expanding wildcard groups.
 *
 * Wildcard (`null`) claims sharing the same prefix are grouped and expanded
 * per array index. Multi-depth wildcards are recursively expanded, with
 * inner wildcards grouped closest to leaf first.
 *
 * - Mandatory claims missing from the payload → `undefined`.
 * - Optional displayable claims absent from the payload are skipped.
 * - Preserves the claim order from the `claims` array (TS12 Section 3.5.1).
 */
export function resolveAllClaims(
  claims: ClaimMetadata[],
  payload: Record<string, unknown>,
  locale: string,
  resolvers: ValueTypeResolvers
): ResolvedClaim[] | undefined {
  if (!validateMandatoryClaims(claims, payload)) return undefined
  if (!validateNoUndeclaredPayloadFields(claims, payload)) return undefined

  const expanded = expandClaims(claims, payload)
  const resolved: ResolvedClaim[] = []

  for (const { claim, concretePath } of expanded) {
    if (!isDisplayable(claim)) continue

    const rawValue = getPayloadValue(payload, concretePath)
    if (rawValue === undefined) continue

    const displayClaim = claim as ClaimMetadata & {
      display: Array<{ name: string; locale?: string; display_type?: string }>
    }

    const result = resolveDisplayableClaim(displayClaim, payload, locale, resolvers, concretePath)
    if (!result) return undefined

    resolved.push(result)
  }

  return resolved
}
