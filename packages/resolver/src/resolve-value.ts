import type { ClaimsPathComponent } from '@animo-id/eudi-wallet-ts12-validation'
import type { ResolvedValue, ValueTypeResolvers } from './types'

/**
 * [OID4VCI] Appendix B — Walk a Claims Path Pointer through a nested structure.
 *
 * Path component semantics:
 * - `string`: select a key in an object
 * - `number` (non-negative integer): select an array index
 * - `null`: select ALL elements of an array (wildcard)
 *
 * When `null` is encountered on an array, the remaining path is applied
 * to each element and results are collected into an array.
 *
 * A negative integer aborts and returns `undefined` per OID4VCI processing rules.
 */
export function getPayloadValue(payload: Record<string, unknown>, path: ClaimsPathComponent[]): unknown | undefined {
  return walkPath(payload, path, 0)
}

function walkPath(current: unknown, path: ClaimsPathComponent[], index: number): unknown | undefined {
  if (index >= path.length) return current
  if (current === null || current === undefined) return undefined

  const key = path[index]

  // null = wildcard: map over all array elements
  if (key === null) {
    if (!Array.isArray(current)) return undefined
    const results = current.map((item) => walkPath(item, path, index + 1))
    return results.every((r) => r === undefined) ? undefined : results
  }

  // number = array index (negative integers abort per OID4VCI)
  if (typeof key === 'number') {
    if (!Array.isArray(current)) return undefined
    if (key < 0 || key >= current.length) return undefined
    return walkPath(current[key], path, index + 1)
  }

  // string = object key
  if (typeof current === 'object' && !Array.isArray(current)) {
    return walkPath((current as Record<string, unknown>)[key], path, index + 1)
  }

  return undefined
}

/**
 * Resolve a raw value through the appropriate value type resolver.
 *
 * - No `valueType`: the value passes through as plain text → `{ type: undefined, value: rawValue }`.
 * - `valueType` present but no resolver registered: unsupported → `undefined`.
 * - Resolver returns `undefined`: invalid value → `undefined`.
 */
export function resolveTypedValue(
  rawValue: unknown,
  valueType: string | undefined,
  resolvers: ValueTypeResolvers,
  locale: string
): ResolvedValue | undefined {
  if (!valueType) {
    return { type: undefined, value: rawValue }
  }

  const resolver = resolvers[valueType]
  if (!resolver) return undefined

  const resolved = resolver(rawValue as string, locale)
  if (resolved === undefined) return undefined

  return { type: valueType, value: resolved }
}
