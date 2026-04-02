/**
 * A predicate that determines whether a transaction data type string
 * identifies an SCA-compatible transaction.
 *
 * Different standards use different URN prefixes (e.g., `urn:eudi:sca:`,
 * `urn:paso:sca:`). The predicate is fully configurable — callers decide
 * what constitutes an SCA type.
 */
export type ScaTransactionTypeMatcher = (type: string) => boolean

/**
 * Create an SCA type matcher that matches one or more URN prefixes.
 *
 * @example
 * ```ts
 * const matcher = createScaTypeMatcher('urn:eudi:sca:')
 *
 * // Multiple prefixes
 * const multi = createScaTypeMatcher('urn:eudi:sca:', 'urn:other:sca:')
 * ```
 */
export function createScaTypeMatcher(...prefixes: [string, ...string[]]): ScaTransactionTypeMatcher {
  return (type: string) => prefixes.some((prefix) => type.startsWith(prefix))
}

/**
 * Default SCA type matcher — matches the `urn:eudi:sca:` prefix per TS12.
 *
 * Use `createScaTypeMatcher` to build matchers for additional prefixes.
 */
export const defaultScaTypeMatcher: ScaTransactionTypeMatcher = createScaTypeMatcher('urn:eudi:sca:')

/**
 * Checks whether credential metadata describes an SCA Attestation
 * by verifying that `transaction_data_types` contains at least one key
 * recognized by the given matcher.
 *
 * @param matcher - Predicate to check type strings. Defaults to `defaultScaTypeMatcher`.
 */
export function isScaAttestationMetadata(
  metadata: { transaction_data_types?: Record<string, unknown> },
  matcher: ScaTransactionTypeMatcher = defaultScaTypeMatcher
): boolean {
  if (!metadata.transaction_data_types) return false
  return Object.keys(metadata.transaction_data_types).some(matcher)
}
