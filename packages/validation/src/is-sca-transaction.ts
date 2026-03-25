import { z } from 'zod'

/**
 * The URN prefix that identifies SCA transaction data types per TS12 Section 3.1 and 3.3.
 *
 * @see TS12 Section 3.1 — SCA Attestation Identification
 * @see TS12 Section 3.3 — Transactional Data Discovery and Validation
 */
export const SCA_TRANSACTION_TYPE_PREFIX = 'urn:eudi:sca:'

/** Template literal type for SCA transaction type URNs. */
export type ScaTransactionType = `urn:eudi:sca:${string}`

/** Zod schema that parses and infers as `urn:eudi:sca:${string}`. */
export const zScaTransactionType = z.templateLiteral([z.literal(SCA_TRANSACTION_TYPE_PREFIX), z.string()])

/**
 * Type guard: checks whether a transaction data entry's `type` is SCA-targeted
 * by verifying the `urn:eudi:sca:` prefix.
 *
 * Per TS12 Section 3.3: "the Wallet Unit SHALL determine whether the entry
 * is SCA-targeted by checking whether its `type` starts with the prefix `urn:eudi:sca:`."
 */
export function isScaTransactionType(type: string): type is ScaTransactionType {
  return type.startsWith(SCA_TRANSACTION_TYPE_PREFIX)
}

/**
 * Checks whether credential metadata describes an SCA Attestation
 * by verifying that `transaction_data_types` contains at least one key
 * starting with the `urn:eudi:sca:` prefix.
 *
 * Per TS12 Section 3.1: "If the `transaction_data_types` object contains at least
 * one key starting with the prefix `urn:eudi:sca:`, the Wallet Unit SHALL process
 * the attestation as an SCA Attestation."
 */
export function isScaAttestationMetadata(metadata: { transaction_data_types?: Record<string, unknown> }): boolean {
  if (!metadata.transaction_data_types) return false
  return Object.keys(metadata.transaction_data_types).some(isScaTransactionType)
}
