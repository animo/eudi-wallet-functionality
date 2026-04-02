import { z } from 'zod'
import { zBaseTransaction } from './z-transaction-data-common'

/**
 * TS12 Section 4.2 — SCA Transaction Data Entry.
 *
 * Extends the [OID4VP] transaction_data object with a `payload` parameter.
 * The `type` field is a plain string — runtime routing via `ScaTransactionTypeMatcher`
 * determines whether an entry is SCA-compatible (different standards use different
 * URN prefixes, e.g. `urn:eudi:sca:`, `urn:paso:sca:`).
 *
 * The `payload` is a generic JSON object whose structure is defined by the `claims`
 * metadata in the credential's `transaction_data_types` entry for the matching `type`.
 */
export const zScaTransactionDataEntry = zBaseTransaction.extend({
  /** Transaction data type identifier (e.g. 'urn:eudi:sca:...'). */
  type: z.string(),
  /** REQUIRED. A JSON object containing the details for the transaction. */
  payload: z.record(z.string(), z.unknown()),
})

export type ScaTransactionDataEntry = z.infer<typeof zScaTransactionDataEntry>
