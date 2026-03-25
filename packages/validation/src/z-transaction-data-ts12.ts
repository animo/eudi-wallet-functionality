import { z } from 'zod'
import { zScaTransactionType } from './is-sca-transaction'
import { zBaseTransaction } from './z-transaction-data-common'

/**
 * TS12 Section 4.2 — SCA Transaction Data Entry.
 *
 * Extends the [OID4VP] transaction_data object with a `payload` parameter.
 * The `type` MUST start with `urn:eudi:sca:`.
 *
 * The `payload` is a generic JSON object whose structure is defined by the `claims`
 * metadata in the credential's `transaction_data_types` entry for the matching `type`.
 * Payload validation against claims metadata is a separate processing step (Section 3.3 step 3).
 */
export const zScaTransactionDataEntry = zBaseTransaction.extend({
  /** Infers as `urn:eudi:sca:${string}`. */
  type: zScaTransactionType,
  /** REQUIRED. A JSON object containing the details for the transaction. */
  payload: z.record(z.string(), z.unknown()),
})

export type ScaTransactionDataEntry = z.infer<typeof zScaTransactionDataEntry>
