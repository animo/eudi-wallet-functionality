import { z } from 'zod'

/**
 * **OpenID4VP Common Fields**
 * Fields required by the transport protocol.
 */
export const zBaseTransaction = z.object({
  /**
   * **Type**
   * REQUIRED. String that identifies the type of transaction data.
   * @source OpenID4VP Section 5.1
   */
  type: z.string(),
  /**
   * **Credential IDs**
   * REQUIRED. Non-empty array of strings each referencing a Credential requested
   * by the Verifier (via DCQL `id` or PEX) that authorizes this transaction.
   * @source OpenID4VP Section 5.1 "transaction_data"
   */
  credential_ids: z.tuple([z.string()]).rest(z.string()),

  /**
   * **Transaction Data Hashes Algorithm**
   * OPTIONAL. Array of hash algorithms (e.g. `["sha-256"]`).
   * @source OpenID4VP Appendix B.3.3.1
   */
  transaction_data_hashes_alg: z.tuple([z.string()]).rest(z.string()).optional(),
})
