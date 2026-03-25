import { z } from 'zod'
import { zBaseTransaction } from './z-transaction-data-common'

/**
 * **Funke (German) QES Authorization Data**
 * * Profile used by the SPRIND/Bundesdruckerei EUDI Wallet.
 * * This type bridges OpenID4VP with ETSI TS 119 432 (Remote Signing).
 * * @see German National EUDI Wallet Architecture (Appendix 07)
 */
export const zFunkeQesTransaction = zBaseTransaction.extend({
  /**
   * **Signature Qualifier**
   * The level of signature required.
   * @source ETSI TS 119 432
   */
  signatureQualifier: z
    .enum(['eu_eidas_qes', 'eu_eidas_aes'])
    .describe('eu_eidas_qes (Qualified) or eu_eidas_aes (Advanced)'),

  /**
   * **Document Digests**
   * List of document hashes to be signed (DTBS - Data To Be Signed).
   * @source ETSI TS 119 432
   */
  documentDigests: z
    .array(
      z.object({
        /**
         * **Label**
         * Human-readable filename displayed to the user.
         */
        label: z.string().describe("Filename (e.g. 'Contract.pdf')"),

        /**
         * **Hash**
         * Base64 encoded hash of the document.
         */
        hash: z.string().describe('Base64 encoded hash'),

        /**
         * **Hash Algorithm OID**
         * Object Identifier for the hash algorithm.
         */
        hashAlgorithmOID: z.string().optional().describe('OID of the hash algorithm'),
      })
    )
    .min(1),
})
export type FunkeQesTransactionDataEntry = z.infer<typeof zFunkeQesTransaction>
