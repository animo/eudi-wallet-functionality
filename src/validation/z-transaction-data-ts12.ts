import { z } from 'zod'
import { zBaseTransaction } from './z-transaction-data-common'

// =============================================================================
// 1. TS12 PAYLOAD SCHEMAS (Nested Objects)
// Source: EUDI TS12 Section 4.3 "Payload Object"
// =============================================================================

/**
 * **TS12 Payment Payload**
 * * The business data strictly defined for Payments.
 * * @see EUDI TS12 Section 4.3.1 "Payment Confirmation"
 */
export const zPaymentPayload = z
  .object({
    /**
     * **Transaction ID**
     * Unique identifier of the Relying Party's interaction with the User.
     * @example "8D8AC610-566D-4EF0-9C22-186B2A5ED793"
     */
    transaction_id: z.string().min(1).max(36).describe("Unique identifier of the Relying Party's interaction"),

    /**
     * **Date Time**
     * ISO 8601 date and time when the Relying Party started to interact with the User.
     * @example "2025-11-13T20:20:39+00:00"
     */
    date_time: z.iso.datetime().optional(),

    /**
     * **Payee**
     * Object holding the Payee (Merchant) details.
     */
    payee: z.object({
      /**
       * **Payee Name**
       * Name of the Payee to whom the payment is being made.
       */
      name: z.string(),

      /**
       * **Payee ID**
       * An identifier of the Payee understood by the payment system.
       */
      id: z.string(),

      /**
       * **Logo**
       * Resolvable URL or Data URI (RFC 2397) of the Payee logo.
       */
      logo: z.url().optional(),

      /**
       * **Website**
       * Resolvable URL of the Payee's website.
       */
      website: z.url().optional(),
    }),

    /**
     * **Currency**
     * 3-letter currency code (ISO 4217).
     */
    currency: z.string().regex(/^[A-Z]{3}$/),

    /**
     * **Amount**
     * The monetary value of the transaction.
     */
    amount: z.number(),

    /**
     * **Amount Estimated**
     */
    amount_estimated: z.boolean().optional(),

    /**
     * **Amount Earmarked**
     */
    amount_earmarked: z.boolean().optional(),

    /**
     * **SCT Inst**
     */
    sct_inst: z.boolean().optional(),

    /**
     * **PISP Details**
     * If present, indicates that the payment is being facilitated by a PISP.
     */
    pisp: z
      .object({
        /**
         * **Legal Name**
         * Legal name of the PISP.
         */
        legal_name: z.string(),

        /**
         * **Brand Name**
         * Brand name of the PISP.
         */
        brand_name: z.string(),

        /**
         * **Domain Name**
         * Domain name of the PISP as secured by the eIDAS QWAC certificate.
         */
        domain_name: z.string(),
      })
      .optional(),

    /**
     * **Execution Date**
     * ISO 8601 date of the payment's execution. MUST NOT be present when recurrence is present.
     * MUST NOT lie in the past.
     */
    execution_date: z.iso
      .datetime()
      .optional()
      .refine(
        (date) => {
          if (!date) return true
          return new Date(date) >= new Date()
        },
        { message: 'Execution date must not be in the past' }
      ),

    /**
     * **Recurrence**
     * Details for recurring payments.
     */
    recurrence: z
      .object({
        /**
         * **Start Date**
         * ISO 8601 date when the recurrence starts.
         */
        start_date: z.iso.datetime().optional(),

        /**
         * **End Date**
         * ISO 8601 date when the recurrence ends.
         */
        end_date: z.iso.datetime().optional(),

        /**
         * **Number**
         */
        number: z.number().int().optional(),

        /**
         * **Frequency**
         * ISO 20022 Frequency Code.
         */
        frequency: z.enum([
          'INDA',
          'DAIL',
          'WEEK',
          'TOWK',
          'TWMN',
          'MNTH',
          'TOMN',
          'QUTR',
          'FOMN',
          'SEMI',
          'YEAR',
          'TYEA',
        ]),

        /**
         * **MIT Options (Merchant Initiated Transaction)**
         */
        mit_options: z
          .object({
            /**
             * **Amount Variable**
             * If true, future amounts may vary.
             */
            amount_variable: z.boolean().optional(),

            /**
             * **Minimum Amount**
             * Minimum expected amount for future transactions.
             */
            min_amount: z.number().optional(),

            /**
             * **Maximum Amount**
             */
            max_amount: z.number().optional(),

            /**
             * **Total Amount**
             */
            total_amount: z.number().optional(),

            /**
             * **Initial Amount**
             */
            initial_amount: z.number().optional(),

            /**
             * **Initial Amount Number**
             */
            initial_amount_number: z.number().int().optional(),

            /**
             * **APR**
             */
            apr: z.number().optional(),
          })
          .optional(),
      })
      .optional(),
  })
  .refine((data) => !(data.recurrence && data.execution_date), {
    message: 'Execution date must not be present when recurrence is present',
    path: ['execution_date'],
  })

/**
 * **TS12 Generic Payload**
 * * @see EUDI TS12 Section 4.3.2
 */
export const zGenericPayload = z
  .object({
    /**
     * **Transaction ID**
     * Unique identifier of the Relying Party's interaction.
     * @example "8D8AC610-566D-4EF0-9C22-186B2A5ED793"
     */
    transaction_id: z.string().min(1).max(36),

    /**
     * **Payment Payload**
     * Nested payment object to leverage data for MITs.
     */
    payment_payload: zPaymentPayload.optional(),
  })
  .catchall(z.string().max(40).nullable())
  .refine(
    (data) => {
      return Object.keys(data).length <= 11
    },
    { message: 'Total number of properties is limited to 11' }
  )

export type Ts12PaymentPayload = z.infer<typeof zPaymentPayload>
export type Ts12GenericPayload = z.infer<typeof zGenericPayload>

export const URN_SCA_PAYMENT = 'urn:eudi:sca:payment:1'
export const URN_SCA_GENERIC = 'urn:eudi:sca:generic:1'

// =============================================================================
// 2. ROOT TRANSACTION DATA OBJECT (OpenID4VP Envelope)
// Source: OpenID4VP Section 5.1 & TS12 Section 4.3
// =============================================================================

export const zTs12PaymentTransaction = zBaseTransaction.extend({
  type: z.literal(URN_SCA_PAYMENT),
  subtype: z.undefined(),
  payload: zPaymentPayload,
})

export const zTs12GenericTransaction = zBaseTransaction.extend({
  type: z.literal(URN_SCA_GENERIC),
  subtype: z.string(),
  payload: zGenericPayload,
})

export const zTs12FallbackTransaction = zBaseTransaction.extend({
  subtype: z.string().optional(),
  payload: z.unknown(),
})

/**
 * **TS12 Transaction**
 * @see TS12 Section 4.3
 */
export const zTs12Transaction = z.union([zTs12PaymentTransaction, zTs12GenericTransaction, zTs12FallbackTransaction])

export type Ts12TransactionDataEntry = z.infer<typeof zTs12Transaction>
