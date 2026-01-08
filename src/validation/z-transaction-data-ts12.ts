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
 * **TS12 Login / Risk Payload**
 * * @see EUDI TS12 Section 4.3.2
 */
export const zLoginPayload = z.object({
  /**
   * **Transaction ID**
   * Unique identifier of the Relying Party's interaction.
   * @example "8D8AC610-566D-4EF0-9C22-186B2A5ED793"
   */
  transaction_id: z.string().min(1).max(36),

  /**
   * **Date Time**
   * @example "2025-11-13T20:20:39+00:00"
   */
  date_time: z.iso.datetime().optional(),

  /**
   * **Service**
   * Name of the service triggering the operation (e.g. "Superbank Online").
   * @example "Superbank Onlinebanking"
   */
  service: z.string().max(100).optional(),

  /**
   * **Action**
   * Description of the action (e.g. "Log in", "Change limit").
   * @example "Login to your online account."
   */
  action: z.string().max(140).describe('Description of the action to be authorized'),
})

/**
 * **TS12 Account Access Payload**
 * * @see EUDI TS12 Section 4.3.3
 */
export const zAccountAccessPayload = z.object({
  /**
   * **Transaction ID**
   * @example "8D8AC610-566D-4EF0-9C22-186B2A5ED793"
   */
  transaction_id: z.string().min(1).max(36),

  /**
   * **Date Time**
   * @example "2025-11-13T20:20:39+00:00"
   */
  date_time: z.iso.datetime().optional(),

  /**
   * **AISP Details**
   * If present, indicates access facilitated by an AISP.
   */
  aisp: z
    .object({
      legal_name: z.string(),
      brand_name: z.string(),
      domain_name: z.string(),
    })
    .optional(),

  /**
   * **Description**
   * Description of the data access the user is agreeing to.
   * @example "Grant access to the account's data."
   */
  description: z.string().max(140).optional(),
})

/**
 * **TS12 E-Mandate Payload**
 * * @see EUDI TS12 Section 4.3.4
 */
export const zEMandatePayload = z
  .object({
    /**
     * **Transaction ID**
     * @example "8D8AC610-566D-4EF0-9C22-186B2A5ED793"
     */
    transaction_id: z.string().min(1).max(36),

    /**
     * **Date Time**
     * @example "2025-11-13T20:20:39+00:00"
     */
    date_time: z.iso.datetime().optional(),

    /**
     * **Start Date**
     * When the mandate becomes valid.
     * @example "2025-11-13T20:20:39+00:00"
     */
    start_date: z.iso.datetime().optional(),

    /**
     * **End Date**
     * When the mandate expires.
     * @example "2025-12-13T20:20:39+00:00"
     */
    end_date: z.iso.datetime().optional(),

    /**
     * **Reference Number**
     * E.g. Mandate Reference Number.
     * @example "A-98765"
     */
    reference_number: z.string().min(1).max(50).optional(),

    /**
     * **Creditor ID**
     * SEPA Creditor Identifier.
     * @example "FR14ZZZ001122334455"
     */
    creditor_id: z.string().min(1).max(50).optional(),

    /**
     * **Purpose**
     * Mandate text. Required if payment_payload is missing.
     * @example "Pay monthly bill"
     */
    purpose: z.string().max(1000).optional(),

    /**
     * **Payment Payload**
     * Nested payment object to leverage data for MITs.
     */
    payment_payload: zPaymentPayload.optional(),
  })
  .refine((data) => data.payment_payload || data.purpose, {
    message: 'Purpose is required if payment_payload is missing',
    path: ['purpose'],
  })

export type Ts12AccountAccessPayload = z.infer<typeof zAccountAccessPayload>
export type Ts12EMandatePayload = z.infer<typeof zEMandatePayload>
export type Ts12LoginPayload = z.infer<typeof zLoginPayload>
export type Ts12PaymentPayload = z.infer<typeof zPaymentPayload>

export const URN_SCA_PAYMENT = 'urn:eudi:sca:payment:1'
export const URN_SCA_LOGIN_RISK = 'urn:eudi:sca:login_risk_transaction:1'
export const URN_SCA_ACCOUNT_ACCESS = 'urn:eudi:sca:account_access:1'
export const URN_SCA_EMANDATE = 'urn:eudi:sca:emandate:1'

// =============================================================================
// 2. ROOT TRANSACTION DATA OBJECT (OpenID4VP Envelope)
// Source: OpenID4VP Section 5.1 & TS12 Section 4.3
// =============================================================================

/**
 * **TS12 Transaction**
 * @see TS12 Section 4.3
 */
export const zTs12Transaction = zBaseTransaction.extend({
  payload: z.union([zPaymentPayload, zLoginPayload, zAccountAccessPayload, zEMandatePayload, z.unknown()]),
})
export type Ts12TransactionDataEntry = z.infer<typeof zTs12Transaction>
