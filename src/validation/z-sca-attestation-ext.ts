import { z } from 'zod'

export const zScaTransactionDataTypeClaims = z.array(
  z.object({
    /** The path to the claim within the transaction payload. */
    path: z.array(z.string()),
    /** [ARF Annex 4] Localised display information for the claim. */
    display: z
      .array(
        z.object({
          /** Localised name of the claim (e.g., "Amount"). */
          name: z.string(),
          /** [ISO639-1] Language code (e.g., "en"). */
          locale: z.string().optional(),
          /** [RFC2397] Resolvable or Data URL of the claim icon. */
          logo: z.string().optional(),
        })
      )
      .min(1),
  })
)

export const zScaTransactionDataTypeUiLabels = z
  .object({
    /**
     * [REQUIRED] Label for the confirmation (consent) button.
     * Max length: 30 characters.
     */
    affirmative_action_label: z
      .array(
        z.object({
          /** [RFC5646] Language identifier (e.g., "en", "fr-CA"). */
          locale: z.string(),
          /** Localised string value. Max length: 30 chars. */
          value: z.string().max(30),
        })
      )
      .min(1),

    /**
     * [OPTIONAL] Label for the denial (cancel) button.
     * Max length: 30 characters.
     */
    denial_action_label: z
      .array(
        z.object({
          /** [RFC5646] Language identifier. */
          locale: z.string(),
          /** Localised string value. Max length: 30 chars. */
          value: z.string().max(30),
        })
      )
      .min(1)
      .optional(),

    /**
     * [OPTIONAL] Title/headline for the transaction confirmation screen.
     * Max length: 50 characters.
     */
    transaction_title: z
      .array(
        z.object({
          /** [RFC5646] Language identifier. */
          locale: z.string(),
          /** Localised string value. Max length: 50 chars. */
          value: z.string().max(50),
        })
      )
      .min(1)
      .optional(),

    /**
     * [OPTIONAL] Security hint to be displayed to the User.
     * Max length: 250 characters.
     */
    security_hint: z
      .array(
        z.object({
          /** [RFC5646] Language identifier. */
          locale: z.string(),
          /** Localised string value. Max length: 250 chars. */
          value: z.string().max(250),
        })
      )
      .min(1)
      .optional(),
  })
  .catchall(
    // [TS12] "Additional UI elements identifiers MAY be defined"
    z.array(
      z.object({
        locale: z.string(),
        value: z.string(),
      })
    )
  )

/**
 * @name zScaAttestationExt
 * @version EUDI TS12 v1.0 (05 December 2025)
 * @description Defines metadata for SCA Attestations, including transaction types and UI localization.
 * @see [EUDI TS12, Section 3] for VC Type Metadata requirements.
 * @see [EUDI TS12, Section 4.1] for Metadata structure.
 */
export const zScaAttestationExt = z.object({
  /**
   * [TS12 Section 3] Category the attestation belongs to.
   * MUST be 'urn:eu:europa:ec:eudi:sua:sca' for SCA Attestations.
   */
  category: z.string().optional(),
  transaction_data_types: z.array(
    z.intersection(
      z.object({
        /** [TS12 4.1] URI (URL or URN) that references a [JSON Schema] defining the structure of the `payload` object within the `transaction_data` object. */
        type: z.string(),
        /** [TS12 4.1] Hash of the document referenced by `type`. MUST be present if `type` is a URL and integrity protection is desired. */
        'type#integrity': z.string().optional(),
        /** [TS12 4.1] A string that can be used to further categorize the transaction type. */
        subtype: z.string().optional(),
      }),
      z.intersection(
        z.union([
          z.object({
            /** [TS12 3.3.2] Transaction Data Claim Metadata. MUST NOT be used if claims_uri is present. */
            claims: zScaTransactionDataTypeClaims,
          }),
          z.object({
            /** [TS12 3.3.2] URI referencing an external claims metadata document. MUST NOT be used if claims is present. */
            claims_uri: z.url(),
            'claims_uri#integrity': z.string().optional(),
          }),
        ]),
        z.union([
          z.object({
            /** [TS12 3.3.3] Localised UI element values. MUST NOT be used if ui_labels_uri is present. */
            ui_labels: zScaTransactionDataTypeUiLabels,
          }),
          z.object({
            /** [TS12 3.3.3] URI referencing external UI labels. MUST NOT be used if ui_labels is present. */
            ui_labels_uri: z.string().url(),
            'ui_labels_uri#integrity': z.string().optional(),
          }),
        ])
      )
    )
  ),
})

export type ZScaAttestationExt = z.infer<typeof zScaAttestationExt>
