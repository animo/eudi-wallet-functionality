import { z } from 'zod'

/**
 * TS12 Section 3.5.2 — Claim metadata display entry.
 *
 * Per Section 3.5.4, entries that omit `locale` are default entries.
 * Uses `name` per [OID4VCI] Appendix B.2.
 */
export const zClaimDisplayEntry = z.object({
  name: z.string(),
  locale: z.string().optional(),
  /** How the Wallet Unit SHALL format the `name` text for display. */
  display_type: z.string().optional(),
})
export type ClaimDisplayEntry = z.infer<typeof zClaimDisplayEntry>

/**
 * [OID4VCI] Appendix B — Claims Path Pointer component.
 * "A claims path pointer MUST be a non-empty array of strings, nulls and integers."
 */
export const zClaimsPathComponent = z.union([z.string(), z.number().int(), z.null()])
export type ClaimsPathComponent = z.infer<typeof zClaimsPathComponent>

/** Fields shared by all claim metadata variants. */
const zClaimBase = {
  /** Claims Path Pointer per [OID4VCI] Appendix B, resolves against `transaction_data.payload`. */
  path: z.array(zClaimsPathComponent),
  /** Whether the claim MUST be present in the payload. */
  mandatory: z.boolean().optional(),
}

/**
 * Internal claim — no `display`, no `value_type`.
 * Per Section 3.5.2: "Claims without a `display` array MUST be internal values."
 * Uses `.strict()` to reject extra fields like `value_type` that belong only on displayable claims.
 */
const zInternalClaimMetadata = z.object(zClaimBase).strict()

/**
 * Displayable claim — has `display`, optionally `value_type`.
 * Per Section 3.5.2: "Claims that are relevant to the User's consent MUST include a `display` array."
 */
const zDisplayableClaimMetadata = z.object({
  ...zClaimBase,
  /** How the Wallet Unit SHALL format the claim value for display. */
  value_type: z.string().optional(),
  /** Localised display labels. */
  display: z.array(zClaimDisplayEntry),
})

/**
 * TS12 Section 3.5.2 — Claim metadata object.
 *
 * Uses [OID4VCI] Appendix B.2 structure, extended with `value_type`.
 * The `path` resolves against `transaction_data.payload`, not against the credential itself.
 *
 * Modelled as a union so TypeScript enforces:
 * - `value_type` can only appear on claims with a `display` array.
 */
export const zClaimMetadata = z.union([zDisplayableClaimMetadata, zInternalClaimMetadata])
export type ClaimMetadata = z.infer<typeof zClaimMetadata>

/**
 * TS12 Section 3.5.3 — UI label locale entry.
 *
 * Per Section 3.5.4, entries that omit `locale` serve as defaults.
 * The `value` string MAY contain placeholders `{<index>}` referencing claims.
 */
export const zUiLabelEntry = z.object({
  locale: z.string().optional(),
  value: z.string(),
  value_type: z.string().optional(),
})
export type UiLabelEntry = z.infer<typeof zUiLabelEntry>

/**
 * TS12 Section 3.5.3 — UI elements catalogue.
 *
 * Known identifiers:
 * - `affirmative_action_label`: REQUIRED — confirmation button label.
 * - `denial_action_label`: OPTIONAL — cancel button label.
 * - `transaction_title`: OPTIONAL — transaction screen title.
 * - `security_hint`: OPTIONAL — security hint displayed to User.
 *
 * Additional UI element identifiers MAY be defined.
 */
export const zUiLabels = z
  .object({
    affirmative_action_label: z.array(zUiLabelEntry),
    denial_action_label: z.array(zUiLabelEntry).optional(),
    transaction_title: z.array(zUiLabelEntry).optional(),
    security_hint: z.array(zUiLabelEntry).optional(),
  })
  .catchall(z.array(zUiLabelEntry))
export type UiLabels = z.infer<typeof zUiLabels>

/**
 * TS12 Section 4.1 — Transaction data type entry (value within `transaction_data_types` object).
 *
 * Each entry describes the claims and UI labels for one transaction data type.
 * Additional parameters MAY be defined; the Wallet Unit MUST ignore unrecognised ones.
 */
export const zTransactionDataType = z
  .object({
    /** REQUIRED. Claim metadata array per Section 3.5.2. */
    claims: z.array(zClaimMetadata),
    /** REQUIRED. UI elements catalogue per Section 3.5.3. */
    ui_labels: zUiLabels,
  })
  .loose()
export type TransactionDataType = z.infer<typeof zTransactionDataType>

// =============================================================================
// OID4VCI Section 12.2.4 — Credential metadata display
// =============================================================================

/**
 * [OID4VCI] Section 12.2.4 — Credential display entry.
 *
 * Locale-tagged display metadata for the credential itself (card rendering).
 * Uses `.loose()` to allow additional fields per spec extensions.
 */
export const zCredentialDisplayEntry = z
  .object({
    name: z.string(),
    locale: z.string().optional(),
    description: z.string().optional(),
    logo: z
      .object({
        uri: z.string(),
        alt_text: z.string().optional(),
      })
      .optional(),
    background_color: z.string().optional(),
    text_color: z.string().optional(),
  })
  .loose()
export type CredentialDisplayEntry = z.infer<typeof zCredentialDisplayEntry>

// =============================================================================
// OID4VCI Section 12.2.4 + TS12 Section 4.1 — Full credential metadata
// =============================================================================

/**
 * [OID4VCI] Section 12.2.4 credential metadata, extended with TS12 `transaction_data_types`.
 *
 * This is the `credential_metadata` object served at `credential_metadata_uri`.
 * It contains:
 * - `display`: credential-level display entries (name, logo, colors) per OID4VCI
 * - `claims`: credential-level claim metadata per OID4VCI Appendix B.2
 * - `transaction_data_types`: SCA transaction type definitions per TS12 Section 4.1
 *
 * Uses `.loose()` to allow additional OID4VCI fields without validating them.
 */
export const zCredentialMetadata = z
  .object({
    /** Credential-level display entries per [OID4VCI] Section 12.2.4. */
    display: z.array(zCredentialDisplayEntry).optional(),
    /** Credential-level claim metadata per [OID4VCI] Appendix B.2. */
    claims: z.array(zClaimMetadata).optional(),
    /** Transaction data type definitions per TS12 Section 4.1. */
    transaction_data_types: z.record(z.string(), zTransactionDataType).optional(),
  })
  .loose()
export type CredentialMetadata = z.infer<typeof zCredentialMetadata>

/**
 * SCA Attestation credential metadata — a `CredentialMetadata` where
 * `transaction_data_types` is required (Section 3.1: SCA Attestations are
 * identified by the presence of `transaction_data_types` keys).
 */
export const zScaCredentialMetadata = z
  .object({
    display: z.array(zCredentialDisplayEntry).optional(),
    claims: z.array(zClaimMetadata).optional(),
    transaction_data_types: z.record(z.string(), zTransactionDataType),
  })
  .loose()
export type ScaCredentialMetadata = z.infer<typeof zScaCredentialMetadata>
