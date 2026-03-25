import type { ResolvedTransactionDisplay, ValueTypeResolvers } from '@animo-id/eudi-wallet-ts12-resolver'
import type { ScaCredentialMetadata } from '@animo-id/eudi-wallet-ts12-validation'

// =============================================================================
// DCQL Query types per OID4VP 1.0 Section 6
// =============================================================================

/** Claims Path Pointer component per OID4VP Section 7. */
export type ClaimsPathComponent = string | number | null

/** A claim query within a credential query (OID4VP Section 6.3). */
export interface DcqlClaimsQuery {
  id?: string
  path: ClaimsPathComponent[]
  values?: (string | number | boolean)[]
  intent_to_retain?: boolean
}

/** Trusted authority constraint (OID4VP Section 6.1.1). */
export interface DcqlTrustedAuthoritiesQuery {
  type: string
  values: string[]
}

/** Format-specific metadata for dc+sd-jwt (OID4VP Appendix B.3.5). */
export interface DcqlMetaSdJwt {
  vct_values: string[]
}

/** Format-specific metadata for mso_mdoc (OID4VP Appendix B.2.3). */
export interface DcqlMetaMsoMdoc {
  doctype_value: string
}

/** Format-specific metadata for jwt_vc_json / ldp_vc (OID4VP Appendix B.1.1). */
export interface DcqlMetaW3cVc {
  type_values: string[][]
}

export type DcqlMeta = DcqlMetaSdJwt | DcqlMetaMsoMdoc | DcqlMetaW3cVc | Record<string, unknown>

/** A credential query from a DCQL request (OID4VP Section 6.1). */
export interface DcqlCredentialQuery {
  id: string
  format: string
  meta: DcqlMeta
  claims?: DcqlClaimsQuery[]
  claim_sets?: string[][]
  multiple?: boolean
  require_cryptographic_holder_binding?: boolean
  trusted_authorities?: DcqlTrustedAuthoritiesQuery[]
}

/** A credential set from a DCQL request (OID4VP Section 6.2). */
export interface DcqlCredentialSetQuery {
  options: string[][]
  description?: string
  required?: boolean
}

/** Top-level DCQL query structure (OID4VP Section 6). */
export interface DcqlQuery {
  credentials: DcqlCredentialQuery[]
  credential_sets?: DcqlCredentialSetQuery[]
}

// =============================================================================
// Credential display metadata (OID4VCI Section 12.2.4 + TS12 Section 5)
// =============================================================================

/** SVG template reference per [SD-JWT-VC] Section 7.1.2, extended by TS12 Section 5. */
export interface SvgTemplate {
  uri: string
  /** W3C SRI integrity hash. REQUIRED per TS12 Section 1.5.4 when supported. */
  'uri#integrity'?: string
}

/** A locale entry in a credential's display array. */
export interface CredentialDisplayEntry {
  name: string
  locale?: string
  description?: string
  logo?: { uri: string; alt_text?: string }
  background_color?: string
  text_color?: string
  /** SVG card templates per [SD-JWT-VC] Section 7.1.2. */
  svg_templates?: SvgTemplate[]
}

/** Locale-resolved credential display (single entry, no array). */
export interface ResolvedCredentialDisplay {
  name: string
  description?: string
  logo?: { uri: string; alt_text?: string }
  background_color?: string
  text_color?: string
  /** Locale-matched SVG template (if wallet supports SVG and templates are present). */
  svg_template?: SvgTemplate
}

// =============================================================================
// Wallet configuration
// =============================================================================

/** Wallet rendering preferences, threaded through all resolution. */
export interface WalletConfiguration {
  /** Ordered list of user preferred locales (RFC 5646 tags), highest priority first. */
  locales: string[]
  /** Value type resolver map. */
  valueTypeResolvers: ValueTypeResolvers
  /** Display mode for theming (affects SVG template selection, credential rendering). */
  mode: 'dark' | 'light'
  /** Whether the wallet supports SVG template rendering. */
  supportsSvgTemplates: boolean
  /** Card format dimensions for SVG template rendering. */
  cardFormat?: {
    width: number
    height: number
  }
  /**
   * Check whether a credential supports a non-SCA transaction_data type.
   * Called for transaction_data entries without the `urn:eudi:sca:` prefix.
   * If absent, all credentials targeted by non-SCA transaction_data are
   * considered incompatible.
   */
  checkNonScaTransactionDataSupport?: (credentialId: string, transactionDataType: string) => boolean
}

// =============================================================================
// Matcher types
// =============================================================================

/** A wallet credential matched by a DCQL credential query. */
export interface MatchedCredential {
  credentialId: string
  /** SCA credential metadata, if this is an SCA Attestation. */
  scaMetadata?: ScaCredentialMetadata
  /** OID4VCI credential display metadata. */
  display?: CredentialDisplayEntry[]
}

/**
 * Resolves a DCQL credential query to matching wallet credentials.
 *
 * Receives the full query (format, meta, claims, trusted_authorities, etc.)
 * and returns matched credentials with their metadata.
 */
export type CredentialMatcher = (query: DcqlCredentialQuery) => MatchedCredential[]

// =============================================================================
// Transaction data input
// =============================================================================

/** A transaction_data entry from the OID4VP request. */
export interface TransactionDataInput {
  type: string
  credential_ids: string[]
  payload: Record<string, unknown>
}

// =============================================================================
// Resolution output
// =============================================================================

/** A wallet credential fully resolved with display, claims, and SCA data. */
export interface ResolvedWalletCredential {
  credentialId: string
  /** Which DCQL credential query this credential was matched from. */
  credentialQueryId: string
  /** Locale-resolved credential display metadata. */
  display?: ResolvedCredentialDisplay
  /** Claims requested by the RP for this credential (from the DCQL query). */
  requestedClaims?: DcqlClaimsQuery[]
  /**
   * Present if a transaction_data entry targets this credential (via credential_ids).
   * - SCA entries: `resolved` contains the full locale-resolved display (first-match rule, TS12 Section 3.3 step 3).
   * - Non-SCA entries: `resolved` is undefined, `entry` contains the raw transaction data.
   */
  transactionData?: {
    index: number
    entry: TransactionDataInput
    resolved?: ResolvedTransactionDisplay
  }
}

/** A slot alternative: one DCQL credential query with its resolved wallet credentials. */
export interface SlotAlternative {
  credentialQueryId: string
  credentials: ResolvedWalletCredential[]
}

/** An independent choice slot within a resolved credential set. */
export interface ResolvedSlot {
  optional: boolean
  alternatives: SlotAlternative[]
}

/** A fully resolved credential set decomposed into independent slots. */
export interface ResolvedCredentialSet {
  description?: string
  required: boolean
  slots: ResolvedSlot[]
}

/** Top-level resolution result with the selected locale. */
export interface ResolvedDcqlResult {
  /** The locale selected for the entire presentation (TS12 Section 3.5.4). */
  locale: string
  credentialSets: ResolvedCredentialSet[]
}
