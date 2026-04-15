import type { JwtVerifier } from '@animo-id/eudi-wallet-ts12-credential-metadata'
import type {
  CredentialMetadata,
  CredentialMetadataJwtHeader,
  CredentialMetadataJwtPayload,
} from '@animo-id/eudi-wallet-ts12-validation'

// --- Agnostic persistence ---

/** Plain data shape for a stored credential metadata JWT. Framework-agnostic. */
export interface StoredCredentialMetadataJwt {
  id: string
  /** The raw signed JWT — persisted in signed form per Section 4.1.3. */
  compactJwt: string
  /** The credential_metadata_uri for re-fetch (Section 4.1.4). */
  credentialMetadataUri: string
  /** The Credential Issuer Identifier (for step 4 verification). */
  issuerIdentifier: string
  /** The credential type identifier — vct or doctype (for step 6a). */
  credentialType: string
  /** The credential format identifier (e.g., 'dc+sd-jwt', 'mso_mdoc'). */
  format: string
  /** The exp claim as epoch seconds, for renewal checks (Section 4.1.4). */
  expiresAtSeconds: number
  /** The id of the linked credential record. */
  credentialRecordId: string
}

/**
 * Wallet-side persistence for credential metadata JWTs.
 *
 * Implementations manage storage of the current signed JWT per credential
 * and the audit history of all previously used JWTs (Section 8.3).
 */
export interface CredentialMetadataWalletStore {
  findByCredentialRecordId(credentialRecordId: string): Promise<StoredCredentialMetadataJwt | null>
  getByCredentialRecordId(credentialRecordId: string): Promise<StoredCredentialMetadataJwt>
  save(record: StoredCredentialMetadataJwt): Promise<void>
  update(record: StoredCredentialMetadataJwt): Promise<void>
  /** Section 8.3 — append old JWT to audit history before overwriting. */
  appendToHistory(credentialRecordId: string, compactJwt: string): Promise<void>
  /** Section 8.3 — all historical JWTs, ordered oldest to most recent. */
  getHistory(credentialRecordId: string): Promise<string[]>
}

// --- Module configuration ---

/** Configuration for the credential metadata wallet module — pluggable persistence and trust. */
export interface CredentialMetadataWalletModuleConfig {
  store: CredentialMetadataWalletStore
  jwtVerifier: JwtVerifier
  /** Default renewal threshold in seconds. Default: 3600 (1 hour). */
  defaultRenewalThresholdSeconds?: number
}

// --- Verification and resolution results ---

/** The result of successful credential metadata JWT verification (Section 4.1.2). */
export interface VerifiedCredentialMetadata {
  header: CredentialMetadataJwtHeader
  payload: CredentialMetadataJwtPayload
  compactJwt: string
  /** W3C SRI integrity value (Section 3.7.1). */
  metadataIntegrity: string
}

/**
 * Credential verification context for signed JWT operations.
 *
 * `credentialX5c` is the credential's own certificate chain, used in
 * step 6b/6c to compare root CA and leaf subjects against the metadata JWT's chain.
 * `trustAnchors` are root certificates from the Wallet Unit's trust store,
 * used in steps 2/3 to validate the metadata JWT's `x5c` chain.
 */
export interface CredentialVerificationContext {
  /** The credential's X.509 certificate chain (for step 6b/6c subject comparison). */
  credentialX5c: string[]
  /** Root certificates from the Wallet Unit's trust store (for chain validation). */
  trustAnchors?: string[]
}

export interface FetchAndStoreOptions extends CredentialVerificationContext {
  credentialMetadataUri: string
  issuerIdentifier: string
  credentialType: string
  credentialRecordId: string
  acceptLanguage?: string
}

export interface GetVerifiedMetadataOptions extends CredentialVerificationContext {
  credentialRecordId: string
}

export interface RenewIfNeededOptions extends CredentialVerificationContext {
  credentialRecordId: string
  /** Seconds before expiry to trigger renewal. Default: 3600 (1 hour). */
  thresholdSeconds?: number
}

/** Unified result of credential metadata resolution. */
export type ResolvedCredentialMetadata =
  | ({ source: 'signed-jwt'; credentialMetadata: CredentialMetadata } & VerifiedCredentialMetadata)
  | { source: 'unsigned-json'; credentialMetadata: CredentialMetadata }
  | { source: 'inline'; credentialMetadata: CredentialMetadata }

/** Options for the unified resolution entry point. */
export interface ResolveCredentialMetadataOptions {
  credentialRecordId: string
  issuerIdentifier: string
  credentialType: string
  /** From credential_configurations_supported. If present, fetches from URI. */
  credentialMetadataUri?: string
  /** Inline credential_metadata object. Used when credentialMetadataUri is absent. */
  credentialMetadata?: CredentialMetadata
  /** Required when credentialMetadataUri is present (for signed JWT verification). */
  credentialX5c?: string[]
  trustAnchors?: string[]
  acceptLanguage?: string
}
