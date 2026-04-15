import type {
  CredentialMetadata,
  CredentialMetadataJwtHeader,
  CredentialMetadataJwtPayload,
} from '@animo-id/eudi-wallet-ts12-validation'

/** The result of successful credential metadata JWT verification (Section 4.1.2). */
export interface VerifiedCredentialMetadata {
  header: CredentialMetadataJwtHeader
  payload: CredentialMetadataJwtPayload
  compactJwt: string
  /** W3C SRI integrity value (Section 3.7.1). */
  metadataIntegrity: string
}

/** Credential verification context for signed JWT operations. */
export interface CredentialVerificationContext {
  credentialX5c: string[]
  trustedCertificates?: string[]
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
  trustedCertificates?: string[]
  acceptLanguage?: string
}
