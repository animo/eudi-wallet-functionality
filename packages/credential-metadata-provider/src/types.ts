import type { JwtSigner } from '@animo-id/eudi-wallet-ts12-credential-metadata'
import type { CredentialMetadata } from '@animo-id/eudi-wallet-ts12-validation'

export type { JwtSigner } from '@animo-id/eudi-wallet-ts12-credential-metadata'

/** Lightweight credential identity — no heavy metadata payload. */
export interface CredentialInfo {
  /** The credential type identifier — vct or doctype (`sub` claim). */
  credentialType: string
  /** The credential format identifier, e.g., 'dc+sd-jwt', 'mso_mdoc' (`format` claim). */
  format: string
  /** The URL at which this JWT is served (`credential_metadata_uri` claim). */
  credentialMetadataUri: string
  /** Epoch milliseconds of last metadata update. Used to bust the derived locale cache. */
  updatedAt: number
}

/**
 * Storage interface for credential metadata.
 *
 * `getCredentialInfo` is called on every request (lightweight).
 * `getCredentialMetadata` is only called when the metadata is actually needed
 * (cache miss or JSON response).
 */
export interface CredentialMetadataStore {
  /** Get lightweight credential identity. Called on every request. */
  getCredentialInfo(credentialId: string): Promise<CredentialInfo | undefined>

  /** Get the full unsigned credential metadata with all locales. Only called on cache miss. */
  getCredentialMetadata(credentialId: string): Promise<CredentialMetadata | undefined>

  /** Get a cached signed JWT for a credential + canonical locale key. */
  getSignedJwt(credentialId: string, canonicalLocale: string): Promise<string | undefined>

  /** Persist a signed JWT for a credential + canonical locale key. */
  saveSignedJwt(credentialId: string, canonicalLocale: string, jwt: string): Promise<void>
}

/**
 * Selects which locales to filter the metadata to, given the requested locales
 * (already pre-filtered by the allow list).
 *
 * Returns an array of locale codes to keep. The provider sorts and joins them
 * into a canonical cache key.
 *
 * Default: takes the first locale and returns its primary language subtag.
 * e.g. `['en-us', 'de-de']` → `['en']`
 */
export type LocaleCanonicalizer = (requestedLocales: string[]) => string[]

/** Configuration for the credential metadata provider handler. */
export interface CredentialMetadataProviderConfig {
  store: CredentialMetadataStore
  /** Signs the JWT. The signer handles alg, x5c, and key material. */
  signer: JwtSigner
  /** The Credential Issuer Identifier (`iss` claim). */
  issuerIdentifier: string
  /** JWT validity in seconds. */
  expiresInSeconds: number
  /**
   * Selects which locales to use for filtering, given the pre-filtered
   * requested locales. Default: primary subtag of the first locale.
   */
  canonicalizeLocale?: LocaleCanonicalizer
  /** Logger for warnings (e.g. non-resolvable locales). */
  logger?: { warn(message: string): void }
}

/** HTTP response from the handler. */
export interface CredentialMetadataResponse {
  status: number
  contentType: 'application/jwt' | 'application/json'
  body: string
}
