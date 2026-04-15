import type { CredentialMetadata } from '@animo-id/eudi-wallet-ts12-validation'
import type { CredentialInfo, CredentialMetadataStore } from '@animo-id/eudi-wallet-ts12-credential-metadata-provider'

/** Registration for a credential in the in-memory store. */
export interface CredentialRegistration {
  /** The credential type identifier — vct or doctype. */
  credentialType: string
  /** The credential format identifier, e.g., 'dc+sd-jwt', 'mso_mdoc'. */
  format: string
  /** The URL at which this credential's metadata is served. */
  credentialMetadataUri: string
  /** The full credential metadata with all locales. */
  credentialMetadata: CredentialMetadata
}

/**
 * Create an in-memory {@link CredentialMetadataStore} from a static credential map.
 *
 * **Debug/development only.** Production deployments should implement
 * {@link CredentialMetadataStore} with persistent storage.
 */
export function createInMemoryCredentialMetadataStore(
  credentials: Record<string, CredentialRegistration>
): CredentialMetadataStore {
  const jwtCache = new Map<string, string>()
  const registeredAt = Date.now()

  return {
    async getCredentialInfo(credentialId): Promise<CredentialInfo | undefined> {
      const reg = credentials[credentialId]
      if (!reg) return undefined
      return {
        credentialType: reg.credentialType,
        format: reg.format,
        credentialMetadataUri: reg.credentialMetadataUri,
        updatedAt: registeredAt,
      }
    },

    async getCredentialMetadata(credentialId): Promise<CredentialMetadata | undefined> {
      return credentials[credentialId]?.credentialMetadata
    },

    async getSignedJwt(credentialId, canonicalLocale): Promise<string | undefined> {
      return jwtCache.get(`${credentialId}:${canonicalLocale}`)
    },

    async saveSignedJwt(credentialId, canonicalLocale, jwt): Promise<void> {
      jwtCache.set(`${credentialId}:${canonicalLocale}`, jwt)
    },
  }
}
