import type { DependencyManager, Module } from '@credo-ts/core'
import type { CredentialMetadataProviderConfig } from '@animo-id/eudi-wallet-ts12-credential-metadata-provider'
import { CredentialMetadataProviderApi } from './credential-metadata-provider-api'

/**
 * Credo-ts module for serving signed credential metadata per TS12 Section 5.
 *
 * @example
 * ```typescript
 * import {
 *   CredentialMetadataProviderModule,
 *   createCredoJwtSigner,
 *   createInMemoryCredentialMetadataStore,
 * } from '@animo-id/eudi-wallet-ts12-credential-metadata-provider-credo'
 *
 * const agent = new Agent({
 *   modules: {
 *     credentialMetadataProvider: new CredentialMetadataProviderModule({
 *       issuerIdentifier: 'https://issuer.example.com',
 *       expiresInSeconds: 86400,
 *       signer: createCredoJwtSigner(agentContext, { x5c: [leafCert, rootCert] }),
 *       store: createInMemoryCredentialMetadataStore({
 *         'WeroSca': {
 *           credentialType: 'https://example.com/wero-sca',
 *           format: 'dc+sd-jwt',
 *           credentialMetadataUri: 'https://issuer.example.com/credential-metadata/WeroSca',
 *           credentialMetadata: { display: [...], transaction_data_types: {...} },
 *         },
 *       }),
 *     }),
 *   }
 * })
 *
 * // Mount the router
 * app.use('/credential-metadata', agent.credentialMetadataProvider.createRouter())
 * ```
 */
export class CredentialMetadataProviderModule implements Module {
  readonly api = CredentialMetadataProviderApi
  readonly config: CredentialMetadataProviderConfig

  constructor(config: CredentialMetadataProviderConfig) {
    this.config = config
  }

  register(_dependencyManager: DependencyManager): void {
    // The provider is stateless and config-driven — DI wiring happens in the API class
  }
}
