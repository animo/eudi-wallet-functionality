import type { AgentContext } from '@credo-ts/core'
import {
  CredentialMetadataProvider,
  type CredentialMetadataResponse,
} from '@animo-id/eudi-wallet-ts12-credential-metadata-provider'
import { CredentialMetadataProviderModule } from './credential-metadata-provider-module'
import { createCredentialMetadataHandler, type CredentialMetadataRouterHandler } from './credential-metadata-router'

/**
 * Public API for the credential metadata provider.
 *
 * Exposed on the Agent as `agent.credentialMetadataProvider.*` when the
 * `CredentialMetadataProviderModule` is registered.
 */
export class CredentialMetadataProviderApi {
  private provider: CredentialMetadataProvider

  constructor(agentContext: AgentContext) {
    const module = agentContext.dependencyManager.resolve(CredentialMetadataProviderModule)
    this.provider = new CredentialMetadataProvider(module.config)
  }

  /**
   * Handle a credential metadata request.
   *
   * @param credentialId The credential configuration ID from the URL path.
   * @param headers The HTTP request headers (accept, acceptLanguage).
   */
  async handle(
    credentialId: string,
    headers: { accept?: string; acceptLanguage?: string }
  ): Promise<CredentialMetadataResponse> {
    return this.provider.handle(credentialId, headers)
  }

  /**
   * Create a request handler for `GET /:credentialId`.
   *
   * Wire this into your HTTP framework's router:
   * @example
   * ```typescript
   * import { Router } from 'express'
   * const router = Router()
   * router.get('/:credentialId', agent.credentialMetadataProvider.createHandler())
   * app.use('/credential-metadata', router)
   * ```
   */
  createHandler(): CredentialMetadataRouterHandler {
    return createCredentialMetadataHandler(this.provider)
  }
}
