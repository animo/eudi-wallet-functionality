import type { AgentContext, DependencyManager, Module } from '@credo-ts/core'
import type { CredentialMetadataWalletStore } from '@animo-id/eudi-wallet-ts12-credential-metadata-wallet'
import type { JwtVerifier } from '@animo-id/eudi-wallet-ts12-credential-metadata'
import { CredentialMetadataApi } from './credential-metadata-api'
import { CredentialMetadataHistoryRepository } from './credential-metadata-history-repository'
import { CredentialMetadataJwtRepository } from './credential-metadata-jwt-repository'

/** Credo-specific module config — accepts factories that receive AgentContext. */
export interface CredentialMetadataModuleConfig {
  /** Factory that creates the wallet store given an AgentContext. */
  store: (agentContext: AgentContext) => CredentialMetadataWalletStore
  /** Factory that creates the JWT verifier given an AgentContext. */
  jwtVerifier: (agentContext: AgentContext) => JwtVerifier
  /** Default renewal threshold in seconds. Default: 3600 (1 hour). */
  defaultRenewalThresholdSeconds?: number
}

/**
 * Credo-ts module for TS12 credential metadata handling.
 *
 * Provides pluggable persistence and trust via factory functions that
 * receive `AgentContext` at API construction time.
 *
 * @example
 * ```typescript
 * import { CredentialMetadataModule, createCredoStore, createCredoJwtVerifier } from '@animo-id/eudi-wallet-ts12-credential-metadata-wallet-credo'
 *
 * const agent = new Agent({
 *   modules: {
 *     credentialMetadata: new CredentialMetadataModule({
 *       store: (agentContext) => createCredoStore(agentContext),
 *       jwtVerifier: (agentContext) => createCredoJwtVerifier(agentContext),
 *     }),
 *   }
 * })
 * ```
 */
export class CredentialMetadataModule implements Module {
  readonly api = CredentialMetadataApi
  readonly config: CredentialMetadataModuleConfig

  constructor(config: CredentialMetadataModuleConfig) {
    this.config = config
  }

  register(dependencyManager: DependencyManager): void {
    dependencyManager.registerSingleton(CredentialMetadataJwtRepository)
    dependencyManager.registerSingleton(CredentialMetadataHistoryRepository)
  }
}
