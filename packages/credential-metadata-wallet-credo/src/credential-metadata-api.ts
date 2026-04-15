import type { AgentContext } from '@credo-ts/core'
import {
  CredentialMetadataService,
  type FetchAndStoreOptions,
  type GetVerifiedMetadataOptions,
  type RenewIfNeededOptions,
  type ResolveCredentialMetadataOptions,
  type ResolvedCredentialMetadata,
  type VerifiedCredentialMetadata,
} from '@animo-id/eudi-wallet-ts12-credential-metadata-wallet'
import { CredentialMetadataModule } from './credential-metadata-module'

/**
 * Public API for credential metadata handling.
 *
 * Exposed on the Agent as `agent.credentialMetadata.*` when the
 * `CredentialMetadataModule` is registered.
 */
export class CredentialMetadataApi {
  private service: CredentialMetadataService

  constructor(agentContext: AgentContext) {
    const module = agentContext.dependencyManager.resolve(CredentialMetadataModule)
    const { defaultRenewalThresholdSeconds } = module.config
    const store = module.config.store(agentContext)
    const jwtVerifier = module.config.jwtVerifier(agentContext)

    this.service = new CredentialMetadataService(store, jwtVerifier, { defaultRenewalThresholdSeconds })
  }

  /** Resolve credential metadata: tries signed JWT, falls back to unsigned JSON or inline. */
  async resolveCredentialMetadata(options: ResolveCredentialMetadataOptions): Promise<ResolvedCredentialMetadata> {
    return this.service.resolveCredentialMetadata(options)
  }

  /** Fetch signed JWT, verify, and store linked to a credential record. */
  async fetchAndStore(options: FetchAndStoreOptions): Promise<VerifiedCredentialMetadata> {
    return this.service.fetchAndStore(options)
  }

  /** Load stored JWT, re-verify, and recompute `metadata_integrity`. Re-fetches on failure. */
  async getVerifiedMetadata(options: GetVerifiedMetadataOptions): Promise<VerifiedCredentialMetadata> {
    return this.service.getVerifiedMetadata(options)
  }

  /** Check if stored JWT needs renewal and re-fetch if so. */
  async renewIfNeeded(options: RenewIfNeededOptions): Promise<void> {
    return this.service.renewIfNeeded(options)
  }

  /** Section 8.3 — Get full signed JWT history (oldest to most recent), including the current JWT. */
  async getSignedCredentialMetadataHistory(credentialRecordId: string): Promise<string[]> {
    return this.service.getSignedCredentialMetadataHistory(credentialRecordId)
  }
}
