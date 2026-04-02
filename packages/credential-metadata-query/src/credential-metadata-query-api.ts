import type { AgentContext } from '@credo-ts/core'
// biome-ignore lint/style/useImportType: DI requires runtime class reference
import { CredentialMetadataQueryService } from './credential-metadata-query-service'
import type {
  FetchAndStoreOptions,
  GetVerifiedMetadataOptions,
  RenewIfNeededOptions,
  ResolveCredentialMetadataOptions,
  ResolvedCredentialMetadata,
  VerifiedCredentialMetadata,
} from './types'

/**
 * Public API for credential metadata resolution.
 *
 * Exposed on the Agent as `agent.credentialMetadataQuery.*` when the
 * `CredentialMetadataQueryModule` is registered.
 */
export class CredentialMetadataQueryApi {
  private service: CredentialMetadataQueryService
  private agentContext: AgentContext

  constructor(service: CredentialMetadataQueryService, agentContext: AgentContext) {
    this.service = service
    this.agentContext = agentContext
  }

  /** Resolve credential metadata: tries signed JWT, falls back to unsigned JSON or inline. */
  async resolveCredentialMetadata(options: ResolveCredentialMetadataOptions): Promise<ResolvedCredentialMetadata> {
    return this.service.resolveCredentialMetadata(this.agentContext, options)
  }

  /** Fetch signed JWT, verify, and store linked to a credential record. */
  async fetchAndStore(options: FetchAndStoreOptions): Promise<VerifiedCredentialMetadata> {
    return this.service.fetchAndStore(this.agentContext, options)
  }

  /** Load stored JWT, re-verify, and recompute `metadata_integrity`. Re-fetches on failure. */
  async getVerifiedMetadata(options: GetVerifiedMetadataOptions): Promise<VerifiedCredentialMetadata> {
    return this.service.getVerifiedMetadata(this.agentContext, options)
  }

  /** Check if stored JWT needs renewal and re-fetch if so. */
  async renewIfNeeded(options: RenewIfNeededOptions): Promise<void> {
    return this.service.renewIfNeeded(this.agentContext, options)
  }

  /** Compute the W3C SRI integrity value for a signed credential metadata JWT. */
  computeMetadataIntegrity(compactJwt: string): string {
    return this.service.computeMetadataIntegrity(compactJwt)
  }
}
