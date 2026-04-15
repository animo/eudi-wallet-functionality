import type { DependencyManager, Module } from '@credo-ts/core'
import { CredentialMetadataQueryApi } from './credential-metadata-query-api'
import { CredentialMetadataQueryService } from './credential-metadata-query-service'
import { CredentialMetadataJwtRepository } from './repository/credential-metadata-jwt-repository'

/**
 * Credo-ts module for TS12 credential metadata resolution.
 *
 * Supports three resolution modes:
 * - Signed JWT via `credential_metadata_uri` (preferred for SCA, Section 4.1)
 * - Unsigned JSON via `credential_metadata_uri` (fallback)
 * - Inline `credential_metadata` from issuer metadata
 *
 * @example
 * ```typescript
 * const agent = new Agent({
 *   modules: {
 *     credentialMetadataQuery: new CredentialMetadataQueryModule(),
 *   }
 * })
 *
 * const result = await agent.credentialMetadataQuery.resolveCredentialMetadata({
 *   credentialMetadataUri: 'https://issuer.example.com/credential-metadata/Card',
 *   issuerIdentifier: 'https://issuer.example.com',
 *   credentialType: 'https://pay.example.com/card',
 *   credentialRecordId: sdJwtVcRecord.id,
 *   credentialX5c: ['...'],
 * })
 *
 * if (result.source === 'signed-jwt') {
 *   // result.metadataIntegrity, result.compactJwt available
 * }
 * // result.credentialMetadata always available
 * ```
 */
export class CredentialMetadataQueryModule implements Module {
  readonly api = CredentialMetadataQueryApi

  register(dependencyManager: DependencyManager): void {
    dependencyManager.registerSingleton(CredentialMetadataQueryService)
    dependencyManager.registerSingleton(CredentialMetadataJwtRepository)
  }
}
