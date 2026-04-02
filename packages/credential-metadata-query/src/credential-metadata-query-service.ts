import { createHash } from 'node:crypto'
import {
  zCredentialMetadata,
  zCredentialMetadataJwtHeader,
  zCredentialMetadataJwtPayload,
} from '@animo-id/eudi-wallet-ts12-validation'
import { type AgentContext, JwsService, Jwt, X509Certificate } from '@credo-ts/core'
import { CredentialMetadataJwtRecord } from './repository/credential-metadata-jwt-record'
// biome-ignore lint/style/useImportType: DI requires runtime class reference
import { CredentialMetadataJwtRepository } from './repository/credential-metadata-jwt-repository'
import type {
  CredentialVerificationContext,
  FetchAndStoreOptions,
  GetVerifiedMetadataOptions,
  RenewIfNeededOptions,
  ResolveCredentialMetadataOptions,
  ResolvedCredentialMetadata,
  VerifiedCredentialMetadata,
} from './types'

const CREDENTIAL_METADATA_JWT_MEDIA_TYPE = 'application/jwt'

function nowEpochSeconds(): number {
  return Math.floor(Date.now() / 1000)
}

function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e)
}

interface VerifyOptions extends CredentialVerificationContext {
  compactJwt: string
  issuerIdentifier: string
  credentialType: string
  expectedCredentialMetadataUri?: string
}

/**
 * TS12 Sections 4.1, 5 — Service for resolving credential metadata.
 *
 * Supports three resolution modes:
 * - Signed JWT via `credential_metadata_uri` (preferred for SCA)
 * - Unsigned JSON via `credential_metadata_uri`
 * - Inline `credential_metadata` from issuer metadata
 */
export class CredentialMetadataQueryService {
  private credentialMetadataJwtRepository: CredentialMetadataJwtRepository

  constructor(credentialMetadataJwtRepository: CredentialMetadataJwtRepository) {
    this.credentialMetadataJwtRepository = credentialMetadataJwtRepository
  }

  /**
   * Unified entry point: resolve credential metadata preferring signed JWT.
   *
   * 1. If `credentialMetadataUri` present: try signed JWT, fall back to unsigned JSON
   * 2. If only inline `credentialMetadata` present: validate and return
   * 3. Neither: throw
   */
  async resolveCredentialMetadata(
    agentContext: AgentContext,
    options: ResolveCredentialMetadataOptions
  ): Promise<ResolvedCredentialMetadata> {
    if (options.credentialMetadataUri) {
      if (!options.credentialX5c) {
        throw new Error('credentialX5c is required when resolving from credential_metadata_uri')
      }

      // Try signed JWT first
      try {
        const verified = await this.fetchAndStore(agentContext, {
          credentialMetadataUri: options.credentialMetadataUri,
          issuerIdentifier: options.issuerIdentifier,
          credentialType: options.credentialType,
          credentialRecordId: options.credentialRecordId,
          credentialX5c: options.credentialX5c,
          trustedCertificates: options.trustedCertificates,
          acceptLanguage: options.acceptLanguage,
        })
        return {
          source: 'signed-jwt',
          credentialMetadata: verified.payload.credential_metadata,
          ...verified,
        }
      } catch {
        // Fall back to unsigned JSON
        const credentialMetadata = await this.fetchUnsignedCredentialMetadata(
          options.credentialMetadataUri,
          options.acceptLanguage
        )
        return { source: 'unsigned-json', credentialMetadata }
      }
    }

    if (options.credentialMetadata) {
      const result = zCredentialMetadata.safeParse(options.credentialMetadata)
      if (!result.success) {
        throw new Error(`Inline credential metadata validation failed — ${result.error.message}`)
      }
      return { source: 'inline', credentialMetadata: result.data }
    }

    throw new Error('Either credentialMetadataUri or credentialMetadata must be provided')
  }

  /** Fetch signed JWT, verify (Section 4.1.2), persist (Section 4.1.3), return verified metadata. */
  async fetchAndStore(agentContext: AgentContext, options: FetchAndStoreOptions): Promise<VerifiedCredentialMetadata> {
    const compactJwt = await this.fetchCredentialMetadataJwt(options.credentialMetadataUri, options.acceptLanguage)

    const verified = await this.verifyCredentialMetadataJwt(agentContext, {
      compactJwt,
      issuerIdentifier: options.issuerIdentifier,
      credentialType: options.credentialType,
      credentialX5c: options.credentialX5c,
      trustedCertificates: options.trustedCertificates,
      expectedCredentialMetadataUri: options.credentialMetadataUri,
    })

    const existing = await this.credentialMetadataJwtRepository.findByCredentialRecordId(
      agentContext,
      options.credentialRecordId
    )

    if (existing) {
      existing.compactJwt = verified.compactJwt
      existing.credentialMetadataUri = options.credentialMetadataUri
      existing.issuerIdentifier = options.issuerIdentifier
      existing.credentialType = options.credentialType
      existing.format = verified.payload.format
      existing.expiresAtSeconds = verified.payload.exp
      await this.credentialMetadataJwtRepository.update(agentContext, existing)
    } else {
      const record = new CredentialMetadataJwtRecord({
        compactJwt: verified.compactJwt,
        credentialMetadataUri: options.credentialMetadataUri,
        issuerIdentifier: options.issuerIdentifier,
        credentialType: options.credentialType,
        format: verified.payload.format,
        expiresAtSeconds: verified.payload.exp,
        credentialRecordId: options.credentialRecordId,
      })
      await this.credentialMetadataJwtRepository.save(agentContext, record)
    }

    return verified
  }

  /** Load stored JWT, re-verify, recompute `metadata_integrity` (Section 4.1.3). Re-fetches on failure. */
  async getVerifiedMetadata(
    agentContext: AgentContext,
    options: GetVerifiedMetadataOptions
  ): Promise<VerifiedCredentialMetadata> {
    const record = await this.credentialMetadataJwtRepository.getByCredentialRecordId(
      agentContext,
      options.credentialRecordId
    )

    try {
      return await this.verifyCredentialMetadataJwt(agentContext, {
        compactJwt: record.compactJwt,
        issuerIdentifier: record.issuerIdentifier,
        credentialType: record.credentialType,
        credentialX5c: options.credentialX5c,
        trustedCertificates: options.trustedCertificates,
        expectedCredentialMetadataUri: record.credentialMetadataUri,
      })
    } catch (storedError) {
      try {
        return await this.refetchFromRecord(agentContext, record, options)
      } catch (refetchError) {
        throw new Error(
          `Stored metadata verification failed and re-fetch also failed. ` +
            `Stored: ${errorMessage(storedError)}. Re-fetch: ${errorMessage(refetchError)}`
        )
      }
    }
  }

  /** Check if stored JWT needs renewal and re-fetch if so (Section 4.1.4). */
  async renewIfNeeded(agentContext: AgentContext, options: RenewIfNeededOptions): Promise<void> {
    const record = await this.credentialMetadataJwtRepository.getByCredentialRecordId(
      agentContext,
      options.credentialRecordId
    )

    const thresholdSeconds = options.thresholdSeconds ?? 3600
    if (record.expiresAtSeconds - nowEpochSeconds() <= thresholdSeconds) {
      await this.refetchFromRecord(agentContext, record, options)
    }
  }

  /** Compute the W3C SRI integrity value of a signed credential metadata JWT (Section 3.7.1). */
  computeMetadataIntegrity(compactJwt: string): string {
    const hash = createHash('sha256').update(compactJwt, 'utf8').digest('base64')
    return `sha256-${hash}`
  }

  private async refetchFromRecord(
    agentContext: AgentContext,
    record: CredentialMetadataJwtRecord,
    context: CredentialVerificationContext & { credentialRecordId: string }
  ): Promise<VerifiedCredentialMetadata> {
    return this.fetchAndStore(agentContext, {
      credentialMetadataUri: record.credentialMetadataUri,
      issuerIdentifier: record.issuerIdentifier,
      credentialType: record.credentialType,
      credentialRecordId: context.credentialRecordId,
      credentialX5c: context.credentialX5c,
      trustedCertificates: context.trustedCertificates,
    })
  }

  /**
   * TS12 Section 4.1.2 — Full 6-step verification.
   */
  private async verifyCredentialMetadataJwt(
    agentContext: AgentContext,
    options: VerifyOptions
  ): Promise<VerifiedCredentialMetadata> {
    const {
      compactJwt,
      issuerIdentifier,
      credentialType,
      credentialX5c,
      trustedCertificates,
      expectedCredentialMetadataUri,
    } = options

    const jwt = Jwt.fromSerializedJwt(compactJwt)

    // Step 1
    const headerResult = zCredentialMetadataJwtHeader.safeParse(jwt.header)
    if (!headerResult.success) {
      throw new Error(`Step 1 failed: invalid JOSE header — ${headerResult.error.message}`)
    }
    const header = headerResult.data

    // Steps 2 + 3
    const jwsService = agentContext.dependencyManager.resolve(JwsService)
    const { isValid } = await jwsService.verifyJws(agentContext, { jws: compactJwt, trustedCertificates })
    if (!isValid) {
      throw new Error('Steps 2/3 failed: JWT signature or certificate chain verification failed')
    }

    const payloadResult = zCredentialMetadataJwtPayload.safeParse(jwt.payload.toJson())
    if (!payloadResult.success) {
      throw new Error(`Payload validation failed — ${payloadResult.error.message}`)
    }
    const payload = payloadResult.data

    // Step 4
    if (payload.iss !== issuerIdentifier) {
      throw new Error(`Step 4 failed: iss '${payload.iss}' does not match expected issuer '${issuerIdentifier}'`)
    }

    // Step 5
    if (payload.exp <= nowEpochSeconds()) {
      throw new Error(`Step 5 failed: JWT expired at ${payload.exp}`)
    }

    if (expectedCredentialMetadataUri && payload.credential_metadata_uri !== expectedCredentialMetadataUri) {
      throw new Error(
        `credential_metadata_uri mismatch: payload contains '${payload.credential_metadata_uri}' but was fetched from '${expectedCredentialMetadataUri}'`
      )
    }

    // Step 6a
    if (payload.sub !== credentialType) {
      throw new Error(`Step 6a failed: sub '${payload.sub}' does not match credential type '${credentialType}'`)
    }

    // Step 6b+6c
    const metadataLeaf = X509Certificate.fromEncodedCertificate(header.x5c[0])
    const credentialLeaf = X509Certificate.fromEncodedCertificate(credentialX5c[0])
    const metadataRoot =
      header.x5c.length === 1 ? metadataLeaf : X509Certificate.fromEncodedCertificate(header.x5c[header.x5c.length - 1])
    const credentialRoot =
      credentialX5c.length === 1
        ? credentialLeaf
        : X509Certificate.fromEncodedCertificate(credentialX5c[credentialX5c.length - 1])

    if (metadataRoot.subject !== credentialRoot.subject) {
      throw new Error(
        `Step 6b failed: root CA subject '${metadataRoot.subject}' does not match credential root CA '${credentialRoot.subject}'`
      )
    }

    if (metadataLeaf.subject !== credentialLeaf.subject) {
      throw new Error(
        `Step 6c failed: leaf Subject '${metadataLeaf.subject}' does not match credential leaf Subject '${credentialLeaf.subject}'`
      )
    }

    const metadataIntegrity = this.computeMetadataIntegrity(compactJwt)
    return { header, payload, compactJwt, metadataIntegrity }
  }

  private async fetchFromUri(uri: string, accept: string, acceptLanguage?: string): Promise<Response> {
    const headers: Record<string, string> = { Accept: accept }
    if (acceptLanguage) headers['Accept-Language'] = acceptLanguage

    const response = await fetch(uri, { headers })
    if (!response.ok) {
      throw new Error(`Failed to fetch credential metadata from '${uri}': HTTP ${response.status}`)
    }
    return response
  }

  private async fetchCredentialMetadataJwt(credentialMetadataUri: string, acceptLanguage?: string): Promise<string> {
    const response = await this.fetchFromUri(credentialMetadataUri, CREDENTIAL_METADATA_JWT_MEDIA_TYPE, acceptLanguage)
    const body = await response.text()
    if (!body || body.split('.').length !== 3) {
      throw new Error(`Response from '${credentialMetadataUri}' is not a valid compact JWT`)
    }
    return body
  }

  private async fetchUnsignedCredentialMetadata(
    credentialMetadataUri: string,
    acceptLanguage?: string
  ): Promise<import('@animo-id/eudi-wallet-ts12-validation').CredentialMetadata> {
    const response = await this.fetchFromUri(credentialMetadataUri, 'application/json', acceptLanguage)
    const json = await response.json()
    const result = zCredentialMetadata.safeParse(json)
    if (!result.success) {
      throw new Error(`Unsigned credential metadata validation failed — ${result.error.message}`)
    }
    return result.data
  }
}
