import type { AgentContext } from '@credo-ts/core'
import type { CredentialMetadataWalletStore, StoredCredentialMetadataJwt } from '@animo-id/eudi-wallet-ts12-credential-metadata-wallet'
import { CredentialMetadataHistoryRecord } from './credential-metadata-history-record'
import { CredentialMetadataHistoryRepository } from './credential-metadata-history-repository'
import { CredentialMetadataJwtRecord } from './credential-metadata-jwt-record'
import { CredentialMetadataJwtRepository } from './credential-metadata-jwt-repository'

function recordToStored(record: CredentialMetadataJwtRecord): StoredCredentialMetadataJwt {
  return {
    id: record.id,
    compactJwt: record.compactJwt,
    credentialMetadataUri: record.credentialMetadataUri,
    issuerIdentifier: record.issuerIdentifier,
    credentialType: record.credentialType,
    format: record.format,
    expiresAtSeconds: record.expiresAtSeconds,
    credentialRecordId: record.credentialRecordId,
  }
}

/**
 * Create a {@link CredentialMetadataWalletStore} backed by Credo repositories.
 *
 * Resolves `CredentialMetadataJwtRepository` and `CredentialMetadataHistoryRepository`
 * from the agent's dependency manager.
 */
export function createCredoStore(agentContext: AgentContext): CredentialMetadataWalletStore {
  const jwtRepo = agentContext.dependencyManager.resolve(CredentialMetadataJwtRepository)
  const historyRepo = agentContext.dependencyManager.resolve(CredentialMetadataHistoryRepository)

  return {
    async findByCredentialRecordId(credentialRecordId) {
      const record = await jwtRepo.findByCredentialRecordId(agentContext, credentialRecordId)
      return record ? recordToStored(record) : null
    },

    async getByCredentialRecordId(credentialRecordId) {
      const record = await jwtRepo.getByCredentialRecordId(agentContext, credentialRecordId)
      return recordToStored(record)
    },

    async save(stored) {
      const record = new CredentialMetadataJwtRecord({
        id: stored.id,
        compactJwt: stored.compactJwt,
        credentialMetadataUri: stored.credentialMetadataUri,
        issuerIdentifier: stored.issuerIdentifier,
        credentialType: stored.credentialType,
        format: stored.format,
        expiresAtSeconds: stored.expiresAtSeconds,
        credentialRecordId: stored.credentialRecordId,
      })
      await jwtRepo.save(agentContext, record)
    },

    async update(stored) {
      const record = await jwtRepo.getByCredentialRecordId(agentContext, stored.credentialRecordId)
      record.compactJwt = stored.compactJwt
      record.credentialMetadataUri = stored.credentialMetadataUri
      record.issuerIdentifier = stored.issuerIdentifier
      record.credentialType = stored.credentialType
      record.format = stored.format
      record.expiresAtSeconds = stored.expiresAtSeconds
      await jwtRepo.update(agentContext, record)
    },

    async appendToHistory(credentialRecordId, compactJwt) {
      const historyRecord = new CredentialMetadataHistoryRecord({
        compactJwt,
        credentialRecordId,
        archivedAt: new Date(),
      })
      await historyRepo.save(agentContext, historyRecord)
    },

    async getHistory(credentialRecordId) {
      const records = await historyRepo.findAllByCredentialRecordId(agentContext, credentialRecordId)
      return records.map((r) => r.compactJwt)
    },
  }
}
