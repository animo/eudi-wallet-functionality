// biome-ignore lint/style/useImportType: DI requires runtime class references for EventEmitter and StorageService
import { type AgentContext, EventEmitter, Repository, StorageService } from '@credo-ts/core'
import { CredentialMetadataHistoryRecord } from './credential-metadata-history-record'

export class CredentialMetadataHistoryRepository extends Repository<CredentialMetadataHistoryRecord> {
  constructor(storageService: StorageService<CredentialMetadataHistoryRecord>, eventEmitter: EventEmitter) {
    super(CredentialMetadataHistoryRecord, storageService, eventEmitter)
  }

  /** Get all history entries for a credential, sorted oldest to most recent. */
  async findAllByCredentialRecordId(
    agentContext: AgentContext,
    credentialRecordId: string
  ): Promise<CredentialMetadataHistoryRecord[]> {
    const records = await this.findByQuery(agentContext, { credentialRecordId })
    return records.sort((a, b) => a.archivedAt.getTime() - b.archivedAt.getTime())
  }
}
