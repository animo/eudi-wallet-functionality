// biome-ignore lint/style/useImportType: DI requires runtime class references for EventEmitter and StorageService
import { type AgentContext, EventEmitter, Repository, StorageService } from '@credo-ts/core'
import { CredentialMetadataJwtRecord } from './credential-metadata-jwt-record'

export class CredentialMetadataJwtRepository extends Repository<CredentialMetadataJwtRecord> {
  constructor(storageService: StorageService<CredentialMetadataJwtRecord>, eventEmitter: EventEmitter) {
    super(CredentialMetadataJwtRecord, storageService, eventEmitter)
  }

  async findByCredentialRecordId(
    agentContext: AgentContext,
    credentialRecordId: string
  ): Promise<CredentialMetadataJwtRecord | null> {
    return this.findSingleByQuery(agentContext, { credentialRecordId })
  }

  /** @throws if no metadata is stored for this credential. */
  async getByCredentialRecordId(
    agentContext: AgentContext,
    credentialRecordId: string
  ): Promise<CredentialMetadataJwtRecord> {
    const record = await this.findByCredentialRecordId(agentContext, credentialRecordId)
    if (!record) {
      throw new Error(`No credential metadata JWT found for credential record '${credentialRecordId}'`)
    }
    return record
  }
}
