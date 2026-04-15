import { BaseRecord, type TagsBase, utils } from '@credo-ts/core'

type DefaultCredentialMetadataHistoryRecordTags = {
  /** Links to the credential record this history entry belongs to. */
  credentialRecordId: string
}

export type CredentialMetadataHistoryRecordProps = {
  id?: string
  createdAt?: Date
  tags?: TagsBase

  /** The archived signed JWT. */
  compactJwt: string
  /** The credential record this history entry belongs to. */
  credentialRecordId: string
  /** When this JWT was archived (replaced by a newer version). */
  archivedAt: Date
}

/**
 * TS12 Section 8.3 — Archived signed credential metadata JWT for audit.
 *
 * Each record stores a previously-used signed metadata JWT that was
 * replaced during a renewal or re-fetch. The full history enables
 * retrospective audit and dispute resolution.
 */
export class CredentialMetadataHistoryRecord extends BaseRecord<DefaultCredentialMetadataHistoryRecordTags> {
  static readonly type = 'CredentialMetadataHistoryRecord' as const
  readonly type = CredentialMetadataHistoryRecord.type

  compactJwt!: string
  credentialRecordId!: string
  archivedAt!: Date

  constructor(props: CredentialMetadataHistoryRecordProps) {
    super()
    this.id = props.id ?? utils.uuid()
    this.createdAt = props.createdAt ?? new Date()
    this._tags = props.tags ?? {}
    this.compactJwt = props.compactJwt
    this.credentialRecordId = props.credentialRecordId
    this.archivedAt = props.archivedAt
  }

  getTags() {
    return {
      ...this._tags,
      credentialRecordId: this.credentialRecordId,
    }
  }
}
