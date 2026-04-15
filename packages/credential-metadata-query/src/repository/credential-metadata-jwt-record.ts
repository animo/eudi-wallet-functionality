import { BaseRecord, type TagsBase, utils } from '@credo-ts/core'

type DefaultCredentialMetadataJwtRecordTags = {
  /** Links to the credential record (SdJwtVcRecord/MdocRecord) by id. */
  credentialRecordId: string
  /** The credential type identifier (vct or doctype) for querying. */
  credentialType: string
  /** The Credential Issuer Identifier. */
  issuerIdentifier: string
}

export type CredentialMetadataJwtRecordProps = {
  id?: string
  createdAt?: Date
  tags?: TagsBase

  /** The raw signed JWT — persisted in signed form per Section 4.1.3. */
  compactJwt: string
  /** The credential_metadata_uri for re-fetch (Section 4.1.4). */
  credentialMetadataUri: string
  /** The Credential Issuer Identifier (for step 4 verification). */
  issuerIdentifier: string
  /** The credential type identifier — vct or doctype (for step 6a). */
  credentialType: string
  /** The credential format identifier (e.g., 'dc+sd-jwt', 'mso_mdoc'). */
  format: string
  /** The exp claim as epoch seconds, for renewal checks (Section 4.1.4). */
  expiresAtSeconds: number
  /** The id of the linked credential record. */
  credentialRecordId: string
}

/**
 * TS12 Section 4.1.3 — Persisted signed credential metadata JWT.
 *
 * Each record is linked to a credential record (SdJwtVcRecord/MdocRecord)
 * via the `credentialRecordId` tag. The Wallet Unit SHALL persist the signed
 * credential metadata JWT in its signed form and SHALL NOT persist the decoded
 * credential metadata.
 */
export class CredentialMetadataJwtRecord extends BaseRecord<DefaultCredentialMetadataJwtRecordTags> {
  static readonly type = 'CredentialMetadataJwtRecord' as const
  readonly type = CredentialMetadataJwtRecord.type

  compactJwt!: string
  credentialMetadataUri!: string
  issuerIdentifier!: string
  credentialType!: string
  format!: string
  expiresAtSeconds!: number
  credentialRecordId!: string

  constructor(props: CredentialMetadataJwtRecordProps) {
    super()
    this.id = props.id ?? utils.uuid()
    this.createdAt = props.createdAt ?? new Date()
    this._tags = props.tags ?? {}
    this.compactJwt = props.compactJwt
    this.credentialMetadataUri = props.credentialMetadataUri
    this.issuerIdentifier = props.issuerIdentifier
    this.credentialType = props.credentialType
    this.format = props.format
    this.expiresAtSeconds = props.expiresAtSeconds
    this.credentialRecordId = props.credentialRecordId
  }

  getTags() {
    return {
      ...this._tags,
      credentialRecordId: this.credentialRecordId,
      credentialType: this.credentialType,
      issuerIdentifier: this.issuerIdentifier,
    }
  }
}
