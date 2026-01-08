import { z } from 'zod'
import { Ts12IntegrityError } from '../error'
import {
  type ZScaAttestationExt,
  zScaTransactionDataTypeClaims,
  zScaTransactionDataTypeUiLabels,
} from './z-sca-attestation-ext'
import { ts12BuiltinSchemaValidators } from './z-transaction-data'

export interface ResolvedTs12Metadata {
  schema: string | object
  claims: Array<{
    path: string[]
    visualisation: 1 | 2 | 3 | 4
    display: Array<{ name: string; locale?: string; logo?: string }>
  }>
  ui_labels: {
    affirmative_action_label: Array<{ lang: string; value: string }>
    denial_action_label?: Array<{ lang: string; value: string }>
    transaction_title?: Array<{ lang: string; value: string }>
    security_hint?: Array<{ lang: string; value: string }>
  }
}

async function fetchVerified<T>(
  uri: string,
  schema: z.ZodType<T>,
  integrity?: string,
  validateIntegrity?: (buf: ArrayBuffer, integrity: string) => boolean
): Promise<T> {
  const response = await fetch(uri)
  if (!response.ok) {
    throw new Error(`Failed to fetch URI: ${uri}`)
  }
  if (integrity && validateIntegrity && !validateIntegrity(await response.clone().arrayBuffer(), integrity)) {
    throw new Ts12IntegrityError(uri, integrity)
  }
  return schema.parse(await response.json())
}

export async function resolveTs12TransactionDisplayMetadata(
  metadata: ZScaAttestationExt,
  type: string,
  validateIntegrity?: (buf: ArrayBuffer, integrity: string) => boolean
): Promise<ResolvedTs12Metadata | undefined> {
  if (!metadata.transaction_data_types || !metadata.transaction_data_types[type]) {
    return undefined
  }

  const typeMetadata = metadata.transaction_data_types[type]
  const resolved: Partial<ResolvedTs12Metadata> = {}

  if ('schema' in typeMetadata && typeMetadata.schema) {
    if (!(typeMetadata.schema in ts12BuiltinSchemaValidators)) {
      throw new Error(`unknown builtin schema: ${typeMetadata.schema}`)
    }
    resolved.schema = typeMetadata.schema
  } else if ('schema_uri' in typeMetadata && typeMetadata.schema_uri) {
    resolved.schema = await fetchVerified(
      typeMetadata.schema_uri,
      z.object({}),
      typeMetadata['schema_uri#integrity'],
      validateIntegrity
    )
  } else {
    throw new Error(`Unknown schema type for ${typeMetadata}`)
  }

  if ('claims' in typeMetadata && typeMetadata.claims) {
    resolved.claims = typeMetadata.claims
  } else if ('claims_uri' in typeMetadata && typeMetadata.claims_uri) {
    resolved.claims = await fetchVerified(
      typeMetadata.claims_uri,
      zScaTransactionDataTypeClaims,
      typeMetadata['claims_uri#integrity'],
      validateIntegrity
    )
  } else {
    throw new Error(`Unknown claims for ${typeMetadata}`)
  }

  if ('ui_labels' in typeMetadata && typeMetadata.ui_labels) {
    resolved.ui_labels = typeMetadata.ui_labels
  } else if ('ui_labels_uri' in typeMetadata && typeMetadata.ui_labels_uri) {
    resolved.ui_labels = await fetchVerified(
      typeMetadata.ui_labels_uri,
      zScaTransactionDataTypeUiLabels,
      typeMetadata['ui_labels_uri#integrity'],
      validateIntegrity
    )
  } else {
    throw new Error(`Unknown ui_labels for ${typeMetadata}`)
  }

  return resolved as ResolvedTs12Metadata
}
