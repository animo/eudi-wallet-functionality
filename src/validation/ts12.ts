import { z } from 'zod'
import { Ts12IntegrityError } from '../error'
import { type MergeConfig, mergeJson } from '../merge-json'
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
    display: Array<{ name: string; locale?: string; logo?: string }>
  }>
  ui_labels: {
    affirmative_action_label: Array<{ locale: string; value: string }>
    denial_action_label?: Array<{ locale: string; value: string }>
    transaction_title?: Array<{ locale: string; value: string }>
    security_hint?: Array<{ locale: string; value: string }>
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
  subtype?: string,
  validateIntegrity?: (buf: ArrayBuffer, integrity: string) => boolean
): Promise<ResolvedTs12Metadata | undefined> {
  if (!metadata.transaction_data_types) {
    return undefined
  }

  const typeMetadata = metadata.transaction_data_types.find((t) => t.type === type && t.subtype === subtype)

  if (!typeMetadata) {
    return undefined
  }

  const resolved: Partial<ResolvedTs12Metadata> = {}

  if (typeMetadata.type in ts12BuiltinSchemaValidators) {
    resolved.schema = typeMetadata.type
  } else if (typeMetadata.type.startsWith('http')) {
    resolved.schema = await fetchVerified(
      typeMetadata.type,
      z.object({}),
      typeMetadata['type#integrity'],
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

export const baseMergeConfig = {
  fields: {
    // [Display Metadata]
    // RULE: COMPLETE REPLACEMENT
    display: {
      strategy: 'replace',
    },

    // [Claim Metadata]
    // RULE: MERGE BY PATH
    claims: {
      strategy: 'merge',
      arrayDiscriminant: 'path',
      items: {
        fields: {
          // Constraint Rule: 'sd' (Selective Disclosure)
          sd: {
            validate: (target: unknown, source: unknown) => {
              // Parent: "always" -> Child: MUST remain "always"
              if (target === 'always' && source !== 'always') {
                throw new Error("Constraint violation: 'sd' cannot change from 'always'")
              }
              // Parent: "never" -> Child: MUST remain "never"
              if (target === 'never' && source !== 'never') {
                throw new Error("Constraint violation: 'sd' cannot change from 'never'")
              }
            },
          },
          // Constraint Rule: 'mandatory'
          mandatory: {
            validate: (target: unknown, source: unknown) => {
              // Parent: true -> Child: MUST remain true
              if (target === true && source !== true) {
                throw new Error("Constraint violation: 'mandatory' cannot change from true to false")
              }
            },
          },
        },
      },
    },
  },
} as const satisfies MergeConfig

export const ts12MergeConfig = mergeJson(baseMergeConfig, {
  fields: {
    transaction_data_types: {
      arrayStrategy: 'append', // Default for unknown arrays
      strategy: 'merge',
      arrayDiscriminant: ['type', 'subtype'],
      items: {
        fields: {
          claims: {
            strategy: 'merge',
            arrayDiscriminant: 'path',
            items: {
              fields: {
                // Display: Merge by locale
                display: {
                  strategy: 'merge',
                  arrayDiscriminant: 'locale',
                },
              },
            },
          },
          ui_labels: {
            strategy: 'merge',
            // Use 'items' to apply configuration to all properties of the ui_labels object
            items: {
              strategy: 'merge',
              arrayDiscriminant: 'locale',
            },
          },
        },
      },
    },
  },
} as const satisfies MergeConfig) satisfies MergeConfig
