import type { ResolvedTransactionDisplay } from '@animo-id/eudi-wallet-ts12-resolver'
import { resolveTransactionDisplay, selectLocaleEntry } from '@animo-id/eudi-wallet-ts12-resolver'
import type { ScaCredentialMetadata, ScaTransactionDataEntry } from '@animo-id/eudi-wallet-ts12-validation'
import { defaultScaTypeMatcher } from '@animo-id/eudi-wallet-ts12-validation'
import type {
  CredentialDisplayEntry,
  DcqlClaimsQuery,
  MatchedCredential,
  ResolvedCredentialDisplay,
  ResolvedWalletCredential,
  TransactionDataInput,
  WalletConfiguration,
} from './types'

/**
 * Resolve credential display metadata for a single locale.
 * Selects the locale-matched SVG template if the wallet supports it.
 */
export function resolveCredentialDisplay(
  display: CredentialDisplayEntry[],
  locale: string,
  _config: WalletConfiguration
): ResolvedCredentialDisplay | undefined {
  const entry = selectLocaleEntry(display, locale)
  if (!entry) return undefined

  return {
    name: entry.name,
    description: entry.description,
    logo: entry.logo,
    background_color: entry.background_color,
    text_color: entry.text_color,
  }
}

/**
 * TS12 Section 3.3 step 3 — First-match rule for SCA transaction data.
 */
export function resolveFirstMatchScaTransactionData(
  scaMetadata: ScaCredentialMetadata,
  credentialQueryId: string,
  transactionData: TransactionDataInput[],
  locale: string,
  config: WalletConfiguration
): { index: number; entry: TransactionDataInput; resolved: ResolvedTransactionDisplay } | undefined {
  const isScaType = config.scaTypeMatcher ?? defaultScaTypeMatcher
  for (let i = 0; i < transactionData.length; i++) {
    const td = transactionData[i]
    if (!isScaType(td.type)) continue
    if (!td.credential_ids.includes(credentialQueryId)) continue

    const resolved = resolveTransactionDisplay(
      td as ScaTransactionDataEntry,
      scaMetadata,
      locale,
      config.valueTypeResolvers
    )
    if (resolved) return { index: i, entry: td, resolved }
  }
  return undefined
}

/**
 * Find the first non-SCA transaction_data entry targeting a credential query ID
 * whose type is supported by the credential.
 *
 * Uses `config.checkNonScaTransactionDataSupport` to verify compatibility.
 * If the check function is absent, no non-SCA entry can match (incompatible).
 */
export function findFirstNonScaTransactionData(
  credentialId: string,
  credentialQueryId: string,
  transactionData: TransactionDataInput[],
  config: WalletConfiguration
): { index: number; entry: TransactionDataInput } | undefined {
  if (!config.checkNonScaTransactionDataSupport) return undefined

  const isScaType = config.scaTypeMatcher ?? defaultScaTypeMatcher
  for (let i = 0; i < transactionData.length; i++) {
    const td = transactionData[i]
    if (isScaType(td.type)) continue
    if (!td.credential_ids.includes(credentialQueryId)) continue
    if (!config.checkNonScaTransactionDataSupport(credentialId, td.type)) continue
    return { index: i, entry: td }
  }
  return undefined
}

/**
 * Find the first matching transaction_data entry for a credential.
 * Tries SCA entries first (with full resolution), then non-SCA (with support check).
 */
export function resolveTransactionDataForCredential(
  credential: MatchedCredential,
  credentialQueryId: string,
  transactionData: TransactionDataInput[],
  locale: string,
  config: WalletConfiguration
): { index: number; entry: TransactionDataInput; resolved?: ResolvedTransactionDisplay } | undefined {
  if (credential.scaMetadata) {
    const sca = resolveFirstMatchScaTransactionData(
      credential.scaMetadata,
      credentialQueryId,
      transactionData,
      locale,
      config
    )
    if (sca) return sca
  }

  return findFirstNonScaTransactionData(credential.credentialId, credentialQueryId, transactionData, config)
}

/**
 * Check if a credential's display arrays can be locale-resolved for a given locale.
 */
export function canResolveCredentialForLocale(
  credential: MatchedCredential,
  credentialQueryId: string,
  transactionData: TransactionDataInput[],
  locale: string,
  config: WalletConfiguration
): boolean {
  if (credential.display && credential.display.length > 0) {
    if (!selectLocaleEntry(credential.display, locale)) return false
  }

  const isScaType = config.scaTypeMatcher ?? defaultScaTypeMatcher
  if (credential.scaMetadata) {
    const hasScaEntry = transactionData.some(
      (td) => isScaType(td.type) && td.credential_ids.includes(credentialQueryId)
    )
    if (hasScaEntry) {
      if (
        !resolveFirstMatchScaTransactionData(credential.scaMetadata, credentialQueryId, transactionData, locale, config)
      ) {
        return false
      }
    }
  }

  return true
}

/**
 * Fully resolve a single wallet credential for a given locale.
 */
export function resolveWalletCredential(
  credential: MatchedCredential,
  credentialQueryId: string,
  requestedClaims: DcqlClaimsQuery[] | undefined,
  transactionData: TransactionDataInput[],
  locale: string,
  config: WalletConfiguration
): ResolvedWalletCredential {
  const display = credential.display ? resolveCredentialDisplay(credential.display, locale, config) : undefined
  const td = resolveTransactionDataForCredential(credential, credentialQueryId, transactionData, locale, config)

  return {
    credentialId: credential.credentialId,
    credentialQueryId,
    display,
    requestedClaims,
    transactionData: td,
  }
}

/**
 * Check whether a credential query ID is targeted by any transaction_data entry.
 */
export function isTargetedByTransactionData(
  credentialQueryId: string,
  transactionData: TransactionDataInput[]
): boolean {
  return transactionData.some((td) => td.credential_ids.includes(credentialQueryId))
}

/**
 * Resolve all matched credentials for a DCQL credential query ID.
 *
 * If the query is targeted by transaction_data, credentials that fail to resolve
 * any matching transaction_data entry are excluded — they cannot fulfil the
 * transaction requirement.
 */
export function resolveAllMatchedCredentials(
  matchedCredentials: MatchedCredential[],
  credentialQueryId: string,
  requestedClaims: DcqlClaimsQuery[] | undefined,
  transactionData: TransactionDataInput[],
  locale: string,
  config: WalletConfiguration
): ResolvedWalletCredential[] {
  const targeted = isTargetedByTransactionData(credentialQueryId, transactionData)

  const resolved = matchedCredentials.map((cred) =>
    resolveWalletCredential(cred, credentialQueryId, requestedClaims, transactionData, locale, config)
  )

  if (!targeted) return resolved

  // Only keep credentials where transaction data resolved
  return resolved.filter((cred) => cred.transactionData !== undefined)
}
