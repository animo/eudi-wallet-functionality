import { isScaTransactionType } from '@animo-id/eudi-wallet-ts12-validation'
import { resolveNonScaCredentialSet, resolveScaCredentialSet } from './resolve-credential-set'
import { canResolveCredentialForLocale } from './resolve-credentials'
import { err, isErr, ok, type Result } from './result'
import type {
  CredentialMatcher,
  DcqlCredentialQuery,
  DcqlCredentialSetQuery,
  DcqlQuery,
  MatchedCredential,
  ResolvedCredentialSet,
  ResolvedDcqlResult,
  TransactionDataInput,
  WalletConfiguration,
} from './types'

/**
 * Build a lookup map from credential query ID to query object.
 */
export function buildCredentialQueryMap(credentials: DcqlCredentialQuery[]): Map<string, DcqlCredentialQuery> {
  const map = new Map<string, DcqlCredentialQuery>()
  for (const q of credentials) {
    map.set(q.id, q)
  }
  return map
}

/**
 * Check whether any transaction_data entry has the SCA prefix.
 */
export function hasScaTransactionData(transactionData: TransactionDataInput[]): boolean {
  return transactionData.some((td) => isScaTransactionType(td.type))
}

/**
 * Collect all (credentialQueryId, matchedCredential) pairs across all credential sets.
 */
function collectAllMatchedCredentials(
  credentialSets: DcqlCredentialSetQuery[],
  queries: Map<string, DcqlCredentialQuery>,
  matchCredentials: CredentialMatcher
): Array<{ credentialQueryId: string; credential: MatchedCredential }> {
  const allIds = new Set<string>()
  for (const cs of credentialSets) {
    for (const opt of cs.options) {
      for (const id of opt) allIds.add(id)
    }
  }

  const result: Array<{ credentialQueryId: string; credential: MatchedCredential }> = []
  for (const id of allIds) {
    const query = queries.get(id)
    if (!query) continue
    for (const cred of matchCredentials(query)) {
      result.push({ credentialQueryId: id, credential: cred })
    }
  }
  return result
}

// =============================================================================
// SCA path — strict TS12 rules
// =============================================================================

function canResolveAllForLocale(
  allMatched: Array<{ credentialQueryId: string; credential: MatchedCredential }>,
  transactionData: TransactionDataInput[],
  locale: string,
  config: WalletConfiguration
): boolean {
  return allMatched.every(({ credentialQueryId, credential }) =>
    canResolveCredentialForLocale(credential, credentialQueryId, transactionData, locale, config)
  )
}

function resolveScaDcql(
  credentialSets: DcqlCredentialSetQuery[],
  queries: Map<string, DcqlCredentialQuery>,
  transactionData: TransactionDataInput[],
  matchCredentials: CredentialMatcher,
  config: WalletConfiguration
): Result<ResolvedDcqlResult> {
  const allMatched = collectAllMatchedCredentials(credentialSets, queries, matchCredentials)

  for (const locale of config.locales) {
    if (!canResolveAllForLocale(allMatched, transactionData, locale, config)) {
      continue
    }

    const resolved: ResolvedCredentialSet[] = []
    for (const cs of credentialSets) {
      const result = resolveScaCredentialSet(cs, queries, transactionData, matchCredentials, locale, config)
      if (isErr(result)) return err(result.error)
      resolved.push(result.value)
    }

    return ok({ locale, credentialSets: resolved })
  }

  return err('No locale from the priority list could satisfy all display arrays in the SCA request')
}

// =============================================================================
// Non-SCA path — best-effort
// =============================================================================

function resolveNonScaDcql(
  credentialSets: DcqlCredentialSetQuery[],
  queries: Map<string, DcqlCredentialQuery>,
  transactionData: TransactionDataInput[],
  matchCredentials: CredentialMatcher,
  config: WalletConfiguration
): Result<ResolvedDcqlResult> {
  const allMatched = collectAllMatchedCredentials(credentialSets, queries, matchCredentials)

  let selectedLocale = config.locales[0]
  for (const locale of config.locales) {
    const allDisplayOk = allMatched.every(({ credential }) => {
      if (!credential.display || credential.display.length === 0) return true
      return credential.display.some((d) => !d.locale) || credential.display.some((d) => d.locale !== undefined)
    })
    if (allDisplayOk) {
      selectedLocale = locale
      break
    }
  }

  const resolved: ResolvedCredentialSet[] = []
  for (const cs of credentialSets) {
    resolved.push(resolveNonScaCredentialSet(cs, queries, transactionData, matchCredentials, selectedLocale, config))
  }

  return ok({ locale: selectedLocale, credentialSets: resolved })
}

// =============================================================================
// Entry point
// =============================================================================

/**
 * Validate that all credential query IDs referenced by transaction_data entries
 * appear within the options of a single credential set.
 */
export function validateTransactionDataCredentialSet(
  dcqlQuery: DcqlQuery,
  transactionData: TransactionDataInput[]
): string | undefined {
  if (transactionData.length === 0) return undefined
  if (!dcqlQuery.credential_sets || dcqlQuery.credential_sets.length === 0) return undefined

  const tdCredentialIds = new Set<string>()
  for (const td of transactionData) {
    for (const id of td.credential_ids) tdCredentialIds.add(id)
  }

  const containingSet = dcqlQuery.credential_sets.find((cs) =>
    cs.options.some((_opt) =>
      [...tdCredentialIds].every((id) => {
        return cs.options.some((o) => o.includes(id))
      })
    )
  )

  if (!containingSet) {
    return 'All transaction_data credential_ids must appear within options of the same credential set'
  }

  return undefined
}

/**
 * Resolve a DCQL query's credential sets into independent slots.
 *
 * Detects whether the request involves SCA by checking if any `transaction_data`
 * entry has the `urn:eudi:sca:` prefix:
 *
 * - **SCA present**: strict TS12 rules — locale MUST satisfy all display arrays,
 *   SCA options MUST be transposable. Returns `Err` on failure.
 * - **No SCA**: best-effort — decomposition never errors, locale is best-effort.
 *
 * In both modes, slot alternatives only include credentials that successfully
 * resolved their associated transaction data.
 */
export function resolveDcql(
  dcqlQuery: DcqlQuery,
  transactionData: TransactionDataInput[],
  matchCredentials: CredentialMatcher,
  config: WalletConfiguration
): Result<ResolvedDcqlResult> {
  const queries = buildCredentialQueryMap(dcqlQuery.credentials)
  const credentialSets = dcqlQuery.credential_sets

  if (!credentialSets || credentialSets.length === 0) {
    return ok({ locale: config.locales[0], credentialSets: [] })
  }

  const validationError = validateTransactionDataCredentialSet(dcqlQuery, transactionData)
  if (validationError) return err(validationError)

  if (hasScaTransactionData(transactionData)) {
    return resolveScaDcql(credentialSets, queries, transactionData, matchCredentials, config)
  }

  return resolveNonScaDcql(credentialSets, queries, transactionData, matchCredentials, config)
}
