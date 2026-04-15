import { defaultScaTypeMatcher } from '@animo-id/eudi-wallet-ts12-validation'
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
/**
 * Build a lookup map from credential query ID to query object.
 * Returns undefined if duplicate IDs are found (OID4VP §6.1: "the same id MUST NOT be present more than once").
 */
export function buildCredentialQueryMap(
  credentials: DcqlCredentialQuery[]
): Map<string, DcqlCredentialQuery> | undefined {
  const map = new Map<string, DcqlCredentialQuery>()
  for (const q of credentials) {
    if (map.has(q.id)) return undefined
    map.set(q.id, q)
  }
  return map
}

/**
 * Check whether any transaction_data entry is SCA-compatible per the given matcher.
 */
export function hasScaTransactionData(transactionData: TransactionDataInput[], config: WalletConfiguration): boolean {
  const isScaType = config.scaTypeMatcher ?? defaultScaTypeMatcher
  return transactionData.some((td) => isScaType(td.type))
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
 * OID4VP §6.1, §6.4.1 — Validate DCQL query structural constraints.
 *
 * - §6.1: "the same id MUST NOT be present more than once"
 * - §6.4.1: "claim_sets MUST NOT be present if claims is absent"
 */
export function validateDcqlQueryStructure(dcqlQuery: DcqlQuery): string | undefined {
  const seenIds = new Set<string>()
  for (const q of dcqlQuery.credentials) {
    if (seenIds.has(q.id)) {
      return `Duplicate credential query id '${q.id}' (OID4VP §6.1)`
    }
    seenIds.add(q.id)

    if (q.claim_sets && !q.claims) {
      return `Credential query '${q.id}' has claim_sets but no claims (OID4VP §6.4.1)`
    }
  }
  return undefined
}

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
 * Detects whether the request involves SCA using `config.scaTypeMatcher`:
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
  const queryValidationError = validateDcqlQueryStructure(dcqlQuery)
  if (queryValidationError) return err(queryValidationError)

  // buildCredentialQueryMap is guaranteed to succeed after validation
  const queries = buildCredentialQueryMap(dcqlQuery.credentials) as Map<string, DcqlCredentialQuery>

  const credentialSets = dcqlQuery.credential_sets

  // OID4VP §6.4.2: "If credential_sets is not provided, the Verifier requests
  // presentations for all Credentials in credentials to be returned."
  const effectiveCredentialSets: DcqlCredentialSetQuery[] =
    credentialSets && credentialSets.length > 0
      ? credentialSets
      : dcqlQuery.credentials.map((q) => ({ options: [[q.id]], required: true }))

  const validationError = validateTransactionDataCredentialSet(dcqlQuery, transactionData)
  if (validationError) return err(validationError)

  if (hasScaTransactionData(transactionData, config)) {
    return resolveScaDcql(effectiveCredentialSets, queries, transactionData, matchCredentials, config)
  }

  return resolveNonScaDcql(effectiveCredentialSets, queries, transactionData, matchCredentials, config)
}
