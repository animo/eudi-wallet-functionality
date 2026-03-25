import { isScaTransactionType } from '@animo-id/eudi-wallet-ts12-validation'
import { bestEffortDecompose, decomposeTransposable, type SlotDecomposition } from './cartesian'
import { resolveAllMatchedCredentials } from './resolve-credentials'
import { err, ok, type Result } from './result'
import type {
  CredentialMatcher,
  DcqlCredentialQuery,
  DcqlCredentialSetQuery,
  ResolvedCredentialSet,
  ResolvedSlot,
  SlotAlternative,
  TransactionDataInput,
  WalletConfiguration,
} from './types'

// =============================================================================
// Shared helpers
// =============================================================================

/**
 * Check whether an option is satisfiable: the wallet has at least one matching
 * credential for every DCQL query in the option.
 */
export function isOptionSatisfiable(
  option: string[],
  queries: Map<string, DcqlCredentialQuery>,
  matchCredentials: CredentialMatcher
): boolean {
  return option.every((id) => {
    const query = queries.get(id)
    return query ? matchCredentials(query).length > 0 : false
  })
}

/**
 * Find the first satisfiable option in the credential set.
 */
export function findFirstSatisfiableOption(
  options: string[][],
  queries: Map<string, DcqlCredentialQuery>,
  matchCredentials: CredentialMatcher
): string[] | undefined {
  return options.find((opt) => isOptionSatisfiable(opt, queries, matchCredentials))
}

/**
 * Order slots so their position matches the ID order in the reference option.
 */
export function orderSlotsByReference(slots: SlotDecomposition[], referenceOption: string[]): SlotDecomposition[] {
  return [...slots].sort((a, b) => {
    const posA = Math.min(
      ...a.ids.map((id) => {
        const idx = referenceOption.indexOf(id)
        return idx === -1 ? Number.MAX_SAFE_INTEGER : idx
      })
    )
    const posB = Math.min(
      ...b.ids.map((id) => {
        const idx = referenceOption.indexOf(id)
        return idx === -1 ? Number.MAX_SAFE_INTEGER : idx
      })
    )
    return posA - posB
  })
}

/**
 * Build a ResolvedSlot from a slot decomposition for a given locale.
 */
export function buildResolvedSlot(
  slot: SlotDecomposition,
  queries: Map<string, DcqlCredentialQuery>,
  transactionData: TransactionDataInput[],
  matchCredentials: CredentialMatcher,
  locale: string,
  config: WalletConfiguration
): ResolvedSlot {
  const alternatives: SlotAlternative[] = slot.ids.map((credentialQueryId) => {
    const query = queries.get(credentialQueryId)
    const matched = query ? matchCredentials(query) : []
    const credentials = resolveAllMatchedCredentials(
      matched,
      credentialQueryId,
      query?.claims,
      transactionData,
      locale,
      config
    )
    return { credentialQueryId, credentials }
  })

  return { optional: slot.optional, alternatives }
}

// =============================================================================
// SCA — strict TS12 resolution
// =============================================================================

/**
 * Collect the set of DCQL credential query IDs referenced by SCA transaction_data entries.
 */
export function collectScaCredentialQueryIds(transactionData: TransactionDataInput[]): Set<string> {
  const ids = new Set<string>()
  for (const td of transactionData) {
    if (isScaTransactionType(td.type)) {
      for (const id of td.credential_ids) ids.add(id)
    }
  }
  return ids
}

/**
 * Partition options into SCA-targeted and non-SCA groups.
 */
export function partitionOptions(
  options: string[][],
  scaCredentialQueryIds: Set<string>
): { sca: string[][]; nonSca: string[][] } {
  const sca: string[][] = []
  const nonSca: string[][] = []
  for (const opt of options) {
    if (opt.some((id) => scaCredentialQueryIds.has(id))) {
      sca.push(opt)
    } else {
      nonSca.push(opt)
    }
  }
  return { sca, nonSca }
}

/**
 * Resolve a credential set under strict TS12 rules.
 *
 * SCA-targeted options MUST be transposable (TS12 Section 3.4) — returns `Err` if not.
 * Non-SCA options within the same set use best-effort decomposition.
 */
export function resolveScaCredentialSet(
  credentialSet: DcqlCredentialSetQuery,
  queries: Map<string, DcqlCredentialQuery>,
  transactionData: TransactionDataInput[],
  matchCredentials: CredentialMatcher,
  locale: string,
  config: WalletConfiguration
): Result<ResolvedCredentialSet> {
  const { options, description } = credentialSet
  const required = credentialSet.required !== false

  const firstSatisfiable = findFirstSatisfiableOption(options, queries, matchCredentials)
  const scaQueryIds = collectScaCredentialQueryIds(transactionData)
  const { sca, nonSca } = partitionOptions(options, scaQueryIds)

  // SCA options: strict transposability
  let scaSlots: SlotDecomposition[] = []
  if (sca.length > 0) {
    const decomposed = decomposeTransposable(sca)
    if (!decomposed) {
      return err('SCA-targeted options are not transposable (TS12 Section 3.4)')
    }
    scaSlots = decomposed
  }

  // Non-SCA options within the same set: best-effort
  const nonScaSlots = bestEffortDecompose(nonSca)

  // Merge: SCA slots first, then non-SCA slots with new IDs only
  const allScaIds = new Set(scaSlots.flatMap((s) => s.ids))
  const mergedSlots = [...scaSlots]
  for (const slot of nonScaSlots) {
    const newIds = slot.ids.filter((id) => !allScaIds.has(id))
    if (newIds.length > 0) {
      mergedSlots.push({ ids: newIds, optional: slot.optional })
    }
  }

  const ordered = firstSatisfiable ? orderSlotsByReference(mergedSlots, firstSatisfiable) : mergedSlots
  const slots = ordered.map((slot) =>
    buildResolvedSlot(slot, queries, transactionData, matchCredentials, locale, config)
  )

  return ok({ description, required, slots })
}

// =============================================================================
// Non-SCA — best-effort resolution
// =============================================================================

/**
 * Resolve a credential set with best-effort decomposition.
 *
 * No transposability requirement — uses `bestEffortDecompose` on all options.
 * Never returns `Err` for decomposition issues.
 */
export function resolveNonScaCredentialSet(
  credentialSet: DcqlCredentialSetQuery,
  queries: Map<string, DcqlCredentialQuery>,
  transactionData: TransactionDataInput[],
  matchCredentials: CredentialMatcher,
  locale: string,
  config: WalletConfiguration
): ResolvedCredentialSet {
  const { options, description } = credentialSet
  const required = credentialSet.required !== false

  const firstSatisfiable = findFirstSatisfiableOption(options, queries, matchCredentials)
  const decomposed = bestEffortDecompose(options)
  const ordered = firstSatisfiable ? orderSlotsByReference(decomposed, firstSatisfiable) : decomposed

  const slots = ordered.map((slot) =>
    buildResolvedSlot(slot, queries, transactionData, matchCredentials, locale, config)
  )

  return { description, required, slots }
}
