import type {
  ClaimMetadata,
  ScaCredentialMetadata,
  ScaTransactionDataEntry,
  TransactionDataType,
} from '@animo-id/eudi-wallet-ts12-validation'
import { selectLocaleEntry } from './locale-lookup'
import {
  filterSupportedDisplayEntries,
  resolveAllClaims,
  validateMandatoryClaims,
  validateNoUndeclaredPayloadFields,
} from './resolve-claims'
import { resolveAllUiLabels } from './resolve-ui-labels'
import type { ResolvedTransactionDisplay, ValueTypeResolvers } from './types'

/**
 * TS12 Section 3.5.4 — Verify that every `display` array across all claims
 * and UI label entries can produce a match for the given locale.
 *
 * Display entries with an unsupported `display_type` are excluded from matching
 * per Section 3.5.2.
 */
export function verifyLocaleSupport(
  typeMetadata: TransactionDataType,
  locale: string,
  resolvers: ValueTypeResolvers
): boolean {
  for (const claim of typeMetadata.claims) {
    if ('display' in claim && Array.isArray((claim as Record<string, unknown>).display)) {
      const display = (claim as { display: Array<{ locale?: string; display_type?: string }> }).display
      const supported = filterSupportedDisplayEntries(display, resolvers)
      if (!selectLocaleEntry(supported, locale)) return false
    }
  }

  for (const entries of Object.values(typeMetadata.ui_labels)) {
    if (Array.isArray(entries)) {
      if (!selectLocaleEntry(entries as Array<{ locale?: string }>, locale)) return false
    }
  }

  return true
}

/**
 * Attempt full resolution for a single locale.
 *
 * Returns `undefined` if locale matching, claim resolution,
 * or UI label interpolation fails for this locale.
 */
function tryResolveForLocale(
  typeMetadata: TransactionDataType,
  typeKey: string,
  payload: Record<string, unknown>,
  locale: string,
  resolvers: ValueTypeResolvers
): ResolvedTransactionDisplay | undefined {
  if (!verifyLocaleSupport(typeMetadata, locale, resolvers)) return undefined

  const claims = resolveAllClaims(typeMetadata.claims as ClaimMetadata[], payload, locale, resolvers)
  if (!claims) return undefined

  const uiLabels = resolveAllUiLabels(
    typeMetadata.ui_labels as Record<string, Array<{ locale?: string; value: string; value_type?: string }>>,
    locale,
    typeMetadata.claims as ClaimMetadata[],
    payload,
    resolvers
  )
  if (!uiLabels) return undefined

  return { locale, type: typeKey, claims, ui_labels: uiLabels }
}

/**
 * TS12 Sections 3.3, 3.5.1–3.5.4 — Resolve the transaction display.
 *
 * Accepts a single locale or an ordered priority list per Section 3.5.4.
 * Tries each locale in order:
 * 1. Match the transaction type to a key in `transaction_data_types`.
 * 2. Check mandatory claims are present (locale-independent).
 * 3. For each locale: verify all display arrays match, resolve claims + UI labels.
 * 4. Return the first locale that fully resolves, with the selected locale in the result.
 *
 * Returns `undefined` if the type is not found, mandatory claims are missing,
 * or no locale in the list produces a complete resolution.
 */
export function resolveTransactionDisplay(
  transactionData: ScaTransactionDataEntry,
  credentialMetadata: ScaCredentialMetadata,
  locales: string | string[],
  resolvers: ValueTypeResolvers
): ResolvedTransactionDisplay | undefined {
  const typeKey = transactionData.type
  const typeMetadata = credentialMetadata.transaction_data_types[typeKey]
  if (!typeMetadata) return undefined

  // Locale-independent checks (Section 3.3 step 3)
  if (!validateMandatoryClaims(typeMetadata.claims as ClaimMetadata[], transactionData.payload)) {
    return undefined
  }
  if (!validateNoUndeclaredPayloadFields(typeMetadata.claims as ClaimMetadata[], transactionData.payload)) {
    return undefined
  }

  const localeList = Array.isArray(locales) ? locales : [locales]

  for (const locale of localeList) {
    const result = tryResolveForLocale(typeMetadata, typeKey, transactionData.payload, locale, resolvers)
    if (result) return result
  }

  return undefined
}
