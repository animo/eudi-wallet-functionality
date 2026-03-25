import assert from 'node:assert'
import { describe, it } from 'node:test'
import type {
  ClaimMetadata,
  ScaCredentialMetadata,
  ScaTransactionDataEntry,
  TransactionDataType,
  UiLabelEntry,
} from '@animo-id/eudi-wallet-ts12-validation'
import type { ValueTypeResolvers } from '../packages/resolver/src/index'
import {
  expandClaims,
  filterSupportedDisplayEntries,
  getPayloadValue,
  interpolatePlaceholders,
  lookupLocale,
  resolveAllClaims,
  resolveAllUiLabels,
  resolveDisplayableClaim,
  resolveTransactionDisplay,
  resolveTypedValue,
  resolveUiLabel,
  selectLocaleEntry,
  validateMandatoryClaims,
  validateNoUndeclaredPayloadFields,
  verifyLocaleSupport,
} from '../packages/resolver/src/index'

// ---------------------------------------------------------------------------
// Spec fixture — TS12 payment transaction
// ---------------------------------------------------------------------------
const TYPE_KEY = 'urn:eudi:sca:eu.europa.ec:payment:single:1' as const

const credentialMetadata: ScaCredentialMetadata = {
  transaction_data_types: {
    [TYPE_KEY]: {
      claims: [
        { path: ['transaction_id'], mandatory: true },
        {
          path: ['date_time'],
          value_type: 'iso_date_time',
          display: [
            { locale: 'de-DE', name: 'Datum' },
            { locale: 'en-GB', name: 'Date' },
          ],
        },
        {
          path: ['amount'],
          mandatory: true,
          value_type: 'iso_currency_amount',
          display: [
            { locale: 'de-DE', name: 'Betrag' },
            { locale: 'en-GB', name: 'Amount' },
          ],
        },
        {
          path: ['payee', 'name'],
          mandatory: true,
          display: [
            { locale: 'de-DE', name: 'Empfänger' },
            { locale: 'en-GB', name: 'Payee' },
          ],
        },
        { path: ['payee', 'id'], mandatory: true },
      ],
      ui_labels: {
        affirmative_action_label: [
          { locale: 'de-DE', value: 'Zahlung bestätigen' },
          { locale: 'en-GB', value: 'Confirm Payment' },
        ],
        denial_action_label: [
          { locale: 'de-DE', value: 'Abbrechen' },
          { locale: 'en-GB', value: 'Cancel' },
        ],
      },
    },
  },
}

const typeMetadata = credentialMetadata.transaction_data_types[TYPE_KEY] as TransactionDataType

const fullPayload: Record<string, unknown> = {
  transaction_id: 'tx-001',
  date_time: '2025-12-01T10:00:00Z',
  amount: '49.99 EUR',
  payee: { name: 'Shop AG', id: 'DE1234' },
}

/** Resolvers that echo the raw value back (sufficient for most tests). */
const echoResolvers: ValueTypeResolvers = {
  iso_date_time: (raw: string) => raw,
  iso_currency_amount: (raw: string) => raw,
}

const emptyResolvers: ValueTypeResolvers = {}

// ===========================================================================
// Section 3.5.4 — Locale Selection (RFC 4647)
// ===========================================================================
describe('Section 3.5.4 — Locale Selection', () => {
  describe('lookupLocale', () => {
    it('exact match', () => {
      assert.strictEqual(lookupLocale('de-DE', ['de-DE', 'en-GB']), 'de-DE')
    })

    it('case-insensitive', () => {
      assert.strictEqual(lookupLocale('DE-de', ['de-DE', 'en-GB']), 'de-DE')
    })

    it('truncates subtags to find a match', () => {
      assert.strictEqual(lookupLocale('de-DE-Bavaria', ['de', 'en']), 'de')
    })

    it('removes single-char subtag (en-x-private -> en)', () => {
      // After truncation of "private" we get "en-x"; "x" is a single-char subtag
      // so it is also removed, leaving "en".
      assert.strictEqual(lookupLocale('en-x-private', ['en', 'de']), 'en')
    })

    it('no match returns undefined', () => {
      assert.strictEqual(lookupLocale('fr-FR', ['de-DE', 'en-GB']), undefined)
    })

    it('empty tags returns undefined', () => {
      assert.strictEqual(lookupLocale('en', []), undefined)
    })
  })

  describe('selectLocaleEntry', () => {
    it('lookup match', () => {
      const entries = [
        { locale: 'de-DE', value: 'Hallo' },
        { locale: 'en-GB', value: 'Hello' },
      ]
      const result = selectLocaleEntry(entries, 'en-GB')
      assert.deepStrictEqual(result, { locale: 'en-GB', value: 'Hello' })
    })

    it('default entry fallback when no locale matches', () => {
      const entries = [
        { locale: 'de-DE', value: 'Hallo' },
        { value: 'Default' }, // no locale → default
      ]
      const result = selectLocaleEntry(entries, 'fr-FR')
      assert.deepStrictEqual(result, { value: 'Default' })
    })

    it('no match and no default returns undefined', () => {
      const entries = [
        { locale: 'de-DE', value: 'Hallo' },
        { locale: 'en-GB', value: 'Hello' },
      ]
      assert.strictEqual(selectLocaleEntry(entries, 'fr-FR'), undefined)
    })

    it('first match when multiple entries share the matched locale', () => {
      const entries = [
        { locale: 'en', value: 'First' },
        { locale: 'en', value: 'Second' },
      ]
      const result = selectLocaleEntry(entries, 'en')
      assert.deepStrictEqual(result, { locale: 'en', value: 'First' })
    })

    it('prefers tagged over default when locale matches', () => {
      const entries = [{ value: 'Default' }, { locale: 'de-DE', value: 'Tagged' }]
      const result = selectLocaleEntry(entries, 'de-DE')
      assert.deepStrictEqual(result, { locale: 'de-DE', value: 'Tagged' })
    })
  })
})

// ===========================================================================
// Section 3.5.2 — Value / Display Type Resolution
// ===========================================================================
describe('Section 3.5.2 — Value / Display Type Resolution', () => {
  describe('getPayloadValue', () => {
    it('nested paths', () => {
      assert.strictEqual(getPayloadValue(fullPayload, ['payee', 'name']), 'Shop AG')
    })

    it('missing intermediate returns undefined', () => {
      assert.strictEqual(getPayloadValue(fullPayload, ['nonexistent', 'deep']), undefined)
    })

    it('null handling — null intermediate returns undefined', () => {
      const payload = { a: null }
      assert.strictEqual(getPayloadValue(payload as Record<string, unknown>, ['a', 'b']), undefined)
    })
  })

  describe('resolveTypedValue', () => {
    it('no type passthrough', () => {
      const result = resolveTypedValue('hello', undefined, echoResolvers, 'en')
      assert.deepStrictEqual(result, { type: undefined, value: 'hello' })
    })

    it('with resolver success', () => {
      const result = resolveTypedValue('49.99 EUR', 'iso_currency_amount', echoResolvers, 'en')
      assert.deepStrictEqual(result, { type: 'iso_currency_amount', value: '49.99 EUR' })
    })

    it('missing resolver returns undefined', () => {
      assert.strictEqual(resolveTypedValue('val', 'unknown_type', echoResolvers, 'en'), undefined)
    })

    it('resolver returns undefined returns undefined', () => {
      const resolvers: ValueTypeResolvers = {
        bad: (_raw: string, _locale: string) => undefined,
      }
      assert.strictEqual(resolveTypedValue('val', 'bad', resolvers, 'en'), undefined)
    })
  })

  describe('filterSupportedDisplayEntries', () => {
    it('keeps plain (no display_type)', () => {
      const entries: Array<{ name: string; display_type?: string }> = [{ name: 'Plain' }]
      assert.deepStrictEqual(filterSupportedDisplayEntries(entries, echoResolvers), entries)
    })

    it('keeps supported display_type', () => {
      const entries = [{ name: 'Formatted', display_type: 'iso_date_time' }]
      assert.deepStrictEqual(filterSupportedDisplayEntries(entries, echoResolvers), entries)
    })

    it('removes unsupported display_type', () => {
      const entries = [{ name: 'Plain' }, { name: 'Fancy', display_type: 'fancy_unsupported' }]
      assert.deepStrictEqual(filterSupportedDisplayEntries(entries, echoResolvers), [{ name: 'Plain' }])
    })
  })
})

// ===========================================================================
// Section 3.3 — Mandatory Claims & Claim Resolution
// ===========================================================================
describe('Section 3.3 — Mandatory Claims & Claim Resolution', () => {
  describe('validateMandatoryClaims', () => {
    it('all present', () => {
      assert.strictEqual(validateMandatoryClaims(typeMetadata.claims as ClaimMetadata[], fullPayload), true)
    })

    it('missing mandatory returns false', () => {
      const { amount: _, ...noAmount } = fullPayload
      assert.strictEqual(validateMandatoryClaims(typeMetadata.claims as ClaimMetadata[], noAmount), false)
    })

    it('optional missing is OK', () => {
      const { date_time: _, ...noDate } = fullPayload
      assert.strictEqual(validateMandatoryClaims(typeMetadata.claims as ClaimMetadata[], noDate), true)
    })

    it('nested path', () => {
      // payee.name is mandatory — remove payee entirely
      const { payee: _, ...noPayee } = fullPayload
      assert.strictEqual(validateMandatoryClaims(typeMetadata.claims as ClaimMetadata[], noPayee), false)
    })
  })

  describe('validateNoUndeclaredPayloadFields', () => {
    it('accepts valid payload with nested fields', () => {
      assert.strictEqual(validateNoUndeclaredPayloadFields(typeMetadata.claims as ClaimMetadata[], fullPayload), true)
    })

    it('rejects undeclared top-level field', () => {
      const payload = { ...fullPayload, undeclared: 'extra' }
      assert.strictEqual(validateNoUndeclaredPayloadFields(typeMetadata.claims as ClaimMetadata[], payload), false)
    })

    it('rejects undeclared nested field', () => {
      // payee.name and payee.id are declared, but payee.extra is not
      const payload = {
        ...fullPayload,
        payee: { name: 'Shop AG', id: 'DE1234', extra: 'undeclared' },
      }
      assert.strictEqual(validateNoUndeclaredPayloadFields(typeMetadata.claims as ClaimMetadata[], payload), false)
    })

    it('accepts payload with declared nested fields only', () => {
      const payload = {
        transaction_id: 'tx-001',
        amount: '49.99 EUR',
        payee: { name: 'Shop AG', id: 'DE1234' },
      }
      assert.strictEqual(validateNoUndeclaredPayloadFields(typeMetadata.claims as ClaimMetadata[], payload), true)
    })
  })

  describe('resolveDisplayableClaim', () => {
    const amountClaim = typeMetadata.claims[2] as ClaimMetadata & {
      display: Array<{ name: string; locale?: string; display_type?: string }>
    }

    it('locale + label + value resolution', () => {
      const result = resolveDisplayableClaim(amountClaim, fullPayload, 'en-GB', echoResolvers)
      assert.ok(result)
      assert.deepStrictEqual(result.path, ['amount'])
      assert.strictEqual(result.mandatory, true)
      assert.deepStrictEqual(result.label, { type: undefined, value: 'Amount' })
      assert.deepStrictEqual(result.value, { type: 'iso_currency_amount', value: '49.99 EUR' })
    })

    it('locale fail returns undefined', () => {
      const result = resolveDisplayableClaim(amountClaim, fullPayload, 'fr-FR', echoResolvers)
      assert.strictEqual(result, undefined)
    })

    it('value_type fail returns undefined', () => {
      // Use empty resolvers — iso_currency_amount not supported
      const result = resolveDisplayableClaim(amountClaim, fullPayload, 'en-GB', emptyResolvers)
      assert.strictEqual(result, undefined)
    })
  })

  describe('resolveAllClaims', () => {
    it('preserves array order', () => {
      const result = resolveAllClaims(typeMetadata.claims as ClaimMetadata[], fullPayload, 'en-GB', echoResolvers)
      assert.ok(result)
      // Only displayable claims are returned (those with display), in order
      assert.deepStrictEqual(
        result.map((c) => c.path),
        [['date_time'], ['amount'], ['payee', 'name']]
      )
    })

    it('skips optional absent', () => {
      const { date_time: _, ...noDate } = fullPayload
      const result = resolveAllClaims(typeMetadata.claims as ClaimMetadata[], noDate, 'en-GB', echoResolvers)
      assert.ok(result)
      assert.deepStrictEqual(
        result.map((c) => c.path),
        [['amount'], ['payee', 'name']]
      )
    })

    it('fails on mandatory missing', () => {
      const { amount: _, ...noAmount } = fullPayload
      const result = resolveAllClaims(typeMetadata.claims as ClaimMetadata[], noAmount, 'en-GB', echoResolvers)
      assert.strictEqual(result, undefined)
    })
  })
})

// ===========================================================================
// Wildcard (null) claim expansion
// ===========================================================================
describe('Wildcard claim expansion', () => {
  const itemNameClaim = {
    path: ['items', null, 'name'],
    display: [{ name: 'Item Name', locale: 'en' }],
  } as unknown as ClaimMetadata

  const itemPriceClaim = {
    path: ['items', null, 'price'],
    value_type: 'iso_currency_amount',
    display: [{ name: 'Price', locale: 'en' }],
  } as unknown as ClaimMetadata

  const totalClaim = {
    path: ['total'],
    value_type: 'iso_currency_amount',
    display: [{ name: 'Total', locale: 'en' }],
  } as unknown as ClaimMetadata

  describe('expandClaims — single depth', () => {
    it('expands group per array index, interleaving members', () => {
      const payload = {
        items: [
          { name: 'Widget', price: '10 EUR' },
          { name: 'Gadget', price: '20 EUR' },
        ],
      }
      const expanded = expandClaims([itemNameClaim, itemPriceClaim], payload)
      assert.deepStrictEqual(
        expanded.map((e) => e.concretePath),
        [
          ['items', 0, 'name'],
          ['items', 0, 'price'],
          ['items', 1, 'name'],
          ['items', 1, 'price'],
        ]
      )
    })

    it('preserves order: plain claims stay in place, group at first member', () => {
      const payload = {
        total: '30 EUR',
        items: [{ name: 'Widget', price: '10 EUR' }],
      }
      const expanded = expandClaims([totalClaim, itemNameClaim, itemPriceClaim], payload)
      assert.deepStrictEqual(
        expanded.map((e) => e.concretePath),
        [['total'], ['items', 0, 'name'], ['items', 0, 'price']]
      )
    })

    it('returns empty for wildcard when array is missing', () => {
      const expanded = expandClaims([itemNameClaim], {})
      assert.strictEqual(expanded.length, 0)
    })
  })

  describe('expandClaims — multi depth', () => {
    const orderDateClaim = {
      path: ['orders', null, 'date'],
      display: [{ name: 'Date', locale: 'en' }],
    } as unknown as ClaimMetadata

    const lineNameClaim = {
      path: ['orders', null, 'items', null, 'name'],
      display: [{ name: 'Name', locale: 'en' }],
    } as unknown as ClaimMetadata

    const linePriceClaim = {
      path: ['orders', null, 'items', null, 'price'],
      value_type: 'iso_currency_amount',
      display: [{ name: 'Price', locale: 'en' }],
    } as unknown as ClaimMetadata

    it('recursively expands nested wildcards, inner grouped closest to leaf', () => {
      const payload = {
        orders: [
          {
            date: '2025-01-01',
            items: [
              { name: 'A', price: '10' },
              { name: 'B', price: '20' },
            ],
          },
          {
            date: '2025-01-02',
            items: [{ name: 'C', price: '30' }],
          },
        ],
      }

      const expanded = expandClaims([orderDateClaim, lineNameClaim, linePriceClaim], payload)
      assert.deepStrictEqual(
        expanded.map((e) => e.concretePath),
        [
          ['orders', 0, 'date'],
          ['orders', 0, 'items', 0, 'name'],
          ['orders', 0, 'items', 0, 'price'],
          ['orders', 0, 'items', 1, 'name'],
          ['orders', 0, 'items', 1, 'price'],
          ['orders', 1, 'date'],
          ['orders', 1, 'items', 0, 'name'],
          ['orders', 1, 'items', 0, 'price'],
        ]
      )
    })

    it('handles mixed: some members have deeper wildcards, some do not', () => {
      // orderDateClaim has only one null, lineNameClaim has two
      const payload = {
        orders: [{ date: 'D1', items: [{ name: 'X' }] }],
      }

      const expanded = expandClaims([orderDateClaim, lineNameClaim], payload)
      assert.deepStrictEqual(
        expanded.map((e) => e.concretePath),
        [
          ['orders', 0, 'date'],
          ['orders', 0, 'items', 0, 'name'],
        ]
      )
    })
  })

  describe('resolveAllClaims with wildcards', () => {
    it('resolves single-depth wildcard claims grouped by array index', () => {
      const payload = {
        total: '30 EUR',
        items: [
          { name: 'Widget', price: '10 EUR' },
          { name: 'Gadget', price: '20 EUR' },
        ],
      }

      const claims: ClaimMetadata[] = [totalClaim, itemNameClaim, itemPriceClaim]
      const result = resolveAllClaims(claims, payload, 'en', echoResolvers)
      assert.ok(result)

      assert.deepStrictEqual(
        result.map((c) => c.path),
        [['total'], ['items', 0, 'name'], ['items', 0, 'price'], ['items', 1, 'name'], ['items', 1, 'price']]
      )
    })
  })
})

// ===========================================================================
// Section 3.5.3 — Placeholder Interpolation & UI Labels
// ===========================================================================
describe('Section 3.5.3 — Placeholder Interpolation & UI Labels', () => {
  const claims = typeMetadata.claims as ClaimMetadata[]

  describe('interpolatePlaceholders', () => {
    it('{2} replacement per spec example "Pay {2}" -> "Pay 49.99 EUR"', () => {
      const result = interpolatePlaceholders('Pay {2}', claims, fullPayload, echoResolvers, 'en')
      assert.strictEqual(result, 'Pay 49.99 EUR')
    })

    it('out-of-bounds literal', () => {
      const result = interpolatePlaceholders('Ref {99}', claims, fullPayload, echoResolvers, 'en')
      assert.strictEqual(result, 'Ref {99}')
    })

    it('missing claim discards', () => {
      const { amount: _, ...noAmount } = fullPayload
      // {2} references the "amount" claim which is absent
      const result = interpolatePlaceholders('Pay {2}', claims, noAmount, echoResolvers, 'en')
      assert.strictEqual(result, undefined)
    })

    it('multiple placeholders', () => {
      const result = interpolatePlaceholders('{2} to {3}', claims, fullPayload, echoResolvers, 'en')
      assert.strictEqual(result, '49.99 EUR to Shop AG')
    })

    it('no placeholders', () => {
      const result = interpolatePlaceholders('Confirm', claims, fullPayload, echoResolvers, 'en')
      assert.strictEqual(result, 'Confirm')
    })
  })

  describe('resolveUiLabel', () => {
    const affirmativeEntries = typeMetadata.ui_labels.affirmative_action_label as UiLabelEntry[]

    it('locale match', () => {
      const result = resolveUiLabel(affirmativeEntries, 'de-DE', claims, fullPayload, echoResolvers)
      assert.ok(result)
      assert.strictEqual(result.value, 'Zahlung bestätigen')
    })

    it('falls back to default entry when locale-matched entry is discarded', () => {
      // Locale-matched entry has {2} referencing amount which is absent → discarded.
      // Default entry (no locale) has no placeholders → succeeds as fallback.
      const entries: UiLabelEntry[] = [{ locale: 'en', value: 'Pay {2}' }, { value: 'Fallback' }]
      const { amount: _, ...noAmount } = fullPayload
      const result = resolveUiLabel(entries, 'en', claims, noAmount, echoResolvers)
      assert.ok(result)
      assert.strictEqual(result.value, 'Fallback')
    })

    it('returns undefined when both locale entry and default are discarded', () => {
      // Both entries reference missing claim → both discarded → undefined.
      const entries: UiLabelEntry[] = [{ locale: 'en', value: 'Pay {2}' }, { value: 'Default {2}' }]
      const { amount: _, ...noAmount } = fullPayload
      const result = resolveUiLabel(entries, 'en', claims, noAmount, echoResolvers)
      assert.strictEqual(result, undefined)
    })
  })

  describe('resolveAllUiLabels', () => {
    it('affirmative required', () => {
      const result = resolveAllUiLabels(
        typeMetadata.ui_labels as Record<string, UiLabelEntry[]>,
        'en-GB',
        claims,
        fullPayload,
        echoResolvers
      )
      assert.ok(result)
      assert.ok(result.affirmative_action_label)
      assert.strictEqual(result.affirmative_action_label.value, 'Confirm Payment')
    })

    it('optional can fail without breaking', () => {
      // Create ui_labels where affirmative works but optional fails
      const uiLabels: Record<string, UiLabelEntry[]> = {
        affirmative_action_label: [{ locale: 'en', value: 'OK' }],
        denial_action_label: [{ locale: 'fr', value: 'Non' }], // no 'en' match, no default
      }
      const result = resolveAllUiLabels(uiLabels, 'en', claims, fullPayload, echoResolvers)
      assert.ok(result)
      assert.strictEqual(result.affirmative_action_label.value, 'OK')
      assert.strictEqual(result.denial_action_label, undefined)
    })
  })
})

// ===========================================================================
// Section 3.5.1 — Full Resolution
// ===========================================================================
describe('Section 3.5.1 — Full Resolution', () => {
  describe('resolveTransactionDisplay', () => {
    const transactionData: ScaTransactionDataEntry = {
      type: TYPE_KEY,
      credential_ids: ['cred-1'],
      payload: fullPayload,
    }

    it('full orchestration with single locale', () => {
      const result = resolveTransactionDisplay(transactionData, credentialMetadata, 'en-GB', echoResolvers)
      assert.ok(result)
      assert.strictEqual(result.locale, 'en-GB')
      assert.strictEqual(result.type, TYPE_KEY)
      assert.ok(result.claims.length > 0)
      assert.ok(result.ui_labels.affirmative_action_label)
    })

    it('priority list iteration', () => {
      // fr-FR will fail, then en-GB succeeds
      const result = resolveTransactionDisplay(transactionData, credentialMetadata, ['fr-FR', 'en-GB'], echoResolvers)
      assert.ok(result)
      assert.strictEqual(result.locale, 'en-GB')
    })

    it('returns selected locale', () => {
      const result = resolveTransactionDisplay(transactionData, credentialMetadata, ['de-DE', 'en-GB'], echoResolvers)
      assert.ok(result)
      assert.strictEqual(result.locale, 'de-DE')
    })

    it('undefined when no locale works', () => {
      const result = resolveTransactionDisplay(transactionData, credentialMetadata, ['fr-FR', 'ja-JP'], echoResolvers)
      assert.strictEqual(result, undefined)
    })

    it('rejects payload with undeclared nested field', () => {
      const td: ScaTransactionDataEntry = {
        type: TYPE_KEY,
        credential_ids: ['cred-1'],
        payload: {
          ...fullPayload,
          payee: { name: 'Shop AG', id: 'DE1234', extra: 'undeclared' },
        },
      }
      const result = resolveTransactionDisplay(td, credentialMetadata, 'en-GB', echoResolvers)
      assert.strictEqual(result, undefined)
    })

    it('accepts entry when unsupported value_type is on absent optional claim', () => {
      // value_type is only checked when the claim is present in the payload.
      // An absent optional claim with unsupported value_type does not make
      // the entry incompatible.
      const metaWithUnsupported: ScaCredentialMetadata = {
        transaction_data_types: {
          [TYPE_KEY]: {
            claims: [
              { path: ['transaction_id'], mandatory: true },
              {
                path: ['amount'],
                mandatory: true,
                value_type: 'iso_currency_amount',
                display: [{ locale: 'en-GB', name: 'Amount' }],
              },
              {
                path: ['optional_field'],
                value_type: 'unsupported_exotic_type',
                display: [{ locale: 'en-GB', name: 'Optional' }],
              },
            ],
            ui_labels: {
              affirmative_action_label: [{ locale: 'en-GB', value: 'Confirm' }],
            },
          },
        },
      }
      const td: ScaTransactionDataEntry = {
        type: TYPE_KEY,
        credential_ids: ['cred-1'],
        payload: { transaction_id: 'tx-001', amount: '49.99 EUR' },
      }
      const result = resolveTransactionDisplay(td, metaWithUnsupported, 'en-GB', echoResolvers)
      assert.ok(result)
    })
  })

  describe('verifyLocaleSupport', () => {
    it('all arrays match', () => {
      assert.strictEqual(verifyLocaleSupport(typeMetadata, 'en-GB', echoResolvers), true)
    })

    it('one fails returns false', () => {
      assert.strictEqual(verifyLocaleSupport(typeMetadata, 'fr-FR', echoResolvers), false)
    })

    it('default entries fill gaps', () => {
      // Build metadata where one claim display only has a default entry
      const meta: TransactionDataType = {
        claims: [
          {
            path: ['x'],
            display: [{ name: 'Default Label' }], // no locale → always matches as default
          },
        ],
        ui_labels: {
          affirmative_action_label: [{ value: 'OK' }], // default entry
        },
      }
      assert.strictEqual(verifyLocaleSupport(meta, 'zh-CN', echoResolvers), true)
    })

    it('filters unsupported display_type', () => {
      // Build metadata where the only locale-matching display entry has an unsupported display_type.
      // After filtering it is removed, leaving no match → false.
      const meta: TransactionDataType = {
        claims: [
          {
            path: ['x'],
            display: [{ name: 'Fancy', locale: 'en', display_type: 'fancy_unsupported' }],
          },
        ],
        ui_labels: {
          affirmative_action_label: [{ locale: 'en', value: 'OK' }],
        },
      }
      assert.strictEqual(verifyLocaleSupport(meta, 'en', echoResolvers), false)
    })
  })
})
