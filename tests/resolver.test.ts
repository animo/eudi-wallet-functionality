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
// Shared resolvers
// ---------------------------------------------------------------------------

/** Resolvers that echo the raw value back (sufficient for most tests). */
const echoResolvers: ValueTypeResolvers = {
  string: (v: string) => String(v),
  iso_currency_amount: (v: string) => String(v),
  iso_date_time: (v: string) => String(v),
}

const emptyResolvers: ValueTypeResolvers = {}

// ---------------------------------------------------------------------------
// Spec fixture -- TS12 Annex D.8 payment transaction
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
            { locale: 'de-DE', name: 'Empfaenger' },
            { locale: 'en-GB', name: 'Payee' },
          ],
        },
        { path: ['payee', 'id'], mandatory: true },
      ],
      ui_labels: {
        affirmative_action_label: [
          { locale: 'de-DE', value: 'Zahlung bestaetigen' },
          { locale: 'en-GB', value: 'Confirm Payment' },
        ],
        denial_action_label: [
          { locale: 'de-DE', value: 'Abbrechen' },
          { locale: 'en-GB', value: 'Cancel' },
        ],
        transaction_title: [
          { locale: 'de-DE', value: 'Zahlung an {3}' },
          { locale: 'en-GB', value: 'Payment to {3}' },
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

// ===========================================================================
// RFC 4647 Section 3.4 -- Locale Lookup (selectLocaleEntry, lookupLocale)
// ===========================================================================
describe('RFC 4647 Section 3.4 -- Locale Lookup', () => {
  describe('lookupLocale', () => {
    it('exact match returns the matching tag', () => {
      assert.strictEqual(lookupLocale('de-DE', ['de-DE', 'en-GB']), 'de-DE')
    })

    it('case insensitivity: DE-de matches de-DE', () => {
      assert.strictEqual(lookupLocale('DE-de', ['de-DE', 'en-GB']), 'de-DE')
    })

    it('subtag truncation: de-CH-1996 falls back to de when de-CH is absent', () => {
      assert.strictEqual(lookupLocale('de-CH-1996', ['de', 'en']), 'de')
    })

    it('subtag truncation: de-CH falls back to de', () => {
      assert.strictEqual(lookupLocale('de-CH', ['de', 'en']), 'de')
    })

    it('single-char subtags are removed during truncation (en-x-private -> en)', () => {
      assert.strictEqual(lookupLocale('en-x-private', ['en', 'de']), 'en')
    })

    it('no match returns undefined', () => {
      assert.strictEqual(lookupLocale('fr-FR', ['de-DE', 'en-GB']), undefined)
    })

    it('empty available tags returns undefined', () => {
      assert.strictEqual(lookupLocale('en', []), undefined)
    })
  })

  describe('selectLocaleEntry', () => {
    it('exact locale match returns the tagged entry', () => {
      const entries = [
        { locale: 'de-DE', value: 'Hallo' },
        { locale: 'en-GB', value: 'Hello' },
      ]
      const result = selectLocaleEntry(entries, 'en-GB')
      assert.deepStrictEqual(result, { locale: 'en-GB', value: 'Hello' })
    })

    it('subtag truncation: de-CH matches de entry', () => {
      const entries = [
        { locale: 'de', value: 'Hallo' },
        { locale: 'en', value: 'Hello' },
      ]
      const result = selectLocaleEntry(entries, 'de-CH')
      assert.deepStrictEqual(result, { locale: 'de', value: 'Hallo' })
    })

    it('case insensitivity: EN-gb matches en-GB', () => {
      const entries = [
        { locale: 'de-DE', value: 'Hallo' },
        { locale: 'en-GB', value: 'Hello' },
      ]
      const result = selectLocaleEntry(entries, 'EN-gb')
      assert.deepStrictEqual(result, { locale: 'en-GB', value: 'Hello' })
    })

    it('first-in-array-order wins when multiple entries match at same truncation step', () => {
      const entries = [
        { locale: 'en', value: 'First' },
        { locale: 'en', value: 'Second' },
      ]
      const result = selectLocaleEntry(entries, 'en')
      assert.deepStrictEqual(result, { locale: 'en', value: 'First' })
    })

    it('fallback to default entry (no locale field) when no tag matches', () => {
      const entries = [
        { locale: 'de-DE', value: 'Hallo' },
        { value: 'Default' }, // no locale = default
      ]
      const result = selectLocaleEntry(entries, 'fr-FR')
      assert.deepStrictEqual(result, { value: 'Default' })
    })

    it('prefers tagged match over default entry', () => {
      const entries = [{ value: 'Default' }, { locale: 'de-DE', value: 'Tagged' }]
      const result = selectLocaleEntry(entries, 'de-DE')
      assert.deepStrictEqual(result, { locale: 'de-DE', value: 'Tagged' })
    })

    it('no match and no default returns undefined', () => {
      const entries = [
        { locale: 'de-DE', value: 'Hallo' },
        { locale: 'en-GB', value: 'Hello' },
      ]
      assert.strictEqual(selectLocaleEntry(entries, 'fr-FR'), undefined)
    })
  })
})

// ===========================================================================
// Section 3.5.2 -- Value Resolution (getPayloadValue, resolveTypedValue)
// ===========================================================================
describe('Section 3.5.2 -- Value Resolution', () => {
  describe('getPayloadValue', () => {
    it('string key navigates into an object', () => {
      assert.strictEqual(getPayloadValue(fullPayload, ['amount']), '49.99 EUR')
    })

    it('nested string keys navigate deep objects', () => {
      assert.strictEqual(getPayloadValue(fullPayload, ['payee', 'name']), 'Shop AG')
    })

    it('numeric index selects array element', () => {
      const payload = { items: ['a', 'b', 'c'] }
      assert.strictEqual(getPayloadValue(payload, ['items', 1]), 'b')
    })

    it('negative index returns undefined', () => {
      const payload = { items: ['a', 'b', 'c'] }
      assert.strictEqual(getPayloadValue(payload, ['items', -1]), undefined)
    })

    it('out-of-bounds index returns undefined', () => {
      const payload = { items: ['a'] }
      assert.strictEqual(getPayloadValue(payload, ['items', 5]), undefined)
    })

    it('null wildcard maps over array elements', () => {
      const payload = { items: [{ n: 'A' }, { n: 'B' }] }
      assert.deepStrictEqual(getPayloadValue(payload, ['items', null, 'n']), ['A', 'B'])
    })

    it('null wildcard on non-array returns undefined', () => {
      const payload = { notArray: 'hello' }
      assert.strictEqual(getPayloadValue(payload, ['notArray', null]), undefined)
    })

    it('null wildcard on empty array returns undefined (all elements are undefined)', () => {
      const payload = { items: [] as unknown[] }
      // An empty array mapped produces [], but every element is undefined -> undefined
      assert.strictEqual(getPayloadValue(payload, ['items', null, 'x']), undefined)
    })

    it('missing intermediate key returns undefined', () => {
      assert.strictEqual(getPayloadValue(fullPayload, ['nonexistent', 'deep']), undefined)
    })

    it('null intermediate value returns undefined', () => {
      const payload = { a: null }
      assert.strictEqual(getPayloadValue(payload as Record<string, unknown>, ['a', 'b']), undefined)
    })

    it('empty path returns the entire payload', () => {
      const payload = { x: 1 }
      assert.deepStrictEqual(getPayloadValue(payload, []), { x: 1 })
    })

    it('numeric index on non-array returns undefined', () => {
      const payload = { obj: { key: 'val' } }
      assert.strictEqual(getPayloadValue(payload, ['obj', 0]), undefined)
    })

    it('string key on array returns undefined', () => {
      const payload = { items: ['a', 'b'] }
      assert.strictEqual(getPayloadValue(payload, ['items', 'missing']), undefined)
    })
  })

  describe('resolveTypedValue', () => {
    it('plain text passthrough when value_type is omitted', () => {
      const result = resolveTypedValue('hello', undefined, echoResolvers, 'en')
      assert.deepStrictEqual(result, { type: undefined, value: 'hello' })
    })

    it('resolves through a registered value type resolver', () => {
      const result = resolveTypedValue('49.99 EUR', 'iso_currency_amount', echoResolvers, 'en')
      assert.deepStrictEqual(result, { type: 'iso_currency_amount', value: '49.99 EUR' })
    })

    it('string resolver echoes the value', () => {
      const result = resolveTypedValue('hello', 'string', echoResolvers, 'en')
      assert.deepStrictEqual(result, { type: 'string', value: 'hello' })
    })

    it('unsupported value_type (no resolver registered) returns undefined', () => {
      assert.strictEqual(resolveTypedValue('val', 'unknown_type', echoResolvers, 'en'), undefined)
    })

    it('resolver returning undefined returns undefined', () => {
      const resolvers: ValueTypeResolvers = {
        bad: (_raw: string, _locale: string) => undefined,
      }
      assert.strictEqual(resolveTypedValue('val', 'bad', resolvers, 'en'), undefined)
    })

    it('passes locale to the resolver', () => {
      let receivedLocale = ''
      const resolvers: ValueTypeResolvers = {
        test: (_raw: string, locale: string) => {
          receivedLocale = locale
          return _raw
        },
      }
      resolveTypedValue('val', 'test', resolvers, 'de-DE')
      assert.strictEqual(receivedLocale, 'de-DE')
    })
  })
})

// ===========================================================================
// Section 3.5.1/3.5.2 -- Claim Resolution
// ===========================================================================
describe('Section 3.5.1/3.5.2 -- Claim Resolution', () => {
  describe('filterSupportedDisplayEntries', () => {
    it('keeps entries with no display_type (plain text)', () => {
      const entries: Array<{ name: string; display_type?: string }> = [{ name: 'Plain' }]
      assert.deepStrictEqual(filterSupportedDisplayEntries(entries, echoResolvers), entries)
    })

    it('keeps entries with supported display_type', () => {
      const entries = [{ name: 'Formatted', display_type: 'iso_date_time' }]
      assert.deepStrictEqual(filterSupportedDisplayEntries(entries, echoResolvers), entries)
    })

    it('removes entries with unsupported display_type', () => {
      const entries = [{ name: 'Plain' }, { name: 'Fancy', display_type: 'fancy_unsupported' }]
      assert.deepStrictEqual(filterSupportedDisplayEntries(entries, echoResolvers), [{ name: 'Plain' }])
    })

    it('removes all entries when none are supported', () => {
      const entries = [
        { name: 'A', display_type: 'exotic' },
        { name: 'B', display_type: 'other' },
      ]
      assert.deepStrictEqual(filterSupportedDisplayEntries(entries, echoResolvers), [])
    })
  })

  describe('validateMandatoryClaims', () => {
    it('returns true when all mandatory claims are present', () => {
      assert.strictEqual(validateMandatoryClaims(typeMetadata.claims as ClaimMetadata[], fullPayload), true)
    })

    it('returns false when a mandatory claim is missing', () => {
      const { amount: _, ...noAmount } = fullPayload
      assert.strictEqual(validateMandatoryClaims(typeMetadata.claims as ClaimMetadata[], noAmount), false)
    })

    it('returns true when an optional claim is absent', () => {
      const { date_time: _, ...noDate } = fullPayload
      assert.strictEqual(validateMandatoryClaims(typeMetadata.claims as ClaimMetadata[], noDate), true)
    })

    it('returns false when a mandatory nested claim parent is missing', () => {
      const { payee: _, ...noPayee } = fullPayload
      assert.strictEqual(validateMandatoryClaims(typeMetadata.claims as ClaimMetadata[], noPayee), false)
    })

    it('returns true for empty claims array (no mandatory claims)', () => {
      assert.strictEqual(validateMandatoryClaims([], fullPayload), true)
    })

    it('non-mandatory claim without mandatory field is treated as optional', () => {
      const claims: ClaimMetadata[] = [{ path: ['optional_field'] }]
      assert.strictEqual(validateMandatoryClaims(claims, {}), true)
    })
  })

  describe('validateNoUndeclaredPayloadFields', () => {
    it('returns true when all payload fields are declared', () => {
      assert.strictEqual(validateNoUndeclaredPayloadFields(typeMetadata.claims as ClaimMetadata[], fullPayload), true)
    })

    it('returns false when an extra top-level field is present', () => {
      const payload = { ...fullPayload, undeclared: 'extra' }
      assert.strictEqual(validateNoUndeclaredPayloadFields(typeMetadata.claims as ClaimMetadata[], payload), false)
    })

    it('returns false when an extra nested field is present', () => {
      const payload = {
        ...fullPayload,
        payee: { name: 'Shop AG', id: 'DE1234', extra: 'undeclared' },
      }
      assert.strictEqual(validateNoUndeclaredPayloadFields(typeMetadata.claims as ClaimMetadata[], payload), false)
    })

    it('returns true for payload with only declared nested fields', () => {
      const payload = {
        transaction_id: 'tx-001',
        amount: '49.99 EUR',
        payee: { name: 'Shop AG', id: 'DE1234' },
      }
      assert.strictEqual(validateNoUndeclaredPayloadFields(typeMetadata.claims as ClaimMetadata[], payload), true)
    })

    it('returns true for empty payload with no claims', () => {
      assert.strictEqual(validateNoUndeclaredPayloadFields([], {}), true)
    })
  })

  describe('resolveDisplayableClaim', () => {
    const amountClaim = typeMetadata.claims[2] as ClaimMetadata & {
      display: Array<{ name: string; locale?: string; display_type?: string }>
    }

    it('resolves locale, label, and value correctly', () => {
      const result = resolveDisplayableClaim(amountClaim, fullPayload, 'en-GB', echoResolvers)
      assert.ok(result)
      assert.deepStrictEqual(result.path, ['amount'])
      assert.strictEqual(result.mandatory, true)
      assert.deepStrictEqual(result.label, { type: undefined, value: 'Amount' })
      assert.deepStrictEqual(result.value, { type: 'iso_currency_amount', value: '49.99 EUR' })
    })

    it('returns undefined when locale does not match any display entry', () => {
      const result = resolveDisplayableClaim(amountClaim, fullPayload, 'fr-FR', echoResolvers)
      assert.strictEqual(result, undefined)
    })

    it('returns undefined when value_type has no resolver', () => {
      const result = resolveDisplayableClaim(amountClaim, fullPayload, 'en-GB', emptyResolvers)
      assert.strictEqual(result, undefined)
    })

    it('uses pathOverride when provided', () => {
      const claim = typeMetadata.claims[3] as ClaimMetadata & {
        display: Array<{ name: string; locale?: string; display_type?: string }>
      }
      const result = resolveDisplayableClaim(claim, fullPayload, 'en-GB', echoResolvers, ['payee', 'name'])
      assert.ok(result)
      assert.deepStrictEqual(result.path, ['payee', 'name'])
      assert.strictEqual(result.label.value, 'Payee')
    })
  })

  describe('resolveAllClaims', () => {
    it('display order follows claims array order', () => {
      const result = resolveAllClaims(typeMetadata.claims as ClaimMetadata[], fullPayload, 'en-GB', echoResolvers)
      assert.ok(result)
      // Only displayable claims (with display array) are returned, in declaration order
      assert.deepStrictEqual(
        result.map((c) => c.path),
        [['date_time'], ['amount'], ['payee', 'name']]
      )
    })

    it('skips optional claim absent from payload', () => {
      const { date_time: _, ...noDate } = fullPayload
      const result = resolveAllClaims(typeMetadata.claims as ClaimMetadata[], noDate, 'en-GB', echoResolvers)
      assert.ok(result)
      assert.deepStrictEqual(
        result.map((c) => c.path),
        [['amount'], ['payee', 'name']]
      )
    })

    it('returns undefined when a mandatory claim is missing', () => {
      const { amount: _, ...noAmount } = fullPayload
      const result = resolveAllClaims(typeMetadata.claims as ClaimMetadata[], noAmount, 'en-GB', echoResolvers)
      assert.strictEqual(result, undefined)
    })

    it('returns undefined when undeclared fields are present', () => {
      const payload = { ...fullPayload, extra: 'undeclared' }
      const result = resolveAllClaims(typeMetadata.claims as ClaimMetadata[], payload, 'en-GB', echoResolvers)
      assert.strictEqual(result, undefined)
    })

    it('returns empty array when no claims are displayable', () => {
      const claims: ClaimMetadata[] = [{ path: ['transaction_id'], mandatory: true }]
      const payload = { transaction_id: 'tx-001' }
      const result = resolveAllClaims(claims, payload, 'en', echoResolvers)
      assert.ok(result)
      assert.strictEqual(result.length, 0)
    })
  })
})

// ===========================================================================
// Wildcard expansion (expandClaims)
// ===========================================================================
describe('Wildcard expansion', () => {
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

  describe('expandClaims -- single-level wildcards', () => {
    it('expands wildcard group per array index, interleaving group members', () => {
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

    it('preserves order: non-wildcard claims stay in place, group emitted at first member position', () => {
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

    it('empty array produces no expanded claims for that group', () => {
      const payload = { items: [] as unknown[] }
      const expanded = expandClaims([itemNameClaim, itemPriceClaim], payload)
      assert.strictEqual(expanded.length, 0)
    })

    it('missing array produces no expanded claims for that group', () => {
      const expanded = expandClaims([itemNameClaim], {})
      assert.strictEqual(expanded.length, 0)
    })

    it('mixed wildcard and non-wildcard claims: non-wildcard always emitted', () => {
      const payload = { total: '30 EUR' }
      // items array is missing, so wildcard claims produce nothing, but totalClaim stays
      const expanded = expandClaims([totalClaim, itemNameClaim], payload)
      assert.deepStrictEqual(
        expanded.map((e) => e.concretePath),
        [['total']]
      )
    })
  })

  describe('expandClaims -- multi-depth wildcards (Annex C)', () => {
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

    it('handles mixed: some group members have deeper wildcards, some do not', () => {
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

    it('inner empty array expands outer but produces nothing for inner', () => {
      const payload = {
        orders: [{ date: 'D1', items: [] as unknown[] }],
      }

      const expanded = expandClaims([orderDateClaim, lineNameClaim, linePriceClaim], payload)
      // date is a single-level wildcard member, so it gets expanded for index 0
      // inner items is empty, so lineNameClaim/linePriceClaim produce nothing
      assert.deepStrictEqual(
        expanded.map((e) => e.concretePath),
        [['orders', 0, 'date']]
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
// Section 3.5.3 -- UI Label Resolution
// ===========================================================================
describe('Section 3.5.3 -- UI Label Resolution', () => {
  const claims = typeMetadata.claims as ClaimMetadata[]

  describe('interpolatePlaceholders', () => {
    it('{index} replaced with formatted claim value', () => {
      // {2} references claims[2] which is the amount claim
      const result = interpolatePlaceholders('Pay {2}', claims, fullPayload, echoResolvers, 'en')
      assert.strictEqual(result, 'Pay 49.99 EUR')
    })

    it('out-of-bounds placeholder kept as literal text', () => {
      const result = interpolatePlaceholders('Ref {99}', claims, fullPayload, echoResolvers, 'en')
      assert.strictEqual(result, 'Ref {99}')
    })

    it('missing claim value discards entire entry (returns undefined)', () => {
      const { amount: _, ...noAmount } = fullPayload
      const result = interpolatePlaceholders('Pay {2}', claims, noAmount, echoResolvers, 'en')
      assert.strictEqual(result, undefined)
    })

    it('multiple placeholders are all replaced', () => {
      const result = interpolatePlaceholders('{2} to {3}', claims, fullPayload, echoResolvers, 'en')
      assert.strictEqual(result, '49.99 EUR to Shop AG')
    })

    it('template without placeholders passes through unchanged', () => {
      const result = interpolatePlaceholders('Confirm', claims, fullPayload, echoResolvers, 'en')
      assert.strictEqual(result, 'Confirm')
    })

    it('empty template returns empty string', () => {
      const result = interpolatePlaceholders('', claims, fullPayload, echoResolvers, 'en')
      assert.strictEqual(result, '')
    })

    it('adjacent placeholders both replaced', () => {
      const result = interpolatePlaceholders('{0}{2}', claims, fullPayload, echoResolvers, 'en')
      assert.strictEqual(result, 'tx-00149.99 EUR')
    })

    it('unsupported value_type on referenced claim discards entry', () => {
      // claims[1] is date_time with value_type iso_date_time
      // Using resolvers that do not support iso_date_time
      const resolvers: ValueTypeResolvers = {
        iso_currency_amount: (v: string) => String(v),
      }
      const result = interpolatePlaceholders('Date: {1}', claims, fullPayload, resolvers, 'en')
      assert.strictEqual(result, undefined)
    })
  })

  describe('resolveUiLabel', () => {
    const affirmativeEntries = typeMetadata.ui_labels.affirmative_action_label as UiLabelEntry[]

    it('locale match resolves the correct label', () => {
      const result = resolveUiLabel(affirmativeEntries, 'de-DE', claims, fullPayload, echoResolvers)
      assert.ok(result)
      assert.strictEqual(result.value, 'Zahlung bestaetigen')
    })

    it('locale match resolves en-GB label', () => {
      const result = resolveUiLabel(affirmativeEntries, 'en-GB', claims, fullPayload, echoResolvers)
      assert.ok(result)
      assert.strictEqual(result.value, 'Confirm Payment')
    })

    it('falls back to default entry when locale-matched entry is discarded', () => {
      const entries: UiLabelEntry[] = [{ locale: 'en', value: 'Pay {2}' }, { value: 'Fallback' }]
      const { amount: _, ...noAmount } = fullPayload
      const result = resolveUiLabel(entries, 'en', claims, noAmount, echoResolvers)
      assert.ok(result)
      assert.strictEqual(result.value, 'Fallback')
    })

    it('returns undefined when both locale entry and default are discarded', () => {
      const entries: UiLabelEntry[] = [{ locale: 'en', value: 'Pay {2}' }, { value: 'Default {2}' }]
      const { amount: _, ...noAmount } = fullPayload
      const result = resolveUiLabel(entries, 'en', claims, noAmount, echoResolvers)
      assert.strictEqual(result, undefined)
    })

    it('returns undefined when no entry matches the locale and no default exists', () => {
      const entries: UiLabelEntry[] = [{ locale: 'de', value: 'Nur Deutsch' }]
      const result = resolveUiLabel(entries, 'fr', claims, fullPayload, echoResolvers)
      assert.strictEqual(result, undefined)
    })

    it('entry with value_type is resolved through that type', () => {
      const entries: UiLabelEntry[] = [{ locale: 'en', value: 'OK', value_type: 'string' }]
      const result = resolveUiLabel(entries, 'en', claims, fullPayload, echoResolvers)
      assert.ok(result)
      assert.deepStrictEqual(result, { type: 'string', value: 'OK' })
    })
  })

  describe('resolveAllUiLabels', () => {
    it('affirmative_action_label is required: succeeds when present', () => {
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

    it('returns undefined when affirmative_action_label fails', () => {
      const uiLabels: Record<string, UiLabelEntry[]> = {
        affirmative_action_label: [{ locale: 'fr', value: 'Confirmer' }], // no 'en' match, no default
      }
      const result = resolveAllUiLabels(uiLabels, 'en', claims, fullPayload, echoResolvers)
      assert.strictEqual(result, undefined)
    })

    it('optional labels failing are omitted from output', () => {
      const uiLabels: Record<string, UiLabelEntry[]> = {
        affirmative_action_label: [{ locale: 'en', value: 'OK' }],
        denial_action_label: [{ locale: 'fr', value: 'Non' }], // no 'en' match
      }
      const result = resolveAllUiLabels(uiLabels, 'en', claims, fullPayload, echoResolvers)
      assert.ok(result)
      assert.strictEqual(result.affirmative_action_label.value, 'OK')
      assert.strictEqual(result.denial_action_label, undefined)
    })

    it('resolves all labels when all match', () => {
      const result = resolveAllUiLabels(
        typeMetadata.ui_labels as Record<string, UiLabelEntry[]>,
        'en-GB',
        claims,
        fullPayload,
        echoResolvers
      )
      assert.ok(result)
      assert.ok(result.affirmative_action_label)
      assert.ok(result.denial_action_label)
      assert.ok(result.transaction_title)
      assert.strictEqual(result.transaction_title.value, 'Payment to Shop AG')
    })

    it('returns undefined when affirmative_action_label key is missing entirely', () => {
      const uiLabels: Record<string, UiLabelEntry[]> = {
        denial_action_label: [{ locale: 'en', value: 'Cancel' }],
      }
      const result = resolveAllUiLabels(uiLabels, 'en', claims, fullPayload, echoResolvers)
      assert.strictEqual(result, undefined)
    })
  })
})

// ===========================================================================
// Section 3.5.4 -- Transaction Display
// ===========================================================================
describe('Section 3.5.4 -- Transaction Display', () => {
  describe('verifyLocaleSupport', () => {
    it('returns true when all display arrays match the locale', () => {
      assert.strictEqual(verifyLocaleSupport(typeMetadata, 'en-GB', echoResolvers), true)
    })

    it('returns false when any display array fails to match', () => {
      assert.strictEqual(verifyLocaleSupport(typeMetadata, 'fr-FR', echoResolvers), false)
    })

    it('default entries fill gaps (no locale field always matches)', () => {
      const meta: TransactionDataType = {
        claims: [
          {
            path: ['x'],
            display: [{ name: 'Default Label' }], // no locale = default
          },
        ],
        ui_labels: {
          affirmative_action_label: [{ value: 'OK' }], // no locale = default
        },
      }
      assert.strictEqual(verifyLocaleSupport(meta, 'zh-CN', echoResolvers), true)
    })

    it('unsupported display_type entries excluded before matching', () => {
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
      // After filtering out the unsupported entry, no display entries remain -> false
      assert.strictEqual(verifyLocaleSupport(meta, 'en', echoResolvers), false)
    })

    it('checks ui_labels too: fails if a ui_label array has no matching entry', () => {
      const meta: TransactionDataType = {
        claims: [
          {
            path: ['x'],
            display: [{ name: 'X', locale: 'en' }],
          },
        ],
        ui_labels: {
          affirmative_action_label: [{ locale: 'de', value: 'Bestaetigen' }], // no 'en'
        },
      }
      assert.strictEqual(verifyLocaleSupport(meta, 'en', echoResolvers), false)
    })
  })

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

    it('output includes locale and type fields', () => {
      const result = resolveTransactionDisplay(transactionData, credentialMetadata, 'de-DE', echoResolvers)
      assert.ok(result)
      assert.strictEqual(result.locale, 'de-DE')
      assert.strictEqual(result.type, TYPE_KEY)
    })

    it('locale priority list: first successful wins', () => {
      // fr-FR will fail, then en-GB succeeds
      const result = resolveTransactionDisplay(transactionData, credentialMetadata, ['fr-FR', 'en-GB'], echoResolvers)
      assert.ok(result)
      assert.strictEqual(result.locale, 'en-GB')
    })

    it('locale priority list: first match is preferred', () => {
      const result = resolveTransactionDisplay(transactionData, credentialMetadata, ['de-DE', 'en-GB'], echoResolvers)
      assert.ok(result)
      assert.strictEqual(result.locale, 'de-DE')
    })

    it('all locales fail returns undefined', () => {
      const result = resolveTransactionDisplay(transactionData, credentialMetadata, ['fr-FR', 'ja-JP'], echoResolvers)
      assert.strictEqual(result, undefined)
    })

    it('type not found returns undefined', () => {
      const td: ScaTransactionDataEntry = {
        type: 'urn:nonexistent:type',
        credential_ids: ['cred-1'],
        payload: fullPayload,
      }
      const result = resolveTransactionDisplay(td, credentialMetadata, 'en-GB', echoResolvers)
      assert.strictEqual(result, undefined)
    })

    it('mandatory claim missing returns undefined', () => {
      const { amount: _, ...noAmount } = fullPayload
      const td: ScaTransactionDataEntry = {
        type: TYPE_KEY,
        credential_ids: ['cred-1'],
        payload: noAmount,
      }
      const result = resolveTransactionDisplay(td, credentialMetadata, 'en-GB', echoResolvers)
      assert.strictEqual(result, undefined)
    })

    it('undeclared nested field returns undefined', () => {
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

    it('resolves claims in declaration order', () => {
      const result = resolveTransactionDisplay(transactionData, credentialMetadata, 'en-GB', echoResolvers)
      assert.ok(result)
      assert.deepStrictEqual(
        result.claims.map((c) => c.path),
        [['date_time'], ['amount'], ['payee', 'name']]
      )
    })

    it('resolves ui_labels including placeholder interpolation', () => {
      const result = resolveTransactionDisplay(transactionData, credentialMetadata, 'en-GB', echoResolvers)
      assert.ok(result)
      assert.strictEqual(result.ui_labels.transaction_title.value, 'Payment to Shop AG')
    })

    it('de-DE locale resolves German labels and placeholder', () => {
      const result = resolveTransactionDisplay(transactionData, credentialMetadata, 'de-DE', echoResolvers)
      assert.ok(result)
      assert.strictEqual(result.ui_labels.affirmative_action_label.value, 'Zahlung bestaetigen')
      assert.strictEqual(result.ui_labels.transaction_title.value, 'Zahlung an Shop AG')
    })
  })
})
