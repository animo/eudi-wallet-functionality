import assert from 'node:assert'
import { describe, it } from 'node:test'
import type { ScaCredentialMetadata } from '@animo-id/eudi-wallet-ts12-validation'
import {
  bestEffortDecompose,
  buildCoOccurrences,
  decomposeTransposable,
  generateCartesianProduct,
  type SlotDecomposition,
  verifyCartesianProduct,
} from '../packages/dcql/src/cartesian'
import {
  collectScaCredentialQueryIds,
  findFirstSatisfiableOption,
  isOptionSatisfiable,
  orderSlotsByReference,
  partitionOptions,
  resolveNonScaCredentialSet,
  resolveScaCredentialSet,
} from '../packages/dcql/src/resolve-credential-set'
import {
  findFirstNonScaTransactionData,
  isTargetedByTransactionData,
  resolveAllMatchedCredentials,
  resolveFirstMatchScaTransactionData,
} from '../packages/dcql/src/resolve-credentials'
import {
  buildCredentialQueryMap,
  hasScaTransactionData,
  resolveDcql,
  validateTransactionDataCredentialSet,
} from '../packages/dcql/src/resolve-dcql'
import { err, isErr, isOk, ok } from '../packages/dcql/src/result'
import type {
  CredentialMatcher,
  DcqlCredentialQuery,
  DcqlCredentialSetQuery,
  MatchedCredential,
  TransactionDataInput,
  WalletConfiguration,
} from '../packages/dcql/src/types'

// =============================================================================
// Mock helpers
// =============================================================================

function makeConfig(overrides?: Partial<WalletConfiguration>): WalletConfiguration {
  return {
    locales: ['en'],
    valueTypeResolvers: {
      iso_currency_amount: (v: string) => v,
      iso_date_time: (v: string) => v,
    },
    mode: 'light',
    supportsSvgTemplates: false,
    ...overrides,
  }
}

function makeQuery(id: string, format = 'dc+sd-jwt'): DcqlCredentialQuery {
  return {
    id,
    format,
    meta: { vct_values: [`https://example.com/${id}`] },
  }
}

function makeMatcher(available: Record<string, MatchedCredential[]>): CredentialMatcher {
  return (query: DcqlCredentialQuery) => available[query.id] ?? []
}

function makeCredential(credentialId: string): MatchedCredential {
  return { credentialId }
}

function makeScaCredential(credentialId: string, typeKeys: string[]): MatchedCredential {
  const transaction_data_types: Record<string, unknown> = {}
  for (const key of typeKeys) {
    transaction_data_types[key] = {
      claims: [
        {
          path: ['amount'],
          mandatory: true,
          value_type: 'iso_currency_amount',
          display: [{ name: 'Amount' }],
        },
      ],
      ui_labels: {
        affirmative_action_label: [{ value: 'Confirm' }],
      },
    }
  }
  return {
    credentialId,
    scaMetadata: { transaction_data_types } as ScaCredentialMetadata,
  }
}

function makeTransactionData(
  type: string,
  credentialIds: string[],
  payload: Record<string, unknown> = {}
): TransactionDataInput {
  return { type, credential_ids: credentialIds, payload }
}

// =============================================================================
// Result helpers
// =============================================================================

describe('Result helpers', () => {
  it('ok wraps a value', () => {
    const r = ok(42)
    assert.deepStrictEqual(r, { ok: true, value: 42 })
  })

  it('err wraps an error', () => {
    const r = err('fail')
    assert.deepStrictEqual(r, { ok: false, error: 'fail' })
  })

  it('isOk returns true for ok results', () => {
    assert.strictEqual(isOk(ok(1)), true)
    assert.strictEqual(isOk(err('x')), false)
  })

  it('isErr returns true for err results', () => {
    assert.strictEqual(isErr(err('x')), true)
    assert.strictEqual(isErr(ok(1)), false)
  })
})

// =============================================================================
// Section 3.4 -- Cartesian Product & Transposability
// =============================================================================

describe('Section 3.4 -- Cartesian Product & Transposability', () => {
  describe('buildCoOccurrences', () => {
    it('detects pairs that co-occur in at least one alternative', () => {
      const alternatives = [
        ['a', 'b'],
        ['a', 'c'],
      ]
      const pairs = buildCoOccurrences(alternatives)
      // a-b co-occur in alt 0, a-c in alt 1, b-c never
      assert.strictEqual(pairs.has('a\0b'), true)
      assert.strictEqual(pairs.has('a\0c'), true)
      assert.strictEqual(pairs.has('b\0c'), false)
    })

    it('normalizes pair keys: min\\0max ordering', () => {
      const pairs = buildCoOccurrences([['z', 'a']])
      assert.strictEqual(pairs.has('a\0z'), true)
      assert.strictEqual(pairs.has('z\0a'), false)
    })
  })

  describe('decomposeTransposable — spec transposable example', () => {
    // Spec example: [["sca_card","pid_1"], ["sca_card","pid_2"], ["sca_card"]]
    // Expected: 2 slots — slot 0: {sca_card}, slot 1: {pid_1, pid_2} (optional)
    it('decomposes spec transposable example into 2 slots', () => {
      const alternatives = [['sca_card', 'pid_1'], ['sca_card', 'pid_2'], ['sca_card']]
      const result = decomposeTransposable(alternatives)
      assert.ok(result, 'should be transposable')
      assert.strictEqual(result.length, 2)

      // Slot 0: sca_card (not optional — appears in every alternative)
      const scaSlot = result.find((s) => s.ids.includes('sca_card'))
      assert.ok(scaSlot)
      assert.strictEqual(scaSlot.optional, false)

      // Slot 1: pid_1, pid_2 (optional — absent from ["sca_card"])
      const pidSlot = result.find((s) => s.ids.includes('pid_1'))
      assert.ok(pidSlot)
      assert.ok(pidSlot.ids.includes('pid_2'))
      assert.strictEqual(pidSlot.optional, true)
    })
  })

  describe('decomposeTransposable — spec counterexample', () => {
    // Spec counterexample: [["sca_card","pid_1"], ["sca_card","pid_2","loyalty"], ["sca_card"]]
    // Not transposable because pid_2 and loyalty co-occur but are in different relationships
    it('rejects spec counterexample as non-transposable', () => {
      const alternatives = [['sca_card', 'pid_1'], ['sca_card', 'pid_2', 'loyalty'], ['sca_card']]
      const result = decomposeTransposable(alternatives)
      assert.strictEqual(result, undefined)
    })
  })

  describe('decomposeTransposable — corrected 6-alternative example', () => {
    // Full cartesian product with 3 slots: {sca_card} x {pid_1, pid_2} x {loyalty} with both optional
    it('decomposes corrected 6-alternative example into 3 slots', () => {
      const alternatives = [
        ['sca_card', 'pid_1', 'loyalty'],
        ['sca_card', 'pid_2', 'loyalty'],
        ['sca_card', 'pid_1'],
        ['sca_card', 'pid_2'],
        ['sca_card', 'loyalty'],
        ['sca_card'],
      ]
      const result = decomposeTransposable(alternatives)
      assert.ok(result, 'should be transposable')
      assert.strictEqual(result.length, 3)

      const scaSlot = result.find((s) => s.ids.includes('sca_card'))
      assert.ok(scaSlot)
      assert.strictEqual(scaSlot.optional, false)

      const pidSlot = result.find((s) => s.ids.includes('pid_1'))
      assert.ok(pidSlot)
      assert.ok(pidSlot.ids.includes('pid_2'))
      assert.strictEqual(pidSlot.optional, true)

      const loyaltySlot = result.find((s) => s.ids.includes('loyalty'))
      assert.ok(loyaltySlot)
      assert.strictEqual(loyaltySlot.optional, true)
    })
  })

  describe('decomposeTransposable — multiple transaction data example', () => {
    // [["sca_card","pid"], ["sca_card"], ["sca_account","pid"], ["sca_account"]]
    // 2 slots: {sca_card, sca_account} x {pid} (optional)
    it('decomposes into 2 slots', () => {
      const alternatives = [['sca_card', 'pid'], ['sca_card'], ['sca_account', 'pid'], ['sca_account']]
      const result = decomposeTransposable(alternatives)
      assert.ok(result, 'should be transposable')
      assert.strictEqual(result.length, 2)

      const scaSlot = result.find((s) => s.ids.includes('sca_card'))
      assert.ok(scaSlot)
      assert.ok(scaSlot.ids.includes('sca_account'))
      assert.strictEqual(scaSlot.optional, false)

      const pidSlot = result.find((s) => s.ids.includes('pid'))
      assert.ok(pidSlot)
      assert.strictEqual(pidSlot.optional, true)
    })
  })

  describe('generateCartesianProduct', () => {
    it('generates product with optional slots', () => {
      const slots: SlotDecomposition[] = [
        { ids: ['a'], optional: false },
        { ids: ['x', 'y'], optional: true },
      ]
      const product = generateCartesianProduct(slots)
      // a x {x, y, null} = [a,x], [a,y], [a]
      assert.strictEqual(product.length, 3)
      assert.deepStrictEqual(
        product.sort().map((a) => a.sort()),
        [['a'], ['a', 'x'], ['a', 'y']].sort().map((a) => a.sort())
      )
    })

    it('returns [[]] for empty slots', () => {
      assert.deepStrictEqual(generateCartesianProduct([]), [[]])
    })
  })

  describe('verifyCartesianProduct', () => {
    it('matches when alternatives equal the product', () => {
      const slots: SlotDecomposition[] = [
        { ids: ['a', 'b'], optional: false },
        { ids: ['x'], optional: false },
      ]
      const alternatives = [
        ['a', 'x'],
        ['b', 'x'],
      ]
      assert.strictEqual(verifyCartesianProduct(slots, alternatives), true)
    })

    it('does not match on size mismatch', () => {
      const slots: SlotDecomposition[] = [
        { ids: ['a', 'b'], optional: false },
        { ids: ['x'], optional: false },
      ]
      const alternatives = [['a', 'x']]
      assert.strictEqual(verifyCartesianProduct(slots, alternatives), false)
    })

    it('does not match when an alternative does not belong to the product', () => {
      const slots: SlotDecomposition[] = [
        { ids: ['a', 'b'], optional: false },
        { ids: ['x'], optional: false },
      ]
      // Product is [a,x],[b,x]. [a,y] is not in the product.
      const alternatives = [
        ['a', 'x'],
        ['a', 'y'],
      ]
      assert.strictEqual(verifyCartesianProduct(slots, alternatives), false)
    })
  })

  describe('bestEffortDecompose', () => {
    it('returns exact decomposition when transposable', () => {
      const alternatives = [
        ['a', 'x'],
        ['b', 'x'],
      ]
      const result = bestEffortDecompose(alternatives)
      assert.strictEqual(result.length, 2)
    })

    it('gracefully falls back for non-transposable input', () => {
      const alternatives = [['sca_card', 'pid_1'], ['sca_card', 'pid_2', 'loyalty'], ['sca_card']]
      // Non-transposable, but bestEffort should still produce some decomposition
      const result = bestEffortDecompose(alternatives)
      assert.ok(result.length > 0, 'should return at least one slot')
      // All IDs from the first alternative should be in the result
      const allIds = result.flatMap((s) => s.ids)
      assert.ok(allIds.includes('sca_card'))
      assert.ok(allIds.includes('pid_1'))
    })

    it('returns empty for empty input', () => {
      assert.deepStrictEqual(bestEffortDecompose([]), [])
    })
  })
})

// =============================================================================
// Credential Set Resolution
// =============================================================================

describe('Credential Set Resolution', () => {
  describe('collectScaCredentialQueryIds', () => {
    it('filters by SCA prefix', () => {
      const td = [
        makeTransactionData('urn:eudi:sca:payment:v1', ['sca_card']),
        makeTransactionData('other_type', ['other_cred']),
        makeTransactionData('urn:eudi:sca:transfer:v1', ['sca_account', 'pid']),
      ]
      const ids = collectScaCredentialQueryIds(td)
      assert.deepStrictEqual([...ids].sort(), ['pid', 'sca_account', 'sca_card'])
    })

    it('returns empty set when no SCA entries', () => {
      const td = [makeTransactionData('custom_type', ['cred1'])]
      const ids = collectScaCredentialQueryIds(td)
      assert.strictEqual(ids.size, 0)
    })
  })

  describe('partitionOptions', () => {
    it('splits SCA vs non-SCA options', () => {
      const options = [['sca_card', 'pid'], ['other_cred'], ['sca_card']]
      const scaIds = new Set(['sca_card'])
      const { sca, nonSca } = partitionOptions(options, scaIds)
      assert.deepStrictEqual(sca, [['sca_card', 'pid'], ['sca_card']])
      assert.deepStrictEqual(nonSca, [['other_cred']])
    })
  })

  describe('isOptionSatisfiable', () => {
    it('returns true when all queries have matches', () => {
      const queries = buildCredentialQueryMap([makeQuery('a'), makeQuery('b')])
      const matcher = makeMatcher({
        a: [makeCredential('c1')],
        b: [makeCredential('c2')],
      })
      assert.strictEqual(isOptionSatisfiable(['a', 'b'], queries, matcher), true)
    })

    it('returns false when some queries have no matches', () => {
      const queries = buildCredentialQueryMap([makeQuery('a'), makeQuery('b')])
      const matcher = makeMatcher({
        a: [makeCredential('c1')],
        b: [],
      })
      assert.strictEqual(isOptionSatisfiable(['a', 'b'], queries, matcher), false)
    })

    it('returns false when query is missing from map', () => {
      const queries = buildCredentialQueryMap([makeQuery('a')])
      const matcher = makeMatcher({ a: [makeCredential('c1')] })
      assert.strictEqual(isOptionSatisfiable(['a', 'missing'], queries, matcher), false)
    })
  })

  describe('findFirstSatisfiableOption', () => {
    it('returns the first satisfiable option', () => {
      const queries = buildCredentialQueryMap([makeQuery('a'), makeQuery('b'), makeQuery('c')])
      const matcher = makeMatcher({
        a: [],
        b: [makeCredential('c2')],
        c: [makeCredential('c3')],
      })
      const options = [['a'], ['b'], ['c']]
      const result = findFirstSatisfiableOption(options, queries, matcher)
      assert.deepStrictEqual(result, ['b'])
    })

    it('returns undefined when none satisfiable', () => {
      const queries = buildCredentialQueryMap([makeQuery('a')])
      const matcher = makeMatcher({ a: [] })
      assert.strictEqual(findFirstSatisfiableOption([['a']], queries, matcher), undefined)
    })
  })

  describe('orderSlotsByReference', () => {
    it('orders slots by reference option position', () => {
      const slots: SlotDecomposition[] = [
        { ids: ['c'], optional: false },
        { ids: ['a'], optional: false },
        { ids: ['b'], optional: false },
      ]
      const reference = ['a', 'b', 'c']
      const ordered = orderSlotsByReference(slots, reference)
      assert.deepStrictEqual(
        ordered.map((s) => s.ids),
        [['a'], ['b'], ['c']]
      )
    })
  })

  describe('resolveScaCredentialSet', () => {
    it('returns Err on non-transposable SCA options', () => {
      const queries = buildCredentialQueryMap([
        makeQuery('sca_card'),
        makeQuery('pid_1'),
        makeQuery('pid_2'),
        makeQuery('loyalty'),
      ])
      const matcher = makeMatcher({
        sca_card: [makeCredential('c1')],
        pid_1: [makeCredential('c2')],
        pid_2: [makeCredential('c3')],
        loyalty: [makeCredential('c4')],
      })
      const credentialSet: DcqlCredentialSetQuery = {
        options: [['sca_card', 'pid_1'], ['sca_card', 'pid_2', 'loyalty'], ['sca_card']],
      }
      const transactionData = [makeTransactionData('urn:eudi:sca:payment:v1', ['sca_card'], { amount: 'EUR 100' })]
      const result = resolveScaCredentialSet(credentialSet, queries, transactionData, matcher, 'en', makeConfig())
      assert.strictEqual(isErr(result), true)
      if (isErr(result)) {
        assert.ok(result.error.includes('not transposable'))
      }
    })
  })

  describe('resolveNonScaCredentialSet', () => {
    it('never errors for decomposition issues', () => {
      const queries = buildCredentialQueryMap([makeQuery('a'), makeQuery('b'), makeQuery('c')])
      const matcher = makeMatcher({
        a: [makeCredential('c1')],
        b: [makeCredential('c2')],
        c: [makeCredential('c3')],
      })
      const credentialSet: DcqlCredentialSetQuery = {
        options: [['a', 'b'], ['a', 'b', 'c'], ['a']],
      }
      // resolveNonScaCredentialSet returns ResolvedCredentialSet directly, not a Result
      const result = resolveNonScaCredentialSet(credentialSet, queries, [], matcher, 'en', makeConfig())
      assert.ok(result)
      assert.ok(result.slots.length > 0)
    })
  })
})

// =============================================================================
// Transaction Data Resolution
// =============================================================================

describe('Transaction Data Resolution', () => {
  describe('isTargetedByTransactionData', () => {
    it('returns true when credential query is targeted', () => {
      const td = [makeTransactionData('type_a', ['cred_1', 'cred_2'])]
      assert.strictEqual(isTargetedByTransactionData('cred_1', td), true)
    })

    it('returns false when credential query is not targeted', () => {
      const td = [makeTransactionData('type_a', ['cred_1'])]
      assert.strictEqual(isTargetedByTransactionData('cred_2', td), false)
    })

    it('returns false for empty transaction data', () => {
      assert.strictEqual(isTargetedByTransactionData('any', []), false)
    })
  })

  describe('resolveFirstMatchScaTransactionData', () => {
    it('applies first-match rule per TS12 3.3', () => {
      const scaMetadata: ScaCredentialMetadata = {
        transaction_data_types: {
          'urn:eudi:sca:payment:v2': {
            claims: [
              {
                path: ['amount'],
                mandatory: true,
                value_type: 'iso_currency_amount',
                display: [{ name: 'Amount' }],
              },
            ],
            ui_labels: {
              affirmative_action_label: [{ value: 'Confirm v2' }],
            },
          },
          'urn:eudi:sca:payment:v1': {
            claims: [
              {
                path: ['amount'],
                mandatory: true,
                value_type: 'iso_currency_amount',
                display: [{ name: 'Amount' }],
              },
            ],
            ui_labels: {
              affirmative_action_label: [{ value: 'Confirm v1' }],
            },
          },
        },
      }

      // v2 entry comes first in the transaction data array
      const transactionData = [
        makeTransactionData('urn:eudi:sca:payment:v2', ['sca_card'], { amount: 'EUR 100' }),
        makeTransactionData('urn:eudi:sca:payment:v1', ['sca_card'], { amount: 'EUR 100' }),
      ]

      const result = resolveFirstMatchScaTransactionData(scaMetadata, 'sca_card', transactionData, 'en', makeConfig())
      assert.ok(result, 'should resolve')
      assert.strictEqual(result.index, 0)
      assert.strictEqual(result.entry.type, 'urn:eudi:sca:payment:v2')
    })

    it('returns undefined when no SCA entry targets the credential', () => {
      const scaMetadata: ScaCredentialMetadata = {
        transaction_data_types: {
          'urn:eudi:sca:payment:v1': {
            claims: [],
            ui_labels: { affirmative_action_label: [{ value: 'OK' }] },
          },
        },
      }
      const transactionData = [makeTransactionData('urn:eudi:sca:payment:v1', ['other_cred'], {})]
      const result = resolveFirstMatchScaTransactionData(scaMetadata, 'sca_card', transactionData, 'en', makeConfig())
      assert.strictEqual(result, undefined)
    })
  })

  describe('findFirstNonScaTransactionData', () => {
    it('uses checkNonScaTransactionDataSupport', () => {
      const config = makeConfig({
        checkNonScaTransactionDataSupport: (credentialId, type) => credentialId === 'c1' && type === 'custom_type',
      })
      const transactionData = [makeTransactionData('custom_type', ['q1'], { data: 'x' })]
      const result = findFirstNonScaTransactionData('c1', 'q1', transactionData, config)
      assert.ok(result)
      assert.strictEqual(result.index, 0)
    })

    it('returns undefined when check function is absent', () => {
      const config = makeConfig()
      const transactionData = [makeTransactionData('custom_type', ['q1'], { data: 'x' })]
      const result = findFirstNonScaTransactionData('c1', 'q1', transactionData, config)
      assert.strictEqual(result, undefined)
    })

    it('skips SCA-typed entries', () => {
      const config = makeConfig({
        checkNonScaTransactionDataSupport: () => true,
      })
      const transactionData = [
        makeTransactionData('urn:eudi:sca:payment:v1', ['q1'], { amount: '10' }),
        makeTransactionData('custom_type', ['q1'], { data: 'x' }),
      ]
      const result = findFirstNonScaTransactionData('c1', 'q1', transactionData, config)
      assert.ok(result)
      assert.strictEqual(result.index, 1)
      assert.strictEqual(result.entry.type, 'custom_type')
    })
  })

  describe('resolveAllMatchedCredentials', () => {
    it('filters credentials failing transaction data when targeted', () => {
      // Two credentials: one with SCA metadata that can resolve, one without
      const scaCred = makeScaCredential('c_sca', ['urn:eudi:sca:payment:v1'])
      const plainCred = makeCredential('c_plain')

      const transactionData = [makeTransactionData('urn:eudi:sca:payment:v1', ['q1'], { amount: 'EUR 50' })]

      const resolved = resolveAllMatchedCredentials(
        [scaCred, plainCred],
        'q1',
        undefined,
        transactionData,
        'en',
        makeConfig()
      )

      // scaCred should resolve (has matching scaMetadata), plainCred has no scaMetadata
      // and no non-SCA check, so its transactionData is undefined -> filtered out
      assert.strictEqual(resolved.length, 1)
      assert.strictEqual(resolved[0].credentialId, 'c_sca')
    })

    it('returns all credentials when not targeted by transaction data', () => {
      const cred1 = makeCredential('c1')
      const cred2 = makeCredential('c2')

      const resolved = resolveAllMatchedCredentials(
        [cred1, cred2],
        'q1',
        undefined,
        [], // no transaction data
        'en',
        makeConfig()
      )

      assert.strictEqual(resolved.length, 2)
    })
  })
})

// =============================================================================
// Versioned first-match (spec Section 3.4 example)
// =============================================================================

describe('Versioned first-match (spec Section 3.4)', () => {
  // A credential with v2 support should select the v2 entry (index 0)
  // A credential with only v1 should fall back to v1 (index 1)

  const scaMetadataV2: ScaCredentialMetadata = {
    transaction_data_types: {
      'urn:eudi:sca:payment:v2': {
        claims: [
          {
            path: ['amount'],
            mandatory: true,
            value_type: 'iso_currency_amount',
            display: [{ name: 'Amount v2' }],
          },
        ],
        ui_labels: {
          affirmative_action_label: [{ value: 'Confirm v2' }],
        },
      },
      'urn:eudi:sca:payment:v1': {
        claims: [
          {
            path: ['amount'],
            mandatory: true,
            value_type: 'iso_currency_amount',
            display: [{ name: 'Amount v1' }],
          },
        ],
        ui_labels: {
          affirmative_action_label: [{ value: 'Confirm v1' }],
        },
      },
    },
  }

  const scaMetadataV1Only: ScaCredentialMetadata = {
    transaction_data_types: {
      'urn:eudi:sca:payment:v1': {
        claims: [
          {
            path: ['amount'],
            mandatory: true,
            value_type: 'iso_currency_amount',
            display: [{ name: 'Amount v1' }],
          },
        ],
        ui_labels: {
          affirmative_action_label: [{ value: 'Confirm v1' }],
        },
      },
    },
  }

  const transactionData = [
    makeTransactionData('urn:eudi:sca:payment:v2', ['sca_card'], { amount: 'EUR 100' }),
    makeTransactionData('urn:eudi:sca:payment:v1', ['sca_card'], { amount: 'EUR 100' }),
  ]

  it('credential with v2 support selects v2 entry (index 0)', () => {
    const result = resolveFirstMatchScaTransactionData(scaMetadataV2, 'sca_card', transactionData, 'en', makeConfig())
    assert.ok(result)
    assert.strictEqual(result.index, 0)
    assert.strictEqual(result.entry.type, 'urn:eudi:sca:payment:v2')
  })

  it('credential with only v1 falls back to v1 (index 1)', () => {
    const result = resolveFirstMatchScaTransactionData(
      scaMetadataV1Only,
      'sca_card',
      transactionData,
      'en',
      makeConfig()
    )
    assert.ok(result)
    assert.strictEqual(result.index, 1)
    assert.strictEqual(result.entry.type, 'urn:eudi:sca:payment:v1')
  })
})

// =============================================================================
// Top-level resolveDcql
// =============================================================================

describe('Top-level resolveDcql', () => {
  describe('hasScaTransactionData', () => {
    it('detects SCA transaction data', () => {
      assert.strictEqual(hasScaTransactionData([makeTransactionData('urn:eudi:sca:payment:v1', ['c1'])]), true)
    })

    it('returns false for non-SCA transaction data', () => {
      assert.strictEqual(hasScaTransactionData([makeTransactionData('custom_type', ['c1'])]), false)
    })

    it('returns false for empty array', () => {
      assert.strictEqual(hasScaTransactionData([]), false)
    })
  })

  describe('validateTransactionDataCredentialSet', () => {
    it('returns undefined when no transaction data', () => {
      const dcqlQuery = {
        credentials: [makeQuery('a')],
        credential_sets: [{ options: [['a']] }],
      }
      assert.strictEqual(validateTransactionDataCredentialSet(dcqlQuery, []), undefined)
    })

    it('returns undefined when no credential sets', () => {
      const dcqlQuery = { credentials: [makeQuery('a')] }
      const td = [makeTransactionData('some_type', ['a'])]
      assert.strictEqual(validateTransactionDataCredentialSet(dcqlQuery, td), undefined)
    })

    it('returns error when credential IDs span multiple sets', () => {
      const dcqlQuery = {
        credentials: [makeQuery('a'), makeQuery('b')],
        credential_sets: [{ options: [['a']] }, { options: [['b']] }],
      }
      const td = [makeTransactionData('some_type', ['a', 'b'])]
      const error = validateTransactionDataCredentialSet(dcqlQuery, td)
      assert.ok(error, 'should return an error string')
      assert.ok(error.includes('same credential set'))
    })

    it('returns undefined when all credential IDs are in the same set', () => {
      const dcqlQuery = {
        credentials: [makeQuery('a'), makeQuery('b')],
        credential_sets: [{ options: [['a', 'b'], ['a']] }],
      }
      const td = [makeTransactionData('some_type', ['a', 'b'])]
      assert.strictEqual(validateTransactionDataCredentialSet(dcqlQuery, td), undefined)
    })
  })

  describe('SCA path: strict locale + transposability', () => {
    it('resolves transposable SCA credential sets', () => {
      const queries = [makeQuery('sca_card'), makeQuery('pid')]
      const dcqlQuery = {
        credentials: queries,
        credential_sets: [
          {
            options: [['sca_card', 'pid'], ['sca_card']],
          },
        ],
      }

      const scaCred = makeScaCredential('c_sca', ['urn:eudi:sca:payment:v1'])
      const pidCred = makeCredential('c_pid')

      const matcher = makeMatcher({
        sca_card: [scaCred],
        pid: [pidCred],
      })
      const transactionData = [makeTransactionData('urn:eudi:sca:payment:v1', ['sca_card'], { amount: 'EUR 50' })]

      const result = resolveDcql(dcqlQuery, transactionData, matcher, makeConfig())
      assert.strictEqual(isOk(result), true)
      if (isOk(result)) {
        assert.strictEqual(result.value.locale, 'en')
        assert.strictEqual(result.value.credentialSets.length, 1)
        assert.ok(result.value.credentialSets[0].slots.length > 0)
      }
    })

    it('returns Err for non-transposable SCA options', () => {
      const queries = [makeQuery('sca_card'), makeQuery('pid_1'), makeQuery('pid_2'), makeQuery('loyalty')]
      const dcqlQuery = {
        credentials: queries,
        credential_sets: [
          {
            options: [['sca_card', 'pid_1'], ['sca_card', 'pid_2', 'loyalty'], ['sca_card']],
          },
        ],
      }

      const matcher = makeMatcher({
        sca_card: [makeScaCredential('c_sca', ['urn:eudi:sca:payment:v1'])],
        pid_1: [makeCredential('c_pid1')],
        pid_2: [makeCredential('c_pid2')],
        loyalty: [makeCredential('c_loy')],
      })
      const transactionData = [makeTransactionData('urn:eudi:sca:payment:v1', ['sca_card'], { amount: 'EUR 50' })]

      const result = resolveDcql(dcqlQuery, transactionData, matcher, makeConfig())
      assert.strictEqual(isErr(result), true)
    })
  })

  describe('Non-SCA path: best-effort', () => {
    it('resolves with best-effort decomposition', () => {
      const queries = [makeQuery('a'), makeQuery('b'), makeQuery('c')]
      const dcqlQuery = {
        credentials: queries,
        credential_sets: [
          {
            options: [['a', 'b'], ['a', 'c'], ['a']],
          },
        ],
      }

      const matcher = makeMatcher({
        a: [makeCredential('c1')],
        b: [makeCredential('c2')],
        c: [makeCredential('c3')],
      })

      const result = resolveDcql(dcqlQuery, [], matcher, makeConfig())
      assert.strictEqual(isOk(result), true)
      if (isOk(result)) {
        assert.strictEqual(result.value.locale, 'en')
        assert.strictEqual(result.value.credentialSets.length, 1)
      }
    })

    it('returns ok with empty credentialSets when no credential_sets defined', () => {
      const result = resolveDcql(
        { credentials: [makeQuery('a')] },
        [],
        makeMatcher({ a: [makeCredential('c1')] }),
        makeConfig()
      )
      assert.strictEqual(isOk(result), true)
      if (isOk(result)) {
        assert.deepStrictEqual(result.value.credentialSets, [])
      }
    })
  })
})
