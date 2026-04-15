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
  canResolveCredentialForLocale,
  findFirstNonScaTransactionData,
  isTargetedByTransactionData,
  resolveAllMatchedCredentials,
  resolveFirstMatchScaTransactionData,
} from '../packages/dcql/src/resolve-credentials'
import {
  buildCredentialQueryMap,
  hasScaTransactionData,
  resolveDcql,
  validateDcqlQueryStructure,
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
      string: (v: string) => v,
      iso_currency_amount: (v: string) => v,
    },
    mode: 'light',
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

function makeMatcher(available: Record<string, MatchedCredential[]>): CredentialMatcher {
  return (query: DcqlCredentialQuery) => available[query.id] ?? []
}

/** buildCredentialQueryMap that asserts no duplicates (for test fixtures with unique IDs). */
function buildQueryMap(queries: DcqlCredentialQuery[]): Map<string, DcqlCredentialQuery> {
  const map = buildCredentialQueryMap(queries)
  assert.ok(map, 'Test fixture has duplicate query IDs')
  return map
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
// Section 3.3 — First-match rule (resolveFirstMatchScaTransactionData)
// =============================================================================

describe('Section 3.3 — First-match rule (resolveFirstMatchScaTransactionData)', () => {
  const scaMetadataBothVersions: ScaCredentialMetadata = {
    transaction_data_types: {
      'urn:eudi:sca:com.example.pay:transaction:2': {
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
      'urn:eudi:sca:com.example.pay:transaction:1': {
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
      'urn:eudi:sca:com.example.pay:transaction:1': {
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

  it('selects the first compatible entry in array order', () => {
    // v2 entry is at index 0, v1 at index 1. Credential supports both.
    const transactionData = [
      makeTransactionData('urn:eudi:sca:com.example.pay:transaction:2', ['sca_card'], { amount: 'EUR 100' }),
      makeTransactionData('urn:eudi:sca:com.example.pay:transaction:1', ['sca_card'], { amount: 'EUR 100' }),
    ]

    const result = resolveFirstMatchScaTransactionData(
      scaMetadataBothVersions,
      'sca_card',
      transactionData,
      'en',
      makeConfig()
    )
    assert.ok(result, 'should resolve')
    assert.strictEqual(result.index, 0)
    assert.strictEqual(result.entry.type, 'urn:eudi:sca:com.example.pay:transaction:2')
  })

  it('falls back to older version when newer does not match', () => {
    // v2 entry at index 0, v1 at index 1. Credential only supports v1.
    const transactionData = [
      makeTransactionData('urn:eudi:sca:com.example.pay:transaction:2', ['sca_card'], { amount: 'EUR 100' }),
      makeTransactionData('urn:eudi:sca:com.example.pay:transaction:1', ['sca_card'], { amount: 'EUR 100' }),
    ]

    const result = resolveFirstMatchScaTransactionData(
      scaMetadataV1Only,
      'sca_card',
      transactionData,
      'en',
      makeConfig()
    )
    assert.ok(result, 'should resolve')
    assert.strictEqual(result.index, 1)
    assert.strictEqual(result.entry.type, 'urn:eudi:sca:com.example.pay:transaction:1')
  })

  it('only entries with matching credential_ids are considered', () => {
    const transactionData = [
      makeTransactionData('urn:eudi:sca:com.example.pay:transaction:1', ['other_credential'], { amount: 'EUR 50' }),
    ]

    const result = resolveFirstMatchScaTransactionData(
      scaMetadataBothVersions,
      'sca_card',
      transactionData,
      'en',
      makeConfig()
    )
    assert.strictEqual(result, undefined)
  })

  it('returns undefined when no entry matches', () => {
    // Credential supports v1 only, but only v2 entries are provided
    const scaMetadataV2Only: ScaCredentialMetadata = {
      transaction_data_types: {
        'urn:eudi:sca:com.example.pay:transaction:2': {
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
      },
    }

    const transactionData = [
      makeTransactionData('urn:eudi:sca:com.example.pay:transaction:1', ['sca_card'], { amount: 'EUR 100' }),
    ]

    const result = resolveFirstMatchScaTransactionData(
      scaMetadataV2Only,
      'sca_card',
      transactionData,
      'en',
      makeConfig()
    )
    assert.strictEqual(result, undefined)
  })
})

// =============================================================================
// Section 3.3 — Credential exclusion (resolveAllMatchedCredentials)
// =============================================================================

describe('Section 3.3 — Credential exclusion (resolveAllMatchedCredentials)', () => {
  it('excludes credentials that fail transaction data resolution when targeted', () => {
    const scaCred = makeScaCredential('c_sca', ['urn:eudi:sca:com.example.pay:transaction:1'])
    const plainCred = makeCredential('c_plain')

    const transactionData = [
      makeTransactionData('urn:eudi:sca:com.example.pay:transaction:1', ['q1'], { amount: 'EUR 50' }),
    ]

    const resolved = resolveAllMatchedCredentials(
      [scaCred, plainCred],
      'q1',
      undefined,
      transactionData,
      'en',
      makeConfig()
    )

    // scaCred has matching scaMetadata so it resolves. plainCred has no scaMetadata
    // and no checkNonScaTransactionDataSupport, so its transactionData is undefined => filtered out.
    assert.strictEqual(resolved.length, 1)
    assert.strictEqual(resolved[0].credentialId, 'c_sca')
    assert.ok(resolved[0].transactionData, 'should have transactionData')
  })

  it('does not filter non-targeted credentials', () => {
    const cred1 = makeCredential('c1')
    const cred2 = makeCredential('c2')

    // Transaction data targets a different query ID
    const transactionData = [
      makeTransactionData('urn:eudi:sca:com.example.pay:transaction:1', ['other_query'], { amount: 'EUR 50' }),
    ]

    const resolved = resolveAllMatchedCredentials([cred1, cred2], 'q1', undefined, transactionData, 'en', makeConfig())

    assert.strictEqual(resolved.length, 2)
  })

  it('returns all credentials when there is no transaction data', () => {
    const cred1 = makeCredential('c1')
    const cred2 = makeCredential('c2')

    const resolved = resolveAllMatchedCredentials([cred1, cred2], 'q1', undefined, [], 'en', makeConfig())

    assert.strictEqual(resolved.length, 2)
  })
})

// =============================================================================
// Section 3.3 — Non-SCA transaction data (findFirstNonScaTransactionData)
// =============================================================================

describe('Section 3.3 — Non-SCA transaction data (findFirstNonScaTransactionData)', () => {
  it('uses checkNonScaTransactionDataSupport callback', () => {
    const config = makeConfig({
      checkNonScaTransactionDataSupport: (credentialId, type) => credentialId === 'c1' && type === 'custom_type',
    })
    const transactionData = [makeTransactionData('custom_type', ['q1'], { data: 'x' })]
    const result = findFirstNonScaTransactionData('c1', 'q1', transactionData, config)
    assert.ok(result)
    assert.strictEqual(result.index, 0)
    assert.strictEqual(result.entry.type, 'custom_type')
  })

  it('returns undefined when callback is absent', () => {
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
      makeTransactionData('urn:eudi:sca:com.example.pay:transaction:1', ['q1'], { amount: '10' }),
      makeTransactionData('custom_type', ['q1'], { data: 'x' }),
    ]
    const result = findFirstNonScaTransactionData('c1', 'q1', transactionData, config)
    assert.ok(result)
    assert.strictEqual(result.index, 1)
    assert.strictEqual(result.entry.type, 'custom_type')
  })

  it('returns undefined when callback rejects the type', () => {
    const config = makeConfig({
      checkNonScaTransactionDataSupport: () => false,
    })
    const transactionData = [makeTransactionData('custom_type', ['q1'], { data: 'x' })]
    const result = findFirstNonScaTransactionData('c1', 'q1', transactionData, config)
    assert.strictEqual(result, undefined)
  })

  it('returns undefined when credential query is not targeted', () => {
    const config = makeConfig({
      checkNonScaTransactionDataSupport: () => true,
    })
    const transactionData = [makeTransactionData('custom_type', ['other_query'], { data: 'x' })]
    const result = findFirstNonScaTransactionData('c1', 'q1', transactionData, config)
    assert.strictEqual(result, undefined)
  })
})

// =============================================================================
// Section 3.4 — Transposability
// =============================================================================

describe('Section 3.4 — Transposability', () => {
  describe('decomposeTransposable', () => {
    it('decomposes transposable options into independent slots', () => {
      // Spec example: [["sca_card","pid_1"], ["sca_card","pid_2"], ["sca_card"]]
      const alternatives = [['sca_card', 'pid_1'], ['sca_card', 'pid_2'], ['sca_card']]
      const result = decomposeTransposable(alternatives)
      assert.ok(result, 'should be transposable')
      assert.strictEqual(result.length, 2)

      const scaSlot = result.find((s) => s.ids.includes('sca_card'))
      assert.ok(scaSlot)
      assert.strictEqual(scaSlot.optional, false)

      const pidSlot = result.find((s) => s.ids.includes('pid_1'))
      assert.ok(pidSlot)
      assert.ok(pidSlot.ids.includes('pid_2'))
      assert.strictEqual(pidSlot.optional, true)
    })

    it('returns undefined for non-transposable options', () => {
      // Spec counterexample: pid_2 and loyalty co-occur in one option but not in all
      const alternatives = [['sca_card', 'pid_1'], ['sca_card', 'pid_2', 'loyalty'], ['sca_card']]
      const result = decomposeTransposable(alternatives)
      assert.strictEqual(result, undefined)
    })

    it('detects optional slot via empty-set presence', () => {
      // ["sca_card"] means the pid slot is absent => optional
      const alternatives = [['sca_card', 'pid'], ['sca_card']]
      const result = decomposeTransposable(alternatives)
      assert.ok(result)
      assert.strictEqual(result.length, 2)

      const pidSlot = result.find((s) => s.ids.includes('pid'))
      assert.ok(pidSlot)
      assert.strictEqual(pidSlot.optional, true)

      const scaSlot = result.find((s) => s.ids.includes('sca_card'))
      assert.ok(scaSlot)
      assert.strictEqual(scaSlot.optional, false)
    })

    it('handles multiple SCA alternatives in the same slot', () => {
      // sca_card and sca_account never co-occur => same slot
      const alternatives = [['sca_card', 'pid'], ['sca_card'], ['sca_account', 'pid'], ['sca_account']]
      const result = decomposeTransposable(alternatives)
      assert.ok(result, 'should be transposable')
      assert.strictEqual(result.length, 2)

      const scaSlot = result.find((s) => s.ids.includes('sca_card'))
      assert.ok(scaSlot)
      assert.ok(scaSlot.ids.includes('sca_account'))
    })

    it('returns empty array for empty input', () => {
      const result = decomposeTransposable([])
      assert.ok(result)
      assert.strictEqual(result.length, 0)
    })

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

  describe('verifyCartesianProduct', () => {
    it('returns true when alternatives equal the product', () => {
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

    it('returns false on size mismatch', () => {
      const slots: SlotDecomposition[] = [
        { ids: ['a', 'b'], optional: false },
        { ids: ['x'], optional: false },
      ]
      const alternatives = [['a', 'x']]
      assert.strictEqual(verifyCartesianProduct(slots, alternatives), false)
    })

    it('returns false when an alternative is not in the product', () => {
      const slots: SlotDecomposition[] = [
        { ids: ['a', 'b'], optional: false },
        { ids: ['x'], optional: false },
      ]
      const alternatives = [
        ['a', 'x'],
        ['a', 'y'],
      ]
      assert.strictEqual(verifyCartesianProduct(slots, alternatives), false)
    })

    it('verifies product with optional slots including the empty option', () => {
      const slots: SlotDecomposition[] = [
        { ids: ['a'], optional: false },
        { ids: ['x', 'y'], optional: true },
      ]
      const alternatives = [['a', 'x'], ['a', 'y'], ['a']]
      assert.strictEqual(verifyCartesianProduct(slots, alternatives), true)
    })
  })

  describe('generateCartesianProduct', () => {
    it('generates product with optional slots', () => {
      const slots: SlotDecomposition[] = [
        { ids: ['a'], optional: false },
        { ids: ['x', 'y'], optional: true },
      ]
      const product = generateCartesianProduct(slots)
      assert.strictEqual(product.length, 3)
      const sorted = product.map((a) => [...a].sort()).sort()
      const expected = [['a'], ['a', 'x'], ['a', 'y']].map((a) => [...a].sort()).sort()
      assert.deepStrictEqual(sorted, expected)
    })

    it('returns [[]] for empty slots', () => {
      assert.deepStrictEqual(generateCartesianProduct([]), [[]])
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

    it('always succeeds even for non-transposable input', () => {
      const alternatives = [['sca_card', 'pid_1'], ['sca_card', 'pid_2', 'loyalty'], ['sca_card']]
      const result = bestEffortDecompose(alternatives)
      assert.ok(result.length > 0, 'should return at least one slot')
      const allIds = result.flatMap((s) => s.ids)
      assert.ok(allIds.includes('sca_card'))
      assert.ok(allIds.includes('pid_1'))
    })

    it('returns empty for empty input', () => {
      assert.deepStrictEqual(bestEffortDecompose([]), [])
    })
  })

  describe('buildCoOccurrences', () => {
    it('detects pairs that co-occur', () => {
      const pairs = buildCoOccurrences([
        ['a', 'b'],
        ['a', 'c'],
      ])
      assert.strictEqual(pairs.has('a\0b'), true)
      assert.strictEqual(pairs.has('a\0c'), true)
      assert.strictEqual(pairs.has('b\0c'), false)
    })

    it('normalizes pair keys min\\0max', () => {
      const pairs = buildCoOccurrences([['z', 'a']])
      assert.strictEqual(pairs.has('a\0z'), true)
      assert.strictEqual(pairs.has('z\0a'), false)
    })
  })
})

// =============================================================================
// Section 3.4 — Credential set resolution
// =============================================================================

describe('Section 3.4 — Credential set resolution', () => {
  describe('resolveScaCredentialSet', () => {
    it('SCA options MUST be transposable — returns Err if not', () => {
      const queries = buildQueryMap([
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
      const transactionData = [
        makeTransactionData('urn:eudi:sca:com.example.pay:transaction:1', ['sca_card'], { amount: 'EUR 100' }),
      ]
      const result = resolveScaCredentialSet(credentialSet, queries, transactionData, matcher, 'en', makeConfig())
      assert.strictEqual(isErr(result), true)
      if (isErr(result)) {
        assert.ok(result.error.includes('not transposable'))
      }
    })

    it('resolves transposable SCA options into slots', () => {
      const queries = buildQueryMap([makeQuery('sca_card'), makeQuery('pid')])
      const scaCred = makeScaCredential('c_sca', ['urn:eudi:sca:com.example.pay:transaction:1'])
      const pidCred = makeCredential('c_pid')
      const matcher = makeMatcher({
        sca_card: [scaCred],
        pid: [pidCred],
      })
      const credentialSet: DcqlCredentialSetQuery = {
        options: [['sca_card', 'pid'], ['sca_card']],
      }
      const transactionData = [
        makeTransactionData('urn:eudi:sca:com.example.pay:transaction:1', ['sca_card'], { amount: 'EUR 50' }),
      ]
      const result = resolveScaCredentialSet(credentialSet, queries, transactionData, matcher, 'en', makeConfig())
      assert.strictEqual(isOk(result), true)
      if (isOk(result)) {
        assert.ok(result.value.slots.length > 0)
        assert.strictEqual(result.value.required, true)
      }
    })
  })

  describe('resolveNonScaCredentialSet', () => {
    it('uses best-effort — never errors', () => {
      const queries = buildQueryMap([makeQuery('a'), makeQuery('b'), makeQuery('c')])
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

    it('preserves description and required fields', () => {
      const queries = buildQueryMap([makeQuery('a')])
      const matcher = makeMatcher({ a: [makeCredential('c1')] })
      const credentialSet: DcqlCredentialSetQuery = {
        options: [['a']],
        description: 'Test set',
        required: false,
      }
      const result = resolveNonScaCredentialSet(credentialSet, queries, [], matcher, 'en', makeConfig())
      assert.strictEqual(result.description, 'Test set')
      assert.strictEqual(result.required, false)
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

    it('returns all as nonSca when no SCA ids', () => {
      const options = [['a', 'b'], ['c']]
      const { sca, nonSca } = partitionOptions(options, new Set())
      assert.strictEqual(sca.length, 0)
      assert.strictEqual(nonSca.length, 2)
    })

    it('returns all as sca when every option contains an SCA id', () => {
      const options = [['sca_card', 'pid'], ['sca_card']]
      const { sca, nonSca } = partitionOptions(options, new Set(['sca_card']))
      assert.strictEqual(sca.length, 2)
      assert.strictEqual(nonSca.length, 0)
    })
  })

  describe('orderSlotsByReference', () => {
    it('orders slots by first-appearance position in reference option', () => {
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

    it('preserves order when ids overlap with reference positions', () => {
      const slots: SlotDecomposition[] = [
        { ids: ['x', 'y'], optional: true },
        { ids: ['a'], optional: false },
      ]
      const reference = ['a', 'x']
      const ordered = orderSlotsByReference(slots, reference)
      assert.deepStrictEqual(
        ordered.map((s) => s.ids),
        [['a'], ['x', 'y']]
      )
    })
  })

  describe('collectScaCredentialQueryIds', () => {
    it('collects IDs from SCA entries only', () => {
      const td = [
        makeTransactionData('urn:eudi:sca:com.example.pay:transaction:1', ['sca_card']),
        makeTransactionData('other_type', ['other_cred']),
        makeTransactionData('urn:eudi:sca:eu.europa.ec:transfer:single:1', ['sca_account', 'pid']),
      ]
      const ids = collectScaCredentialQueryIds(td, makeConfig())
      assert.deepStrictEqual([...ids].sort(), ['pid', 'sca_account', 'sca_card'])
    })

    it('returns empty set when no SCA entries', () => {
      const td = [makeTransactionData('custom_type', ['cred1'])]
      const ids = collectScaCredentialQueryIds(td, makeConfig())
      assert.strictEqual(ids.size, 0)
    })
  })

  describe('isOptionSatisfiable', () => {
    it('returns true when all queries have matches', () => {
      const queries = buildQueryMap([makeQuery('a'), makeQuery('b')])
      const matcher = makeMatcher({
        a: [makeCredential('c1')],
        b: [makeCredential('c2')],
      })
      assert.strictEqual(isOptionSatisfiable(['a', 'b'], queries, matcher), true)
    })

    it('returns false when some queries have no matches', () => {
      const queries = buildQueryMap([makeQuery('a'), makeQuery('b')])
      const matcher = makeMatcher({ a: [makeCredential('c1')], b: [] })
      assert.strictEqual(isOptionSatisfiable(['a', 'b'], queries, matcher), false)
    })

    it('returns false when query is missing from map', () => {
      const queries = buildQueryMap([makeQuery('a')])
      const matcher = makeMatcher({ a: [makeCredential('c1')] })
      assert.strictEqual(isOptionSatisfiable(['a', 'missing'], queries, matcher), false)
    })
  })

  describe('findFirstSatisfiableOption', () => {
    it('returns the first satisfiable option', () => {
      const queries = buildQueryMap([makeQuery('a'), makeQuery('b'), makeQuery('c')])
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
      const queries = buildQueryMap([makeQuery('a')])
      const matcher = makeMatcher({ a: [] })
      assert.strictEqual(findFirstSatisfiableOption([['a']], queries, matcher), undefined)
    })
  })
})

// =============================================================================
// Section 3.4 — DCQL validation (validateTransactionDataCredentialSet)
// =============================================================================

describe('Section 3.4 — DCQL validation (validateTransactionDataCredentialSet)', () => {
  it('all SCA credential_ids must appear in the same credential set', () => {
    const dcqlQuery = {
      credentials: [makeQuery('a'), makeQuery('b')],
      credential_sets: [{ options: [['a']] }, { options: [['b']] }],
    }
    const td = [makeTransactionData('some_type', ['a', 'b'])]
    const error = validateTransactionDataCredentialSet(dcqlQuery, td)
    assert.ok(error, 'should return an error string')
    assert.ok(error.includes('same credential set'))
  })

  it('passes when no transaction_data', () => {
    const dcqlQuery = {
      credentials: [makeQuery('a')],
      credential_sets: [{ options: [['a']] }],
    }
    assert.strictEqual(validateTransactionDataCredentialSet(dcqlQuery, []), undefined)
  })

  it('passes when no credential_sets', () => {
    const dcqlQuery = { credentials: [makeQuery('a')] }
    const td = [makeTransactionData('some_type', ['a'])]
    assert.strictEqual(validateTransactionDataCredentialSet(dcqlQuery, td), undefined)
  })

  it('passes when all credential IDs are in the same set', () => {
    const dcqlQuery = {
      credentials: [makeQuery('a'), makeQuery('b')],
      credential_sets: [{ options: [['a', 'b'], ['a']] }],
    }
    const td = [makeTransactionData('some_type', ['a', 'b'])]
    assert.strictEqual(validateTransactionDataCredentialSet(dcqlQuery, td), undefined)
  })

  it('passes with empty credential_sets array', () => {
    const dcqlQuery = {
      credentials: [makeQuery('a')],
      credential_sets: [],
    }
    const td = [makeTransactionData('some_type', ['a'])]
    assert.strictEqual(validateTransactionDataCredentialSet(dcqlQuery, td), undefined)
  })
})

// =============================================================================
// Section 3.5.4 — Locale selection in SCA path (canResolveCredentialForLocale)
// =============================================================================

describe('Section 3.5.4 — Locale selection in SCA path', () => {
  it('locale must satisfy ALL display arrays (canResolveCredentialForLocale)', () => {
    // Credential with display that only has a French entry
    const cred: MatchedCredential = {
      credentialId: 'c1',
      display: [{ name: 'Carte', locale: 'fr' }],
    }
    // Trying to resolve for 'en' should fail because the display has no matching locale
    const result = canResolveCredentialForLocale(cred, 'q1', [], 'en', makeConfig())
    assert.strictEqual(result, false)
  })

  it('locale succeeds when display has a matching entry', () => {
    const cred: MatchedCredential = {
      credentialId: 'c1',
      display: [
        { name: 'Card', locale: 'en' },
        { name: 'Carte', locale: 'fr' },
      ],
    }
    const result = canResolveCredentialForLocale(cred, 'q1', [], 'en', makeConfig())
    assert.strictEqual(result, true)
  })

  it('locale succeeds when display has a default entry (no locale)', () => {
    const cred: MatchedCredential = {
      credentialId: 'c1',
      display: [{ name: 'Card' }],
    }
    const result = canResolveCredentialForLocale(cred, 'q1', [], 'de', makeConfig())
    assert.strictEqual(result, true)
  })

  it('locale succeeds when credential has no display at all', () => {
    const cred: MatchedCredential = { credentialId: 'c1' }
    const result = canResolveCredentialForLocale(cred, 'q1', [], 'en', makeConfig())
    assert.strictEqual(result, true)
  })

  it('SCA transaction display must also resolve for the locale', () => {
    const cred = makeScaCredential('c1', ['urn:eudi:sca:com.example.pay:transaction:1'])
    const transactionData = [
      makeTransactionData('urn:eudi:sca:com.example.pay:transaction:1', ['q1'], { amount: 'EUR 50' }),
    ]
    // Default config with 'en' locale. SCA metadata claims have display with no locale
    // (default entry), so it should resolve for 'en'.
    const result = canResolveCredentialForLocale(cred, 'q1', transactionData, 'en', makeConfig())
    assert.strictEqual(result, true)
  })

  it('priority list: first complete match wins in resolveDcql', () => {
    // Credential display only has 'fr' entry.
    // Config has locales: ['en', 'fr'].
    // 'en' should fail, 'fr' should succeed.
    const queries = [makeQuery('sca_card')]
    const scaCred: MatchedCredential = {
      credentialId: 'c_sca',
      display: [{ name: 'Carte SCA', locale: 'fr' }],
      scaMetadata: {
        transaction_data_types: {
          'urn:eudi:sca:com.example.pay:transaction:1': {
            claims: [
              {
                path: ['amount'],
                mandatory: true,
                value_type: 'iso_currency_amount',
                display: [{ name: 'Montant', locale: 'fr' }],
              },
            ],
            ui_labels: {
              affirmative_action_label: [{ value: 'Confirmer', locale: 'fr' }],
            },
          },
        },
      } as ScaCredentialMetadata,
    }
    const dcqlQuery = {
      credentials: queries,
      credential_sets: [{ options: [['sca_card']] }],
    }
    const matcher = makeMatcher({ sca_card: [scaCred] })
    const transactionData = [
      makeTransactionData('urn:eudi:sca:com.example.pay:transaction:1', ['sca_card'], { amount: 'EUR 50' }),
    ]
    const config = makeConfig({ locales: ['en', 'fr'] })
    const result = resolveDcql(dcqlQuery, transactionData, matcher, config)
    assert.strictEqual(isOk(result), true)
    if (isOk(result)) {
      assert.strictEqual(result.value.locale, 'fr')
    }
  })

  it('priority list exhausted returns Err', () => {
    // Credential display only has 'ja' entry.
    // Config has locales: ['en', 'fr']. Neither matches.
    const queries = [makeQuery('sca_card')]
    const scaCred: MatchedCredential = {
      credentialId: 'c_sca',
      display: [{ name: 'SCA Card', locale: 'ja' }],
      scaMetadata: {
        transaction_data_types: {
          'urn:eudi:sca:com.example.pay:transaction:1': {
            claims: [
              {
                path: ['amount'],
                mandatory: true,
                value_type: 'iso_currency_amount',
                display: [{ name: 'Amount', locale: 'ja' }],
              },
            ],
            ui_labels: {
              affirmative_action_label: [{ value: 'OK', locale: 'ja' }],
            },
          },
        },
      } as ScaCredentialMetadata,
    }
    const dcqlQuery = {
      credentials: queries,
      credential_sets: [{ options: [['sca_card']] }],
    }
    const matcher = makeMatcher({ sca_card: [scaCred] })
    const transactionData = [
      makeTransactionData('urn:eudi:sca:com.example.pay:transaction:1', ['sca_card'], { amount: 'EUR 50' }),
    ]
    const config = makeConfig({ locales: ['en', 'fr'] })
    const result = resolveDcql(dcqlQuery, transactionData, matcher, config)
    assert.strictEqual(isErr(result), true)
    if (isErr(result)) {
      assert.ok(result.error.includes('locale'))
    }
  })
})

// =============================================================================
// SCA/non-SCA path detection (hasScaTransactionData, resolveDcql)
// =============================================================================

describe('SCA/non-SCA path detection', () => {
  describe('hasScaTransactionData', () => {
    it('returns true when any transaction_data entry is SCA-typed', () => {
      assert.strictEqual(
        hasScaTransactionData(
          [makeTransactionData('urn:eudi:sca:com.example.pay:transaction:1', ['c1'])],
          makeConfig()
        ),
        true
      )
    })

    it('returns true when SCA mixed with non-SCA', () => {
      assert.strictEqual(
        hasScaTransactionData(
          [
            makeTransactionData('custom_type', ['c1']),
            makeTransactionData('urn:eudi:sca:com.example.pay:transaction:1', ['c2']),
          ],
          makeConfig()
        ),
        true
      )
    })

    it('returns false when none are SCA', () => {
      assert.strictEqual(hasScaTransactionData([makeTransactionData('custom_type', ['c1'])], makeConfig()), false)
    })

    it('returns false for empty array', () => {
      assert.strictEqual(hasScaTransactionData([], makeConfig()), false)
    })
  })

  describe('resolveDcql — SCA path', () => {
    it('takes SCA path when any transaction_data entry is SCA-typed', () => {
      const queries = [makeQuery('sca_card'), makeQuery('pid')]
      const dcqlQuery = {
        credentials: queries,
        credential_sets: [{ options: [['sca_card', 'pid'], ['sca_card']] }],
      }

      const scaCred = makeScaCredential('c_sca', ['urn:eudi:sca:com.example.pay:transaction:1'])
      const pidCred = makeCredential('c_pid')
      const matcher = makeMatcher({
        sca_card: [scaCred],
        pid: [pidCred],
      })
      const transactionData = [
        makeTransactionData('urn:eudi:sca:com.example.pay:transaction:1', ['sca_card'], { amount: 'EUR 50' }),
      ]

      const result = resolveDcql(dcqlQuery, transactionData, matcher, makeConfig())
      assert.strictEqual(isOk(result), true)
      if (isOk(result)) {
        assert.strictEqual(result.value.locale, 'en')
        assert.strictEqual(result.value.credentialSets.length, 1)
        assert.ok(result.value.credentialSets[0].slots.length > 0)
      }
    })

    it('SCA path returns Err for non-transposable options', () => {
      const queries = [makeQuery('sca_card'), makeQuery('pid_1'), makeQuery('pid_2'), makeQuery('loyalty')]
      const dcqlQuery = {
        credentials: queries,
        credential_sets: [{ options: [['sca_card', 'pid_1'], ['sca_card', 'pid_2', 'loyalty'], ['sca_card']] }],
      }

      const matcher = makeMatcher({
        sca_card: [makeScaCredential('c_sca', ['urn:eudi:sca:com.example.pay:transaction:1'])],
        pid_1: [makeCredential('c_pid1')],
        pid_2: [makeCredential('c_pid2')],
        loyalty: [makeCredential('c_loy')],
      })
      const transactionData = [
        makeTransactionData('urn:eudi:sca:com.example.pay:transaction:1', ['sca_card'], { amount: 'EUR 50' }),
      ]

      const result = resolveDcql(dcqlQuery, transactionData, matcher, makeConfig())
      assert.strictEqual(isErr(result), true)
    })
  })

  describe('resolveDcql — Non-SCA path', () => {
    it('takes non-SCA path when none are SCA', () => {
      const queries = [makeQuery('a'), makeQuery('b'), makeQuery('c')]
      const dcqlQuery = {
        credentials: queries,
        credential_sets: [{ options: [['a', 'b'], ['a', 'c'], ['a']] }],
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

    it('non-SCA path selects first locale, never errors for decomposition', () => {
      const queries = [makeQuery('a'), makeQuery('b'), makeQuery('c')]
      const dcqlQuery = {
        credentials: queries,
        // non-transposable options — would fail in SCA path but not here
        credential_sets: [{ options: [['a', 'b'], ['a', 'b', 'c'], ['a']] }],
      }

      const matcher = makeMatcher({
        a: [makeCredential('c1')],
        b: [makeCredential('c2')],
        c: [makeCredential('c3')],
      })

      const config = makeConfig({ locales: ['de', 'fr'] })
      const result = resolveDcql(dcqlQuery, [], matcher, config)
      assert.strictEqual(isOk(result), true)
      if (isOk(result)) {
        // Non-SCA always picks the first locale from the priority list
        assert.strictEqual(result.value.locale, 'de')
      }
    })

    it('non-SCA path with non-SCA transaction data', () => {
      const queries = [makeQuery('a')]
      const dcqlQuery = {
        credentials: queries,
        credential_sets: [{ options: [['a']] }],
      }

      const matcher = makeMatcher({
        a: [makeCredential('c1')],
      })
      const transactionData = [makeTransactionData('custom_type', ['a'], { data: 'test' })]

      const config = makeConfig({
        checkNonScaTransactionDataSupport: () => true,
      })
      const result = resolveDcql(dcqlQuery, transactionData, matcher, config)
      assert.strictEqual(isOk(result), true)
    })
  })
})

// =============================================================================
// Output structure
// =============================================================================

describe('Output structure', () => {
  it('SCA resolved credential includes transactionData.resolved', () => {
    const queries = [makeQuery('sca_card')]
    const dcqlQuery = {
      credentials: queries,
      credential_sets: [{ options: [['sca_card']] }],
    }

    const scaCred = makeScaCredential('c_sca', ['urn:eudi:sca:com.example.pay:transaction:1'])
    const matcher = makeMatcher({ sca_card: [scaCred] })
    const transactionData = [
      makeTransactionData('urn:eudi:sca:com.example.pay:transaction:1', ['sca_card'], { amount: 'EUR 50' }),
    ]

    const result = resolveDcql(dcqlQuery, transactionData, matcher, makeConfig())
    assert.strictEqual(isOk(result), true)
    if (isOk(result)) {
      const sets = result.value.credentialSets
      assert.strictEqual(sets.length, 1)
      const slot = sets[0].slots[0]
      const alt = slot.alternatives[0]
      const cred = alt.credentials[0]
      assert.ok(cred.transactionData, 'should have transactionData')
      assert.ok(cred.transactionData.resolved, 'SCA credential should have resolved transaction display')
      assert.strictEqual(cred.transactionData.entry.type, 'urn:eudi:sca:com.example.pay:transaction:1')
    }
  })

  it('non-SCA credential includes raw entry without resolved', () => {
    const queries = [makeQuery('a')]
    const dcqlQuery = {
      credentials: queries,
      credential_sets: [{ options: [['a']] }],
    }

    const matcher = makeMatcher({ a: [makeCredential('c1')] })
    const transactionData = [makeTransactionData('custom_type', ['a'], { data: 'test' })]

    const config = makeConfig({
      checkNonScaTransactionDataSupport: () => true,
    })
    const result = resolveDcql(dcqlQuery, transactionData, matcher, config)
    assert.strictEqual(isOk(result), true)
    if (isOk(result)) {
      const sets = result.value.credentialSets
      assert.strictEqual(sets.length, 1)
      const cred = sets[0].slots[0].alternatives[0].credentials[0]
      assert.ok(cred.transactionData, 'should have transactionData')
      assert.strictEqual(cred.transactionData.resolved, undefined, 'non-SCA should not have resolved display')
      assert.strictEqual(cred.transactionData.entry.type, 'custom_type')
    }
  })

  it('absent credential_sets requests all credentials (OID4VP §6.4.2)', () => {
    const result = resolveDcql(
      { credentials: [makeQuery('a')] },
      [],
      makeMatcher({ a: [makeCredential('c1')] }),
      makeConfig()
    )
    assert.strictEqual(isOk(result), true)
    if (isOk(result)) {
      assert.strictEqual(result.value.credentialSets.length, 1)
      assert.strictEqual(result.value.locale, 'en')
    }
  })

  it('result includes selected locale', () => {
    const result = resolveDcql(
      { credentials: [makeQuery('a')], credential_sets: [{ options: [['a']] }] },
      [],
      makeMatcher({ a: [makeCredential('c1')] }),
      makeConfig({ locales: ['fr', 'en'] })
    )
    assert.strictEqual(isOk(result), true)
    if (isOk(result)) {
      assert.strictEqual(typeof result.value.locale, 'string')
    }
  })

  it('resolved credential carries credentialQueryId', () => {
    const queries = [makeQuery('my_query')]
    const dcqlQuery = {
      credentials: queries,
      credential_sets: [{ options: [['my_query']] }],
    }
    const matcher = makeMatcher({ my_query: [makeCredential('c1')] })
    const result = resolveDcql(dcqlQuery, [], matcher, makeConfig())
    assert.strictEqual(isOk(result), true)
    if (isOk(result)) {
      const cred = result.value.credentialSets[0].slots[0].alternatives[0].credentials[0]
      assert.strictEqual(cred.credentialQueryId, 'my_query')
      assert.strictEqual(cred.credentialId, 'c1')
    }
  })
})

// =============================================================================
// isTargetedByTransactionData
// =============================================================================

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

// =============================================================================
// buildCredentialQueryMap
// =============================================================================

describe('buildCredentialQueryMap', () => {
  it('builds a lookup map from credential query ID to query', () => {
    const queries = [makeQuery('a'), makeQuery('b')]
    const map = buildCredentialQueryMap(queries)
    assert.ok(map)
    assert.strictEqual(map.size, 2)
    assert.strictEqual(map.get('a')?.id, 'a')
    assert.strictEqual(map.get('b')?.id, 'b')
    assert.strictEqual(map.get('c'), undefined)
  })

  it('returns undefined for duplicate ids (OID4VP §6.1)', () => {
    const map = buildCredentialQueryMap([makeQuery('a'), makeQuery('a')])
    assert.strictEqual(map, undefined)
  })
})

// =============================================================================
// OID4VP Section 6.4.2 — credential_sets absent means "request all credentials"
// =============================================================================
// "If credential_sets is not provided, the Verifier requests presentations for
//  all Credentials in credentials to be returned."

describe('OID4VP §6.4.2 — credential_sets absent requests all credentials', () => {
  it('absent credential_sets resolves each credential query as a required slot', () => {
    const dcqlQuery = { credentials: [makeQuery('a'), makeQuery('b')] }
    const matcher = makeMatcher({ a: [makeCredential('c1')], b: [makeCredential('c2')] })
    const result = resolveDcql(dcqlQuery, [], matcher, makeConfig())
    assert.ok(isOk(result))
    // Per OID4VP §6.4.2: all credentials should be requested
    assert.strictEqual(result.value.credentialSets.length, 2)
    assert.ok(result.value.credentialSets.every((cs) => cs.required === true))
  })
})

// =============================================================================
// OID4VP Section 6.1 — Duplicate credential query id
// =============================================================================
// "Within the Authorization Request, the same id MUST NOT be present more than once."

// =============================================================================
// OID4VP Section 6.1, 6.4.1 — validateDcqlQueryStructure
// =============================================================================

describe('OID4VP §6.1, §6.4.1 — validateDcqlQueryStructure', () => {
  it('returns error for duplicate credential query ids (§6.1)', () => {
    const error = validateDcqlQueryStructure({ credentials: [makeQuery('a'), makeQuery('a')] })
    assert.ok(error)
    assert.ok(error.includes('Duplicate'))
  })

  it('returns error for claim_sets without claims (§6.4.1)', () => {
    const query: DcqlCredentialQuery = {
      id: 'a',
      format: 'dc+sd-jwt',
      meta: { vct_values: ['x'] },
      claim_sets: [['c1']],
    }
    const error = validateDcqlQueryStructure({ credentials: [query] })
    assert.ok(error)
    assert.ok(error.includes('claim_sets'))
  })

  it('returns undefined for valid query', () => {
    assert.strictEqual(validateDcqlQueryStructure({ credentials: [makeQuery('a'), makeQuery('b')] }), undefined)
  })

  it('resolveDcql returns Err for duplicate ids', () => {
    const result = resolveDcql({ credentials: [makeQuery('a'), makeQuery('a')] }, [], makeMatcher({}), makeConfig())
    assert.ok(isErr(result))
  })

  it('resolveDcql returns Err for claim_sets without claims', () => {
    const query: DcqlCredentialQuery = {
      id: 'a',
      format: 'dc+sd-jwt',
      meta: { vct_values: ['x'] },
      claim_sets: [['c1']],
    }
    const result = resolveDcql({ credentials: [query] }, [], makeMatcher({}), makeConfig())
    assert.ok(isErr(result))
  })
})
