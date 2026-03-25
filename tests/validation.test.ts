import assert from 'node:assert'
import { describe, it } from 'node:test'
import {
  isScaAttestationMetadata,
  isScaTransactionType,
  zBaseTransaction,
  zClaimMetadata,
  zScaCredentialMetadata,
  zScaTransactionDataEntry,
  zScaTransactionType,
  zTransactionDataEntry,
  zTransactionDataType,
  zUiLabels,
} from '@animo-id/eudi-wallet-ts12-validation'

// ---------------------------------------------------------------------------
// Section 2.3 JSON fixtures (spec examples)
// ---------------------------------------------------------------------------

/** Minimal valid SCA transaction type URN (Section 2.3 example). */
const SCA_PAYMENT_TYPE = 'urn:eudi:sca:eu.europa.ec:payment:single:1'

/** Minimal valid claim metadata for an internal claim. */
const internalClaim = { path: ['amount'] }

/** Minimal valid claim metadata for a displayable claim. */
const displayableClaim = {
  path: ['beneficiary_name'],
  display: [{ name: 'Beneficiary', locale: 'en' }],
  value_type: 'string',
}

/** Minimal valid UI labels object. */
const minimalUiLabels = {
  affirmative_action_label: [{ value: 'Confirm', locale: 'en' }],
}

/** Full UI labels with all optional elements. */
const fullUiLabels = {
  affirmative_action_label: [{ value: 'Approve', locale: 'en' }],
  denial_action_label: [{ value: 'Cancel', locale: 'en' }],
  transaction_title: [{ value: 'Payment', locale: 'en' }],
  security_hint: [{ value: 'Check details', locale: 'en' }],
}

/** A valid transaction_data_types entry. */
const validTransactionDataType = {
  claims: [internalClaim, displayableClaim],
  ui_labels: minimalUiLabels,
}

/** Full SCA credential metadata (Section 2.3 style). */
const fullScaCredentialMetadata = {
  transaction_data_types: {
    [SCA_PAYMENT_TYPE]: validTransactionDataType,
  },
}

/** Valid SCA transaction data entry (Section 4.2). */
const validScaTransactionDataEntry = {
  type: SCA_PAYMENT_TYPE,
  credential_ids: ['payment_credential'],
  payload: {
    amount: '100.00',
    beneficiary_name: 'Alice',
  },
}

/** Valid Funke QES transaction data entry. */
const validFunkeQesEntry = {
  type: 'funke_qes',
  credential_ids: ['qes_credential'],
  signatureQualifier: 'eu_eidas_qes',
  documentDigests: [
    {
      label: 'Contract.pdf',
      hash: 'abc123==',
      hashAlgorithmOID: '2.16.840.1.101.3.4.2.1',
    },
  ],
}

// ===========================================================================
// Section 3.1 -- SCA Attestation Identification
// ===========================================================================

describe('Section 3.1 -- SCA Attestation Identification', () => {
  describe('isScaTransactionType', () => {
    it('returns true for a valid SCA transaction type URN', () => {
      assert.strictEqual(isScaTransactionType(SCA_PAYMENT_TYPE), true)
    })

    it('returns false for a non-SCA type', () => {
      assert.strictEqual(isScaTransactionType('funke_qes'), false)
    })

    it('returns false for a partial prefix (missing trailing colon)', () => {
      assert.strictEqual(isScaTransactionType('urn:eudi:sca'), false)
    })

    it('returns false for an empty string', () => {
      assert.strictEqual(isScaTransactionType(''), false)
    })

    it('is case-sensitive', () => {
      assert.strictEqual(isScaTransactionType('URN:EUDI:SCA:something'), false)
      assert.strictEqual(isScaTransactionType('Urn:Eudi:Sca:something'), false)
    })
  })

  describe('isScaAttestationMetadata', () => {
    it('returns true when object has at least one SCA key', () => {
      assert.strictEqual(
        isScaAttestationMetadata({
          transaction_data_types: { [SCA_PAYMENT_TYPE]: {} },
        }),
        true
      )
    })

    it('returns true when keys are mixed (SCA and non-SCA)', () => {
      assert.strictEqual(
        isScaAttestationMetadata({
          transaction_data_types: {
            [SCA_PAYMENT_TYPE]: {},
            funke_qes: {},
          },
        }),
        true
      )
    })

    it('returns false when no keys are SCA-prefixed', () => {
      assert.strictEqual(
        isScaAttestationMetadata({
          transaction_data_types: { funke_qes: {} },
        }),
        false
      )
    })

    it('returns false when transaction_data_types is missing', () => {
      assert.strictEqual(isScaAttestationMetadata({}), false)
    })

    it('returns false when transaction_data_types is empty', () => {
      assert.strictEqual(isScaAttestationMetadata({ transaction_data_types: {} }), false)
    })
  })

  describe('zScaTransactionType', () => {
    it('accepts a valid SCA URN', () => {
      const result = zScaTransactionType.parse(SCA_PAYMENT_TYPE)
      assert.strictEqual(result, SCA_PAYMENT_TYPE)
    })

    it('rejects a non-SCA string', () => {
      assert.throws(() => zScaTransactionType.parse('funke_qes'))
    })
  })
})

// ===========================================================================
// Section 4.1 -- SCA Attestation Credential Metadata
// ===========================================================================

describe('Section 4.1 -- SCA Attestation Credential Metadata', () => {
  describe('zTransactionDataType', () => {
    it('requires claims and ui_labels', () => {
      const result = zTransactionDataType.parse(validTransactionDataType)
      assert.ok(Array.isArray(result.claims))
      assert.ok(result.ui_labels)
    })

    it('ignores extra params (.loose())', () => {
      const input = {
        ...validTransactionDataType,
        some_extension: 'custom_value',
      }
      const result = zTransactionDataType.parse(input)
      assert.ok(result)
    })

    it('rejects missing claims', () => {
      assert.throws(() =>
        zTransactionDataType.parse({
          ui_labels: minimalUiLabels,
        })
      )
    })

    it('rejects missing ui_labels', () => {
      assert.throws(() =>
        zTransactionDataType.parse({
          claims: [internalClaim],
        })
      )
    })
  })

  describe('zScaCredentialMetadata', () => {
    it('accepts full spec example', () => {
      const result = zScaCredentialMetadata.parse(fullScaCredentialMetadata)
      assert.ok(result.transaction_data_types)
      assert.ok(result.transaction_data_types[SCA_PAYMENT_TYPE])
    })

    it('rejects missing transaction_data_types', () => {
      assert.throws(() => zScaCredentialMetadata.parse({}))
    })

    it('allows extra OID4VCI fields (.loose())', () => {
      const input = {
        ...fullScaCredentialMetadata,
        display: [{ name: 'SCA Attestation', locale: 'en' }],
        format: 'vc+sd-jwt',
      }
      const result = zScaCredentialMetadata.parse(input)
      assert.ok(result)
    })
  })

  describe('zUiLabels', () => {
    it('requires affirmative_action_label', () => {
      assert.throws(() => zUiLabels.parse({}))
    })

    it('accepts with only required affirmative_action_label', () => {
      const result = zUiLabels.parse(minimalUiLabels)
      assert.ok(result.affirmative_action_label)
    })

    it('accepts optional denial_action_label, transaction_title, security_hint', () => {
      const result = zUiLabels.parse(fullUiLabels)
      assert.ok(result.affirmative_action_label)
      assert.ok(result.denial_action_label)
      assert.ok(result.transaction_title)
      assert.ok(result.security_hint)
    })

    it('allows custom labels via catchall', () => {
      const input = {
        ...minimalUiLabels,
        custom_element: [{ value: 'Custom', locale: 'en' }],
      }
      const result = zUiLabels.parse(input)
      assert.ok(result.custom_element)
    })
  })
})

// ===========================================================================
// Section 3.5.2 -- Claim Metadata
// ===========================================================================

describe('Section 3.5.2 -- Claim Metadata', () => {
  describe('zClaimMetadata union', () => {
    it('accepts an internal claim (path only)', () => {
      const result = zClaimMetadata.parse({ path: ['nonce'] })
      assert.deepStrictEqual(result.path, ['nonce'])
    })

    it('accepts an internal claim with mandatory flag', () => {
      const result = zClaimMetadata.parse({ path: ['nonce'], mandatory: true })
      assert.deepStrictEqual(result.path, ['nonce'])
      assert.strictEqual(result.mandatory, true)
    })

    it('accepts a displayable claim (with display and value_type)', () => {
      const result = zClaimMetadata.parse(displayableClaim)
      assert.deepStrictEqual(result.path, ['beneficiary_name'])
      assert.ok('display' in result && Array.isArray(result.display))
      assert.ok('value_type' in result && result.value_type === 'string')
    })

    it('accepts a display entry with display_type', () => {
      const claim = {
        path: ['amount'],
        display: [{ name: 'Amount', locale: 'en', display_type: 'currency' }],
      }
      const result = zClaimMetadata.parse(claim)
      assert.ok('display' in result && result.display[0])
    })

    it('rejects value_type on internal claims (no display)', () => {
      // Per TS12 Section 3.5.2: "The value_type parameter MUST NOT be used
      // on claims without a display array."
      // The internal variant uses .strict() so value_type is rejected,
      // and the displayable variant fails because display is missing.
      assert.throws(
        () => zClaimMetadata.parse({ path: ['nonce'], value_type: 'string' }),
        (e: unknown) => e instanceof Error && e.constructor.name === 'ZodError'
      )
    })
  })
})

// ===========================================================================
// Section 4.2 -- Transactional Data Object
// ===========================================================================

describe('Section 4.2 -- Transactional Data Object', () => {
  describe('zBaseTransaction', () => {
    it('accepts a valid base transaction', () => {
      const result = zBaseTransaction.parse({
        type: 'some_type',
        credential_ids: ['cred1'],
      })
      assert.strictEqual(result.type, 'some_type')
      assert.deepStrictEqual(result.credential_ids, ['cred1'])
    })

    it('rejects empty credential_ids', () => {
      assert.throws(() =>
        zBaseTransaction.parse({
          type: 'some_type',
          credential_ids: [],
        })
      )
    })

    it('accepts multiple credential_ids', () => {
      const result = zBaseTransaction.parse({
        type: 'some_type',
        credential_ids: ['cred1', 'cred2', 'cred3'],
      })
      assert.strictEqual(result.credential_ids.length, 3)
    })
  })

  describe('zScaTransactionDataEntry', () => {
    it('accepts a valid SCA entry with payload', () => {
      const result = zScaTransactionDataEntry.parse(validScaTransactionDataEntry)
      assert.strictEqual(result.type, SCA_PAYMENT_TYPE)
      assert.ok(result.payload)
      assert.strictEqual(result.payload.amount, '100.00')
    })

    it('rejects without payload', () => {
      assert.throws(() =>
        zScaTransactionDataEntry.parse({
          type: SCA_PAYMENT_TYPE,
          credential_ids: ['cred1'],
        })
      )
    })

    it('rejects non-SCA type', () => {
      assert.throws(() =>
        zScaTransactionDataEntry.parse({
          type: 'funke_qes',
          credential_ids: ['cred1'],
          payload: { amount: '100.00' },
        })
      )
    })
  })

  describe('zTransactionDataEntry union', () => {
    it('accepts an SCA transaction data entry', () => {
      const result = zTransactionDataEntry.parse(validScaTransactionDataEntry)
      assert.strictEqual(result.type, SCA_PAYMENT_TYPE)
    })

    it('accepts a Funke QES transaction data entry', () => {
      const result = zTransactionDataEntry.parse(validFunkeQesEntry)
      assert.strictEqual(result.type, 'funke_qes')
      assert.ok('signatureQualifier' in result)
    })
  })
})
