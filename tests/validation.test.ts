import assert from 'node:assert'
import { describe, it } from 'node:test'
import {
  createScaTypeMatcher,
  defaultScaTypeMatcher,
  isScaAttestationMetadata,
  zBaseTransaction,
  zClaimMetadata,
  zCredentialMetadata,
  zScaCredentialMetadata,
  zScaTransactionDataEntry,
  zTransactionDataEntry,
  zTransactionDataType,
  zUiLabels,
} from '@animo-id/eudi-wallet-ts12-validation'

// ---------------------------------------------------------------------------
// Shared fixtures
// ---------------------------------------------------------------------------

/** Spec example URN: urn:eudi:sca:eu.europa.ec:payment:single:1 (Section 2.3). */
const SCA_PAYMENT_TYPE = 'urn:eudi:sca:eu.europa.ec:payment:single:1'

/** Minimal internal claim (path only, no display). */
const internalClaim = { path: ['amount'] }

/** Displayable claim with display array and value_type. */
const displayableClaim = {
  path: ['beneficiary_name'],
  display: [{ name: 'Beneficiary', locale: 'en' }],
  value_type: 'string',
}

/** Minimal valid UI labels (only the REQUIRED affirmative_action_label). */
const minimalUiLabels = {
  affirmative_action_label: [{ value: 'Confirm', locale: 'en' }],
}

/** Full UI labels with all known optional elements. */
const fullUiLabels = {
  affirmative_action_label: [{ value: 'Approve', locale: 'en' }],
  denial_action_label: [{ value: 'Cancel', locale: 'en' }],
  transaction_title: [{ value: 'Payment', locale: 'en' }],
  security_hint: [{ value: 'Check details', locale: 'en' }],
}

/** A valid transaction_data_types entry (claims + ui_labels). */
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
  signatureQualifier: 'eu_eidas_qes' as const,
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
// "The Wallet Unit determines whether an Attestation is an SCA Attestation
//  by checking the transaction_data_types keys against known SCA URN prefixes."
// ===========================================================================

describe('Section 3.1 -- SCA Attestation Identification', () => {
  // -------------------------------------------------------------------------
  // defaultScaTypeMatcher
  // "Default matcher recognises the urn:eudi:sca: prefix per TS12."
  // -------------------------------------------------------------------------
  describe('defaultScaTypeMatcher', () => {
    it('matches a valid urn:eudi:sca: prefixed URN', () => {
      assert.strictEqual(defaultScaTypeMatcher(SCA_PAYMENT_TYPE), true)
    })

    it('rejects a non-SCA type string', () => {
      assert.strictEqual(defaultScaTypeMatcher('funke_qes'), false)
    })

    it('rejects the prefix itself without trailing colon', () => {
      assert.strictEqual(defaultScaTypeMatcher('urn:eudi:sca'), false)
    })

    it('rejects an empty string', () => {
      assert.strictEqual(defaultScaTypeMatcher(''), false)
    })

    it('is case-sensitive (URN scheme is lowercase per spec)', () => {
      assert.strictEqual(defaultScaTypeMatcher('URN:EUDI:SCA:something'), false)
      assert.strictEqual(defaultScaTypeMatcher('Urn:Eudi:Sca:something'), false)
    })
  })

  // -------------------------------------------------------------------------
  // createScaTypeMatcher
  // "Create an SCA type matcher that matches one or more URN prefixes."
  // -------------------------------------------------------------------------
  describe('createScaTypeMatcher', () => {
    it('matches a single custom prefix', () => {
      const matcher = createScaTypeMatcher('urn:custom:sca:')
      assert.strictEqual(matcher('urn:custom:sca:com.example:payment:single:1'), true)
      assert.strictEqual(matcher('urn:eudi:sca:eu.europa.ec:payment:single:1'), false)
    })

    it('matches multiple prefixes', () => {
      const matcher = createScaTypeMatcher('urn:eudi:sca:', 'urn:paso:sca:')
      assert.strictEqual(matcher('urn:eudi:sca:eu.europa.ec:payment:single:1'), true)
      assert.strictEqual(matcher('urn:paso:sca:com.example:signing:1'), true)
      assert.strictEqual(matcher('other:type'), false)
    })
  })

  // -------------------------------------------------------------------------
  // isScaAttestationMetadata
  // "Checks whether credential metadata describes an SCA Attestation by
  //  verifying that transaction_data_types contains at least one key
  //  recognized by the given matcher."
  // -------------------------------------------------------------------------
  describe('isScaAttestationMetadata', () => {
    it('returns true when at least one key matches the default matcher', () => {
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

    it('returns false when no keys match the SCA prefix', () => {
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

    it('returns false when transaction_data_types is an empty object', () => {
      assert.strictEqual(isScaAttestationMetadata({ transaction_data_types: {} }), false)
    })
  })

  // -------------------------------------------------------------------------
  // isScaAttestationMetadata with custom matcher
  // -------------------------------------------------------------------------
  describe('isScaAttestationMetadata with custom matcher', () => {
    it('matches when keys use the custom prefix', () => {
      const matcher = createScaTypeMatcher('urn:paso:sca:')
      assert.strictEqual(
        isScaAttestationMetadata({ transaction_data_types: { 'urn:paso:sca:com.example:payment:1': {} } }, matcher),
        true
      )
    })

    it('does not match the default eudi prefix when only custom is configured', () => {
      const matcher = createScaTypeMatcher('urn:paso:sca:')
      assert.strictEqual(
        isScaAttestationMetadata({ transaction_data_types: { [SCA_PAYMENT_TYPE]: {} } }, matcher),
        false
      )
    })
  })
})

// ===========================================================================
// Section 3.5.2 -- Claim Metadata
// "Claims that are relevant to the User's consent MUST include a display
//  array. Claims without a display array MUST be internal values."
// ===========================================================================

describe('Section 3.5.2 -- Claim Metadata', () => {
  // -------------------------------------------------------------------------
  // Displayable vs internal claims
  // -------------------------------------------------------------------------
  describe('zClaimMetadata -- displayable claims', () => {
    it('accepts a displayable claim with display and optional value_type', () => {
      const result = zClaimMetadata.parse(displayableClaim)
      assert.deepStrictEqual(result.path, ['beneficiary_name'])
      assert.ok('display' in result && Array.isArray(result.display))
      assert.ok('value_type' in result && result.value_type === 'string')
    })

    it('accepts a displayable claim with display but without value_type', () => {
      const result = zClaimMetadata.parse({
        path: ['beneficiary_name'],
        display: [{ name: 'Beneficiary' }],
      })
      assert.ok('display' in result && result.display.length === 1)
    })
  })

  describe('zClaimMetadata -- internal claims', () => {
    it('accepts an internal claim (no display, no value_type)', () => {
      const result = zClaimMetadata.parse({ path: ['nonce'] })
      assert.deepStrictEqual(result.path, ['nonce'])
    })

    it('accepts an internal claim with mandatory boolean', () => {
      const result = zClaimMetadata.parse({ path: ['nonce'], mandatory: true })
      assert.deepStrictEqual(result.path, ['nonce'])
      assert.strictEqual(result.mandatory, true)
    })
  })

  // -------------------------------------------------------------------------
  // value_type MUST NOT appear without display
  // "The value_type parameter MUST NOT be used on claims without a display array."
  // -------------------------------------------------------------------------
  describe('zClaimMetadata -- value_type without display is rejected', () => {
    it('rejects value_type on an internal claim (no display)', () => {
      assert.throws(
        () => zClaimMetadata.parse({ path: ['nonce'], value_type: 'string' }),
        (e: unknown) => e instanceof Error && e.constructor.name === 'ZodError'
      )
    })
  })

  // -------------------------------------------------------------------------
  // Claims Path Pointer components
  // "[OID4VCI] Appendix B: a claims path pointer MUST be a non-empty array
  //  of strings, nulls and integers."
  // -------------------------------------------------------------------------
  describe('zClaimMetadata -- claim path components', () => {
    it('accepts a path with string components', () => {
      const result = zClaimMetadata.parse({ path: ['a', 'b', 'c'] })
      assert.deepStrictEqual(result.path, ['a', 'b', 'c'])
    })

    it('accepts a path with null component (wildcard)', () => {
      const result = zClaimMetadata.parse({ path: ['items', null, 'name'] })
      assert.deepStrictEqual(result.path, ['items', null, 'name'])
    })

    it('accepts a path with integer component (array index)', () => {
      const result = zClaimMetadata.parse({ path: ['items', 0, 'name'] })
      assert.deepStrictEqual(result.path, ['items', 0, 'name'])
    })

    it('accepts a path mixing string, null, and integer components', () => {
      const result = zClaimMetadata.parse({ path: ['data', null, 2, 'value'] })
      assert.deepStrictEqual(result.path, ['data', null, 2, 'value'])
    })

    it('rejects a non-integer number in path', () => {
      assert.throws(
        () => zClaimMetadata.parse({ path: ['items', 1.5] }),
        (e: unknown) => e instanceof Error && e.constructor.name === 'ZodError'
      )
    })
  })

  // -------------------------------------------------------------------------
  // mandatory is optional boolean
  // -------------------------------------------------------------------------
  describe('zClaimMetadata -- mandatory field', () => {
    it('mandatory defaults to undefined when omitted', () => {
      const result = zClaimMetadata.parse({ path: ['field'] })
      assert.strictEqual(result.mandatory, undefined)
    })

    it('accepts mandatory: false', () => {
      const result = zClaimMetadata.parse({ path: ['field'], mandatory: false })
      assert.strictEqual(result.mandatory, false)
    })
  })

  // -------------------------------------------------------------------------
  // Display entry structure
  // "name REQUIRED, locale OPTIONAL, display_type OPTIONAL."
  // -------------------------------------------------------------------------
  describe('zClaimMetadata -- display entry structure', () => {
    it('display entry requires name', () => {
      assert.throws(() =>
        zClaimMetadata.parse({
          path: ['x'],
          display: [{ locale: 'en' }],
        })
      )
    })

    it('display entry accepts name only (locale and display_type optional)', () => {
      const result = zClaimMetadata.parse({
        path: ['x'],
        display: [{ name: 'Label' }],
      })
      assert.ok('display' in result && result.display[0].name === 'Label')
    })

    it('display entry accepts name with locale', () => {
      const result = zClaimMetadata.parse({
        path: ['x'],
        display: [{ name: 'Label', locale: 'en' }],
      })
      assert.ok('display' in result && result.display[0].locale === 'en')
    })

    it('display entry accepts name with display_type', () => {
      const result = zClaimMetadata.parse({
        path: ['x'],
        display: [{ name: 'Amount', display_type: 'currency' }],
      })
      assert.ok('display' in result && result.display[0].display_type === 'currency')
    })
  })
})

// ===========================================================================
// Section 3.5.3 -- UI Labels
// "affirmative_action_label: REQUIRED. denial_action_label, transaction_title,
//  security_hint: OPTIONAL. Additional UI element identifiers MAY be defined."
// ===========================================================================

describe('Section 3.5.3 -- UI Labels', () => {
  // -------------------------------------------------------------------------
  // Required / optional fields
  // -------------------------------------------------------------------------
  describe('zUiLabels -- required and optional fields', () => {
    it('affirmative_action_label is REQUIRED', () => {
      assert.throws(() => zUiLabels.parse({}))
    })

    it('accepts with only the required affirmative_action_label', () => {
      const result = zUiLabels.parse(minimalUiLabels)
      assert.ok(result.affirmative_action_label)
      assert.strictEqual(result.denial_action_label, undefined)
      assert.strictEqual(result.transaction_title, undefined)
      assert.strictEqual(result.security_hint, undefined)
    })

    it('denial_action_label is OPTIONAL', () => {
      const result = zUiLabels.parse({
        ...minimalUiLabels,
        denial_action_label: [{ value: 'Cancel' }],
      })
      assert.ok(result.denial_action_label)
    })

    it('transaction_title is OPTIONAL', () => {
      const result = zUiLabels.parse({
        ...minimalUiLabels,
        transaction_title: [{ value: 'Payment Authorization' }],
      })
      assert.ok(result.transaction_title)
    })

    it('security_hint is OPTIONAL', () => {
      const result = zUiLabels.parse({
        ...minimalUiLabels,
        security_hint: [{ value: 'Verify details carefully' }],
      })
      assert.ok(result.security_hint)
    })

    it('accepts all known optional fields together', () => {
      const result = zUiLabels.parse(fullUiLabels)
      assert.ok(result.affirmative_action_label)
      assert.ok(result.denial_action_label)
      assert.ok(result.transaction_title)
      assert.ok(result.security_hint)
    })
  })

  // -------------------------------------------------------------------------
  // Catchall for additional UI element identifiers
  // "Additional UI element identifiers MAY be defined."
  // -------------------------------------------------------------------------
  describe('zUiLabels -- additional UI element identifiers (catchall)', () => {
    it('allows additional UI element identifiers', () => {
      const input = {
        ...minimalUiLabels,
        custom_warning: [{ value: 'Be careful', locale: 'en' }],
        progress_label: [{ value: 'Processing...' }],
      }
      const result = zUiLabels.parse(input)
      assert.ok(result.custom_warning)
      assert.ok(result.progress_label)
    })
  })

  // -------------------------------------------------------------------------
  // UI label entry structure
  // "value REQUIRED, locale OPTIONAL, value_type OPTIONAL."
  // -------------------------------------------------------------------------
  describe('zUiLabels -- label entry structure', () => {
    it('label entry requires value', () => {
      assert.throws(() =>
        zUiLabels.parse({
          affirmative_action_label: [{ locale: 'en' }],
        })
      )
    })

    it('label entry accepts value only (locale and value_type optional)', () => {
      const result = zUiLabels.parse({
        affirmative_action_label: [{ value: 'OK' }],
      })
      assert.strictEqual(result.affirmative_action_label[0].value, 'OK')
      assert.strictEqual(result.affirmative_action_label[0].locale, undefined)
      assert.strictEqual(result.affirmative_action_label[0].value_type, undefined)
    })

    it('label entry accepts locale', () => {
      const result = zUiLabels.parse({
        affirmative_action_label: [{ value: 'OK', locale: 'en' }],
      })
      assert.strictEqual(result.affirmative_action_label[0].locale, 'en')
    })

    it('label entry accepts value_type', () => {
      const result = zUiLabels.parse({
        affirmative_action_label: [{ value: 'Pay {0} EUR', value_type: 'template' }],
      })
      assert.strictEqual(result.affirmative_action_label[0].value_type, 'template')
    })
  })
})

// ===========================================================================
// Section 4.1 -- Transaction Data Types
// "Each entry describes the claims and UI labels for one transaction data
//  type. Additional parameters MAY be defined."
// ===========================================================================

describe('Section 4.1 -- Transaction Data Types', () => {
  // -------------------------------------------------------------------------
  // zTransactionDataType
  // -------------------------------------------------------------------------
  describe('zTransactionDataType', () => {
    it('claims REQUIRED and ui_labels REQUIRED', () => {
      const result = zTransactionDataType.parse(validTransactionDataType)
      assert.ok(Array.isArray(result.claims))
      assert.ok(result.ui_labels)
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

    it('additional parameters allowed (.loose())', () => {
      const input = {
        ...validTransactionDataType,
        some_extension: 'custom_value',
        version: 2,
      }
      const result = zTransactionDataType.parse(input)
      assert.ok(result)
    })
  })

  // -------------------------------------------------------------------------
  // Credential Metadata
  // -------------------------------------------------------------------------
  describe('zCredentialMetadata', () => {
    it('transaction_data_types is optional', () => {
      const result = zCredentialMetadata.parse({})
      assert.strictEqual(result.transaction_data_types, undefined)
    })

    it('accepts transaction_data_types when present', () => {
      const result = zCredentialMetadata.parse(fullScaCredentialMetadata)
      assert.ok(result.transaction_data_types)
    })

    it('allows extra fields (.loose())', () => {
      const result = zCredentialMetadata.parse({
        format: 'vc+sd-jwt',
        vct: 'urn:example:type',
      })
      assert.ok(result)
    })
  })

  describe('zScaCredentialMetadata', () => {
    it('requires transaction_data_types', () => {
      assert.throws(() => zScaCredentialMetadata.parse({}))
    })

    it('accepts full spec example', () => {
      const result = zScaCredentialMetadata.parse(fullScaCredentialMetadata)
      assert.ok(result.transaction_data_types)
      assert.ok(result.transaction_data_types[SCA_PAYMENT_TYPE])
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

  // -------------------------------------------------------------------------
  // Credential display entry
  // "[OID4VCI] Section 12.2.4: name required, locale/description/logo/colors optional."
  // -------------------------------------------------------------------------
  describe('Credential display entry', () => {
    it('name is required', () => {
      assert.throws(() =>
        zCredentialMetadata.parse({
          display: [{ locale: 'en' }],
        })
      )
    })

    it('accepts name only', () => {
      const result = zCredentialMetadata.parse({
        display: [{ name: 'My Credential' }],
      })
      assert.ok(result.display)
      assert.strictEqual(result.display?.[0].name, 'My Credential')
    })

    it('accepts all optional fields: locale, description, logo, colors', () => {
      const result = zCredentialMetadata.parse({
        display: [
          {
            name: 'Payment SCA',
            locale: 'en',
            description: 'SCA attestation for payments',
            logo: { uri: 'https://example.com/logo.png', alt_text: 'Logo' },
            background_color: '#FFFFFF',
            text_color: '#000000',
          },
        ],
      })
      assert.ok(result.display)
      const entry = result.display?.[0]
      assert.strictEqual(entry.name, 'Payment SCA')
      assert.strictEqual(entry.locale, 'en')
      assert.strictEqual(entry.description, 'SCA attestation for payments')
      assert.ok(entry.logo)
      assert.strictEqual(entry.logo?.uri, 'https://example.com/logo.png')
      assert.strictEqual(entry.background_color, '#FFFFFF')
      assert.strictEqual(entry.text_color, '#000000')
    })
  })
})

// ===========================================================================
// Section 4.2 -- Transaction Data Entry
// "The type field is a plain string. credential_ids is REQUIRED non-empty.
//  payload is REQUIRED (generic JSON object)."
// ===========================================================================

describe('Section 4.2 -- Transaction Data Entry', () => {
  // -------------------------------------------------------------------------
  // zScaTransactionDataEntry
  // -------------------------------------------------------------------------
  describe('zScaTransactionDataEntry', () => {
    it('type REQUIRED, credential_ids REQUIRED non-empty, payload REQUIRED object', () => {
      const result = zScaTransactionDataEntry.parse(validScaTransactionDataEntry)
      assert.strictEqual(result.type, SCA_PAYMENT_TYPE)
      assert.ok(result.credential_ids.length > 0)
      assert.ok(result.payload)
    })

    it('rejects missing payload', () => {
      assert.throws(() =>
        zScaTransactionDataEntry.parse({
          type: SCA_PAYMENT_TYPE,
          credential_ids: ['cred1'],
        })
      )
    })

    it('rejects missing type', () => {
      assert.throws(() =>
        zScaTransactionDataEntry.parse({
          credential_ids: ['cred1'],
          payload: { amount: '10' },
        })
      )
    })

    it('rejects missing credential_ids', () => {
      assert.throws(() =>
        zScaTransactionDataEntry.parse({
          type: SCA_PAYMENT_TYPE,
          payload: { amount: '10' },
        })
      )
    })

    it('payload accepts arbitrary nested JSON', () => {
      const result = zScaTransactionDataEntry.parse({
        type: SCA_PAYMENT_TYPE,
        credential_ids: ['cred1'],
        payload: {
          amount: '100.00',
          currency: 'EUR',
          beneficiary: {
            name: 'Alice',
            iban: 'DE89370400440532013000',
          },
          tags: ['urgent', 'domestic'],
          metadata: null,
        },
      })
      assert.strictEqual((result.payload as Record<string, unknown>).amount, '100.00')
      assert.ok((result.payload as Record<string, unknown>).beneficiary)
    })

    it('transaction_data_hashes_alg is optional', () => {
      const result = zScaTransactionDataEntry.parse(validScaTransactionDataEntry)
      assert.strictEqual(result.transaction_data_hashes_alg, undefined)
    })

    it('transaction_data_hashes_alg accepted when present and non-empty', () => {
      const result = zScaTransactionDataEntry.parse({
        ...validScaTransactionDataEntry,
        transaction_data_hashes_alg: ['sha-256'],
      })
      assert.deepStrictEqual(result.transaction_data_hashes_alg, ['sha-256'])
    })

    it('transaction_data_hashes_alg rejects empty array', () => {
      assert.throws(() =>
        zScaTransactionDataEntry.parse({
          ...validScaTransactionDataEntry,
          transaction_data_hashes_alg: [],
        })
      )
    })
  })

  // -------------------------------------------------------------------------
  // zBaseTransaction
  // "type and credential_ids required, empty credential_ids rejected."
  // -------------------------------------------------------------------------
  describe('zBaseTransaction', () => {
    it('type and credential_ids required', () => {
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

    it('rejects missing type', () => {
      assert.throws(() =>
        zBaseTransaction.parse({
          credential_ids: ['cred1'],
        })
      )
    })

    it('rejects missing credential_ids', () => {
      assert.throws(() =>
        zBaseTransaction.parse({
          type: 'some_type',
        })
      )
    })
  })

  // -------------------------------------------------------------------------
  // zTransactionDataEntry union
  // "Accepts SCA entries and Funke QES entries."
  // -------------------------------------------------------------------------
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

    it('rejects an entry that matches neither variant', () => {
      assert.throws(() =>
        zTransactionDataEntry.parse({
          type: 'unknown_type',
          credential_ids: ['cred1'],
          // no payload (SCA fails) and no signatureQualifier/documentDigests (Funke fails)
        })
      )
    })
  })
})

// ===========================================================================
// Section 2.3 -- End-to-end spec example
// "Full credential metadata and transaction data entry from the spec example
//  parse through all schemas."
// ===========================================================================

describe('Section 2.3 -- End-to-end spec example', () => {
  /** Comprehensive credential metadata modelled after the Section 2.3 example. */
  const specCredentialMetadata = {
    display: [
      {
        name: 'Payment SCA Attestation',
        locale: 'en',
        description: 'Attestation for payment transaction signing',
        logo: { uri: 'https://example.com/logo.png', alt_text: 'Bank Logo' },
        background_color: '#003366',
        text_color: '#FFFFFF',
      },
    ],
    transaction_data_types: {
      [SCA_PAYMENT_TYPE]: {
        claims: [
          { path: ['amount'], mandatory: true, display: [{ name: 'Amount', locale: 'en' }], value_type: 'currency' },
          { path: ['currency'], mandatory: true, display: [{ name: 'Currency', locale: 'en' }] },
          {
            path: ['beneficiary_name'],
            display: [{ name: 'Beneficiary', locale: 'en' }],
            value_type: 'string',
          },
          { path: ['beneficiary_iban'], display: [{ name: 'IBAN', locale: 'en' }] },
          { path: ['nonce'] },
        ],
        ui_labels: {
          affirmative_action_label: [
            { value: 'Approve payment of {0} {1} to {2}', locale: 'en' },
            { value: 'Zahlung von {0} {1} an {2} genehmigen', locale: 'de' },
          ],
          denial_action_label: [
            { value: 'Cancel', locale: 'en' },
            { value: 'Abbrechen', locale: 'de' },
          ],
          transaction_title: [
            { value: 'Payment Authorization', locale: 'en' },
            { value: 'Zahlungsfreigabe', locale: 'de' },
          ],
          security_hint: [{ value: 'Verify all details before confirming', locale: 'en' }],
        },
      },
    },
  }

  /** Corresponding transaction data entry for the above metadata type. */
  const specTransactionDataEntry = {
    type: SCA_PAYMENT_TYPE,
    credential_ids: ['payment_sca_01'],
    transaction_data_hashes_alg: ['sha-256'],
    payload: {
      amount: '250.00',
      currency: 'EUR',
      beneficiary_name: 'Alice Wonderland',
      beneficiary_iban: 'DE89370400440532013000',
      nonce: 'abc123-random-nonce',
    },
  }

  it('credential metadata parses through zCredentialMetadata', () => {
    const result = zCredentialMetadata.parse(specCredentialMetadata)
    assert.ok(result.display)
    assert.strictEqual(result.display?.[0].name, 'Payment SCA Attestation')
    assert.ok(result.transaction_data_types)
    assert.ok(result.transaction_data_types?.[SCA_PAYMENT_TYPE])
  })

  it('credential metadata parses through zScaCredentialMetadata', () => {
    const result = zScaCredentialMetadata.parse(specCredentialMetadata)
    assert.ok(result.transaction_data_types[SCA_PAYMENT_TYPE])
  })

  it('isScaAttestationMetadata identifies it as SCA', () => {
    assert.strictEqual(isScaAttestationMetadata(specCredentialMetadata), true)
  })

  it('transaction data type entry parses through zTransactionDataType', () => {
    const typeEntry = specCredentialMetadata.transaction_data_types[SCA_PAYMENT_TYPE]
    const result = zTransactionDataType.parse(typeEntry)
    assert.strictEqual(result.claims.length, 5)
    assert.ok(result.ui_labels.affirmative_action_label)
  })

  it('transaction data entry parses through zScaTransactionDataEntry', () => {
    const result = zScaTransactionDataEntry.parse(specTransactionDataEntry)
    assert.strictEqual(result.type, SCA_PAYMENT_TYPE)
    assert.strictEqual(result.credential_ids[0], 'payment_sca_01')
    assert.deepStrictEqual(result.transaction_data_hashes_alg, ['sha-256'])
    assert.strictEqual((result.payload as Record<string, unknown>).amount, '250.00')
  })

  it('transaction data entry parses through the zTransactionDataEntry union', () => {
    const result = zTransactionDataEntry.parse(specTransactionDataEntry)
    assert.strictEqual(result.type, SCA_PAYMENT_TYPE)
  })
})
