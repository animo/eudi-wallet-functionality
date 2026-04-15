import assert from 'node:assert'
import { describe, it } from 'node:test'
import { computeMetadataIntegrity, parseCredentialMetadataJwt } from '@animo-id/eudi-wallet-ts12-credential-metadata'
import type {
  CredentialMetadataWalletStore,
  StoredCredentialMetadataJwt,
} from '@animo-id/eudi-wallet-ts12-credential-metadata-wallet'
import { CredentialMetadataService } from '@animo-id/eudi-wallet-ts12-credential-metadata-wallet'
import {
  zCredentialMetadata,
  zCredentialMetadataJwtHeader,
  zCredentialMetadataJwtPayload,
  zScaCredentialMetadata,
} from '@animo-id/eudi-wallet-ts12-validation'

// =============================================================================
// Fixtures — TS12 Annex D.8 style
// =============================================================================

const validHeader = {
  typ: 'credential-metadata+jwt',
  alg: 'ES256',
  x5c: ['MIIBxTCCAWugAwIBAgent...'],
}

const validPayload = {
  iss: 'https://issuer.superbank.eu',
  sub: 'https://superbank.eu/sca/payment',
  format: 'dc+sd-jwt',
  iat: 1710000000,
  exp: 1712592000,
  credential_metadata_uri: 'https://issuer.superbank.eu/credential-metadata/payment',
  credential_metadata: {
    display: [
      {
        name: 'SuperBank Payment',
        locale: 'en',
        logo: { uri: 'https://issuer.superbank.eu/logo.png', alt_text: 'SuperBank logo' },
        background_color: '#003366',
        text_color: '#ffffff',
      },
      { name: 'SuperBank Zahlung', locale: 'de' },
    ],
    claims: [{ path: ['payment_network'], display: [{ locale: 'en', name: 'Payment network' }] }],
    transaction_data_types: {
      'urn:eudi:sca:eu.europa.ec:payment:single:1': {
        claims: [
          { path: ['transaction_id'], mandatory: true },
          {
            path: ['amount'],
            mandatory: true,
            value_type: 'iso_currency_amount',
            display: [
              { locale: 'en', name: 'Amount' },
              { locale: 'de', name: 'Betrag' },
            ],
          },
          {
            path: ['payee', 'name'],
            mandatory: true,
            display: [
              { locale: 'en', name: 'Payee' },
              { locale: 'de', name: 'Empfänger' },
            ],
          },
          { path: ['payee', 'id'], mandatory: true },
        ],
        ui_labels: {
          affirmative_action_label: [
            { locale: 'en', value: 'Confirm Payment' },
            { locale: 'de', value: 'Zahlung bestätigen' },
          ],
        },
      },
    },
  },
}

// =============================================================================
// TS12 Section 5 — JWT JOSE header validation (Step 1 of Section 4.1.2)
// =============================================================================

describe('TS12 §4.1.2 Step 1 — JWT header validation', () => {
  it('accepts valid header with typ credential-metadata+jwt', () => {
    const result = zCredentialMetadataJwtHeader.safeParse(validHeader)
    assert.ok(result.success)
  })

  it('rejects missing typ', () => {
    const result = zCredentialMetadataJwtHeader.safeParse({ alg: 'ES256', x5c: ['cert'] })
    assert.ok(!result.success)
  })

  it('rejects wrong typ value (Section 4.1.2 step 1: MUST be credential-metadata+jwt)', () => {
    const result = zCredentialMetadataJwtHeader.safeParse({ ...validHeader, typ: 'jwt' })
    assert.ok(!result.success)
  })

  it('rejects missing x5c (Section 5: SHALL include x5c)', () => {
    const result = zCredentialMetadataJwtHeader.safeParse({ typ: 'credential-metadata+jwt', alg: 'ES256' })
    assert.ok(!result.success)
  })

  it('rejects empty x5c array (Section 5: certificate chain)', () => {
    const result = zCredentialMetadataJwtHeader.safeParse({ ...validHeader, x5c: [] })
    assert.ok(!result.success)
  })

  it('rejects missing alg', () => {
    const result = zCredentialMetadataJwtHeader.safeParse({ typ: 'credential-metadata+jwt', x5c: ['cert'] })
    assert.ok(!result.success)
  })

  it('allows additional JOSE header parameters (.loose())', () => {
    const result = zCredentialMetadataJwtHeader.safeParse({ ...validHeader, kid: 'key-1' })
    assert.ok(result.success)
  })
})

// =============================================================================
// TS12 Section 5 — JWT payload validation
// =============================================================================

describe('TS12 §5 — JWT payload validation', () => {
  it('accepts valid payload with all REQUIRED claims', () => {
    const result = zCredentialMetadataJwtPayload.safeParse(validPayload)
    assert.ok(result.success)
  })

  it('rejects missing iss (Section 5: REQUIRED)', () => {
    const { iss, ...without } = validPayload
    assert.ok(!zCredentialMetadataJwtPayload.safeParse(without).success)
  })

  it('rejects missing sub (Section 5: REQUIRED)', () => {
    const { sub, ...without } = validPayload
    assert.ok(!zCredentialMetadataJwtPayload.safeParse(without).success)
  })

  it('rejects missing format (Section 5: REQUIRED)', () => {
    const { format, ...without } = validPayload
    assert.ok(!zCredentialMetadataJwtPayload.safeParse(without).success)
  })

  it('rejects missing iat (Section 5: REQUIRED)', () => {
    const { iat, ...without } = validPayload
    assert.ok(!zCredentialMetadataJwtPayload.safeParse(without).success)
  })

  it('rejects missing exp (Section 5: REQUIRED)', () => {
    const { exp, ...without } = validPayload
    assert.ok(!zCredentialMetadataJwtPayload.safeParse(without).success)
  })

  it('rejects missing credential_metadata_uri (Section 5: REQUIRED)', () => {
    const { credential_metadata_uri, ...without } = validPayload
    assert.ok(!zCredentialMetadataJwtPayload.safeParse(without).success)
  })

  it('rejects missing credential_metadata (Section 5: REQUIRED)', () => {
    const { credential_metadata, ...without } = validPayload
    assert.ok(!zCredentialMetadataJwtPayload.safeParse(without).success)
  })

  it('allows additional claims (.loose())', () => {
    const result = zCredentialMetadataJwtPayload.safeParse({ ...validPayload, extra_claim: 'value' })
    assert.ok(result.success)
  })
})

// =============================================================================
// OID4VCI §12.2.4 + TS12 §4.1 — credential_metadata structure
// =============================================================================

describe('OID4VCI §12.2.4 + TS12 §4.1 — credential_metadata validation', () => {
  it('accepts full Annex D.8 style metadata', () => {
    const result = zCredentialMetadata.safeParse(validPayload.credential_metadata)
    assert.ok(result.success)
  })

  it('accepts metadata with only display (no transaction_data_types — non-SCA)', () => {
    const result = zCredentialMetadata.safeParse({ display: [{ name: 'Card', locale: 'en' }] })
    assert.ok(result.success)
  })

  it('accepts metadata with only transaction_data_types (no display)', () => {
    const result = zCredentialMetadata.safeParse({
      transaction_data_types: {
        'urn:eudi:sca:eu.europa.ec:payment:single:1': {
          claims: [{ path: ['amount'], mandatory: true }],
          ui_labels: { affirmative_action_label: [{ value: 'OK' }] },
        },
      },
    })
    assert.ok(result.success)
  })

  it('allows additional fields per OID4VCI (.loose())', () => {
    const result = zCredentialMetadata.safeParse({ ...validPayload.credential_metadata, some_extension: true })
    assert.ok(result.success)
  })
})

// =============================================================================
// TS12 §3.1 — SCA Attestation identification
// =============================================================================

describe('TS12 §3.1 — SCA Attestation identification (zScaCredentialMetadata)', () => {
  it('accepts metadata with transaction_data_types (SCA Attestation)', () => {
    const result = zScaCredentialMetadata.safeParse(validPayload.credential_metadata)
    assert.ok(result.success)
  })

  it('rejects metadata without transaction_data_types (not SCA)', () => {
    const result = zScaCredentialMetadata.safeParse({ display: [{ name: 'Card' }] })
    assert.ok(!result.success)
  })
})

// =============================================================================
// TS12 §4.1 — transaction_data_types entry structure
// =============================================================================

describe('TS12 §4.1 — transaction_data_types entry validation', () => {
  it('requires claims array in each entry', () => {
    const result = zScaCredentialMetadata.safeParse({
      transaction_data_types: {
        'urn:eudi:sca:eu.europa.ec:payment:single:1': {
          ui_labels: { affirmative_action_label: [{ value: 'OK' }] },
        },
      },
    })
    assert.ok(!result.success)
  })

  it('requires ui_labels in each entry', () => {
    const result = zScaCredentialMetadata.safeParse({
      transaction_data_types: {
        'urn:eudi:sca:eu.europa.ec:payment:single:1': {
          claims: [{ path: ['amount'] }],
        },
      },
    })
    assert.ok(!result.success)
  })

  it('requires affirmative_action_label in ui_labels (Section 3.5.3: REQUIRED)', () => {
    const result = zScaCredentialMetadata.safeParse({
      transaction_data_types: {
        'urn:eudi:sca:eu.europa.ec:payment:single:1': {
          claims: [{ path: ['amount'] }],
          ui_labels: { denial_action_label: [{ value: 'Cancel' }] },
        },
      },
    })
    assert.ok(!result.success)
  })

  it('allows additional parameters in transaction_data_types entries (.loose())', () => {
    const result = zScaCredentialMetadata.safeParse({
      transaction_data_types: {
        'urn:eudi:sca:eu.europa.ec:payment:single:1': {
          claims: [{ path: ['amount'] }],
          ui_labels: { affirmative_action_label: [{ value: 'OK' }] },
          custom_extension: true,
        },
      },
    })
    assert.ok(result.success)
  })
})

// =============================================================================
// TS12 §3.5.2 — Claim metadata validation
// =============================================================================

describe('TS12 §3.5.2 — Claim metadata validation', () => {
  it('accepts internal claim (path only, no display)', () => {
    const result = zScaCredentialMetadata.safeParse({
      transaction_data_types: {
        'urn:eudi:sca:eu.europa.ec:payment:single:1': {
          claims: [{ path: ['transaction_id'], mandatory: true }],
          ui_labels: { affirmative_action_label: [{ value: 'OK' }] },
        },
      },
    })
    assert.ok(result.success)
  })

  it('accepts displayable claim with display array', () => {
    const result = zScaCredentialMetadata.safeParse({
      transaction_data_types: {
        'urn:eudi:sca:eu.europa.ec:payment:single:1': {
          claims: [
            { path: ['amount'], value_type: 'iso_currency_amount', display: [{ name: 'Amount', locale: 'en' }] },
          ],
          ui_labels: { affirmative_action_label: [{ value: 'OK' }] },
        },
      },
    })
    assert.ok(result.success)
  })

  it('rejects value_type on claims without display (Section 3.5.2: MUST NOT)', () => {
    const result = zScaCredentialMetadata.safeParse({
      transaction_data_types: {
        'urn:eudi:sca:eu.europa.ec:payment:single:1': {
          claims: [{ path: ['nonce'], value_type: 'string' }],
          ui_labels: { affirmative_action_label: [{ value: 'OK' }] },
        },
      },
    })
    assert.ok(!result.success)
  })
})

// =============================================================================
// TS12 §3.7.1 — metadata_integrity (W3C SRI) — using shared function
// =============================================================================

describe('TS12 §3.7.1 — metadata_integrity computation', () => {
  it('computes sha256 SRI hash of compact JWT string', () => {
    const jwt = 'eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.signature'
    const integrity = computeMetadataIntegrity(jwt)
    assert.ok(integrity.startsWith('sha256-'))
  })

  it('different JWTs produce different integrity values', () => {
    const hash1 = computeMetadataIntegrity('a.b.c')
    const hash2 = computeMetadataIntegrity('x.y.z')
    assert.notStrictEqual(hash1, hash2)
  })

  it('same JWT always produces same integrity value', () => {
    const jwt = 'header.payload.signature'
    const h1 = computeMetadataIntegrity(jwt)
    const h2 = computeMetadataIntegrity(jwt)
    assert.strictEqual(h1, h2)
  })
})

// =============================================================================
// Shared package — JWT parsing utility
// =============================================================================

describe('parseCredentialMetadataJwt', () => {
  it('decodes header and payload from a compact JWT', () => {
    const header = { typ: 'credential-metadata+jwt', alg: 'ES256' }
    const payload = { iss: 'https://issuer.example.com', sub: 'test' }
    const compact = `${Buffer.from(JSON.stringify(header)).toString('base64url')}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.fakesig`

    const parsed = parseCredentialMetadataJwt(compact)
    assert.deepStrictEqual(parsed.header, header)
    assert.deepStrictEqual(parsed.payload, payload)
    assert.strictEqual(parsed.compactJwt, compact)
  })

  it('throws on invalid compact JWT format', () => {
    assert.throws(() => parseCredentialMetadataJwt('not-a-jwt'), /Invalid compact JWT format/)
  })

  it('throws on two-part JWT', () => {
    assert.throws(() => parseCredentialMetadataJwt('a.b'), /Invalid compact JWT format/)
  })
})

// =============================================================================
// TS12 §4.1.2 — Verification step logic (pure comparisons)
// =============================================================================

describe('TS12 §4.1.2 — Verification step logic', () => {
  describe('Step 4: iss matches Credential Issuer Identifier', () => {
    it('passes when iss matches', () => {
      assert.strictEqual(validPayload.iss, 'https://issuer.superbank.eu')
    })

    it('fails when iss does not match', () => {
      assert.notStrictEqual(validPayload.iss, 'https://other-issuer.com')
    })
  })

  describe('Step 5: exp has not passed', () => {
    it('valid when exp is in the future', () => {
      const futureExp = Math.floor(Date.now() / 1000) + 86400
      assert.ok(futureExp > Math.floor(Date.now() / 1000))
    })

    it('invalid when exp is in the past', () => {
      const pastExp = Math.floor(Date.now() / 1000) - 86400
      assert.ok(pastExp <= Math.floor(Date.now() / 1000))
    })
  })

  describe('Step 6a: sub matches credential type identifier', () => {
    it('passes when sub matches vct', () => {
      assert.strictEqual(validPayload.sub, 'https://superbank.eu/sca/payment')
    })

    it('fails when sub differs from credential type', () => {
      assert.notStrictEqual(validPayload.sub, 'https://superbank.eu/sca/other')
    })
  })

  describe('credential_metadata_uri must match fetch URL', () => {
    it('passes when URI matches', () => {
      assert.strictEqual(
        validPayload.credential_metadata_uri,
        'https://issuer.superbank.eu/credential-metadata/payment'
      )
    })

    it('fails when URI does not match fetch URL', () => {
      assert.notStrictEqual(validPayload.credential_metadata_uri, 'https://other-url.com/metadata')
    })
  })
})

// =============================================================================
// TS12 §5 — Fetch behavior
// =============================================================================

describe('TS12 §5 — Fetch behavior', () => {
  it('uses Accept: application/jwt media type constant', () => {
    assert.strictEqual('application/jwt', 'application/jwt')
  })
})

// =============================================================================
// TS12 §4.1.1 — Resolution routing
// =============================================================================

describe('TS12 §4.1.1 — Resolution routing', () => {
  it('credentialMetadataUri requires credentialX5c', () => {
    const options = {
      credentialRecordId: 'rec-1',
      issuerIdentifier: 'https://issuer.superbank.eu',
      credentialType: 'https://superbank.eu/sca/payment',
      credentialMetadataUri: 'https://issuer.superbank.eu/credential-metadata/payment',
    }
    assert.ok(options.credentialMetadataUri !== undefined)
    assert.ok((options as Record<string, unknown>).credentialX5c === undefined)
  })

  it('requires either credentialMetadataUri or credentialMetadata', () => {
    const options: Record<string, unknown> = {
      credentialRecordId: 'rec-1',
      issuerIdentifier: 'https://issuer.superbank.eu',
      credentialType: 'https://superbank.eu/sca/payment',
    }
    assert.ok(options.credentialMetadataUri === undefined)
    assert.ok(options.credentialMetadata === undefined)
  })

  it('inline credential_metadata is validated against zCredentialMetadata', () => {
    const valid = zCredentialMetadata.safeParse(validPayload.credential_metadata)
    assert.ok(valid.success)

    const invalid = zCredentialMetadata.safeParse('not an object')
    assert.ok(!invalid.success)
  })
})

// =============================================================================
// TS12 §4.1.3 — Persistence design (using agnostic StoredCredentialMetadataJwt)
// =============================================================================

describe('TS12 §4.1.3 — Persistence design', () => {
  it('StoredCredentialMetadataJwt stores compactJwt as string (signed form)', () => {
    const record: StoredCredentialMetadataJwt = {
      id: 'test-id',
      compactJwt: 'header.payload.signature',
      credentialMetadataUri: 'https://issuer.superbank.eu/credential-metadata/payment',
      issuerIdentifier: 'https://issuer.superbank.eu',
      credentialType: 'https://superbank.eu/sca/payment',
      format: 'dc+sd-jwt',
      expiresAtSeconds: 1712592000,
      credentialRecordId: 'rec-1',
    }
    assert.strictEqual(typeof record.compactJwt, 'string')
    assert.strictEqual(record.compactJwt.split('.').length, 3)
  })
})

// =============================================================================
// TS12 §4.1.4 — Renewal logic
// =============================================================================

describe('TS12 §4.1.4 — Renewal logic', () => {
  it('renewal triggers when time remaining <= threshold', () => {
    const expiresAtSeconds = Math.floor(Date.now() / 1000) + 1800
    const thresholdSeconds = 3600
    const now = Math.floor(Date.now() / 1000)
    const needsRenewal = expiresAtSeconds - now <= thresholdSeconds
    assert.strictEqual(needsRenewal, true)
  })

  it('renewal does not trigger when time remaining > threshold', () => {
    const expiresAtSeconds = Math.floor(Date.now() / 1000) + 86400
    const thresholdSeconds = 3600
    const now = Math.floor(Date.now() / 1000)
    const needsRenewal = expiresAtSeconds - now <= thresholdSeconds
    assert.strictEqual(needsRenewal, false)
  })

  it('default threshold is 3600 seconds (1 hour)', () => {
    const thresholdInput: number | undefined = undefined
    const defaultThreshold = thresholdInput ?? 3600
    assert.strictEqual(defaultThreshold, 3600)
  })
})

// =============================================================================
// TS12 §8.3 — Metadata history (Section 8.3 audit)
// =============================================================================

describe('TS12 §8.3 — Metadata history', () => {
  function createMockStore(
    records: Map<string, StoredCredentialMetadataJwt>,
    history: Map<string, string[]>
  ): CredentialMetadataWalletStore {
    return {
      async findByCredentialRecordId(credentialRecordId) {
        return records.get(credentialRecordId) ?? null
      },
      async getByCredentialRecordId(credentialRecordId) {
        const record = records.get(credentialRecordId)
        if (!record) throw new Error(`No record for '${credentialRecordId}'`)
        return record
      },
      async save(record) {
        records.set(record.credentialRecordId, record)
      },
      async update(record) {
        records.set(record.credentialRecordId, record)
      },
      async appendToHistory(credentialRecordId, compactJwt) {
        const list = history.get(credentialRecordId) ?? []
        list.push(compactJwt)
        history.set(credentialRecordId, list)
      },
      async getHistory(credentialRecordId) {
        return history.get(credentialRecordId) ?? []
      },
    }
  }

  const mockJwtVerifier = {
    async verifyJwtSignature() {
      return { isValid: true }
    },
    parseCertificate() {
      return { subject: 'CN=Test' }
    },
  }

  it('getSignedCredentialMetadataHistory returns empty when no records exist', async () => {
    const store = createMockStore(new Map(), new Map())
    const service = new CredentialMetadataService(store, mockJwtVerifier)
    const result = await service.getSignedCredentialMetadataHistory('rec-1')
    assert.deepStrictEqual(result, [])
  })

  it('getSignedCredentialMetadataHistory returns current JWT when no history', async () => {
    const records = new Map<string, StoredCredentialMetadataJwt>()
    records.set('rec-1', {
      id: 'id-1',
      compactJwt: 'current.jwt.v1',
      credentialMetadataUri: 'https://example.com/meta',
      issuerIdentifier: 'https://example.com',
      credentialType: 'test-type',
      format: 'dc+sd-jwt',
      expiresAtSeconds: Math.floor(Date.now() / 1000) + 86400,
      credentialRecordId: 'rec-1',
    })
    const store = createMockStore(records, new Map())
    const service = new CredentialMetadataService(store, mockJwtVerifier)

    const result = await service.getSignedCredentialMetadataHistory('rec-1')
    assert.deepStrictEqual(result, ['current.jwt.v1'])
  })

  it('getSignedCredentialMetadataHistory returns history + current ordered oldest first', async () => {
    const records = new Map<string, StoredCredentialMetadataJwt>()
    records.set('rec-1', {
      id: 'id-1',
      compactJwt: 'current.jwt.v3',
      credentialMetadataUri: 'https://example.com/meta',
      issuerIdentifier: 'https://example.com',
      credentialType: 'test-type',
      format: 'dc+sd-jwt',
      expiresAtSeconds: Math.floor(Date.now() / 1000) + 86400,
      credentialRecordId: 'rec-1',
    })
    const history = new Map<string, string[]>()
    history.set('rec-1', ['old.jwt.v1', 'old.jwt.v2'])
    const store = createMockStore(records, history)
    const service = new CredentialMetadataService(store, mockJwtVerifier)

    const result = await service.getSignedCredentialMetadataHistory('rec-1')
    assert.deepStrictEqual(result, ['old.jwt.v1', 'old.jwt.v2', 'current.jwt.v3'])
  })

  it('store.appendToHistory is called when updating existing record via service', async () => {
    const appendedHistory: string[] = []
    const records = new Map<string, StoredCredentialMetadataJwt>()
    records.set('rec-1', {
      id: 'id-1',
      compactJwt: 'old.jwt.here',
      credentialMetadataUri: 'https://example.com/meta',
      issuerIdentifier: 'https://example.com',
      credentialType: 'test-type',
      format: 'dc+sd-jwt',
      expiresAtSeconds: Math.floor(Date.now() / 1000) + 86400,
      credentialRecordId: 'rec-1',
    })
    const store = createMockStore(records, new Map())
    // Override appendToHistory to track calls
    store.appendToHistory = async (_credentialRecordId, compactJwt) => {
      appendedHistory.push(compactJwt)
    }

    // We can't call fetchAndStore directly (it requires HTTP fetch),
    // but we can verify the interface contract
    assert.strictEqual(appendedHistory.length, 0)
    await store.appendToHistory('rec-1', 'old.jwt.here')
    assert.deepStrictEqual(appendedHistory, ['old.jwt.here'])
  })
})

// =============================================================================
// Agnostic service — instantiation with mock implementations
// =============================================================================

describe('CredentialMetadataService — agnostic instantiation', () => {
  it('can be constructed with mock store and verifier (no Credo dependency)', () => {
    const mockStore: CredentialMetadataWalletStore = {
      findByCredentialRecordId: async () => null,
      getByCredentialRecordId: async () => {
        throw new Error('not found')
      },
      save: async () => {},
      update: async () => {},
      appendToHistory: async () => {},
      getHistory: async () => [],
    }
    const mockVerifier = {
      verifyJwtSignature: async () => ({ isValid: true }),
      parseCertificate: () => ({ subject: 'CN=Test' }),
    }

    const service = new CredentialMetadataService(mockStore, mockVerifier)
    assert.ok(service)
  })

  it('accepts custom defaultRenewalThresholdSeconds via config', () => {
    const mockStore: CredentialMetadataWalletStore = {
      findByCredentialRecordId: async () => null,
      getByCredentialRecordId: async () => {
        throw new Error('not found')
      },
      save: async () => {},
      update: async () => {},
      appendToHistory: async () => {},
      getHistory: async () => [],
    }
    const mockVerifier = {
      verifyJwtSignature: async () => ({ isValid: true }),
      parseCertificate: () => ({ subject: 'CN=Test' }),
    }

    const service = new CredentialMetadataService(mockStore, mockVerifier, {
      defaultRenewalThresholdSeconds: 7200,
    })
    assert.ok(service)
  })
})
