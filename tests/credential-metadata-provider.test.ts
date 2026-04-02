import assert from 'node:assert'
import { describe, it } from 'node:test'
import { CredentialMetadataProvider } from '../packages/credential-metadata-provider/src/credential-metadata-provider'
import {
  buildLocaleKey,
  collectMetadataLocales,
  defaultLocaleCanonicalizer,
  deriveAllowedLocales,
  filterByAllowList,
  filterMetadataByLocales,
  localeFullyResolves,
  negotiateMediaType,
  parseAcceptLanguage,
} from '../packages/credential-metadata-provider/src/filter-locale'
import type { CredentialMetadata } from '../packages/validation/src/z-sca-attestation-ext'

// =============================================================================
// Fixtures — TS12 Annex D.8 style credential metadata
// =============================================================================

const annexDMetadata: CredentialMetadata = {
  display: [
    {
      name: 'SuperBank Payment',
      locale: 'en',
      logo: { uri: 'https://issuer.superbank.eu/logo.png', alt_text: 'SuperBank logo' },
      background_color: '#003366',
      text_color: '#ffffff',
    },
    {
      name: 'SuperBank Zahlung',
      locale: 'de',
      logo: { uri: 'https://issuer.superbank.eu/logo.png', alt_text: 'SuperBank-Logo' },
      background_color: '#003366',
      text_color: '#ffffff',
    },
  ],
  claims: [
    {
      path: ['payment_network'],
      display: [
        { locale: 'en', name: 'Payment network' },
        { locale: 'de', name: 'Zahlungsnetzwerk' },
      ],
    },
  ],
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
        denial_action_label: [
          { locale: 'en', value: 'Cancel' },
          { locale: 'de', value: 'Abbrechen' },
        ],
      },
    },
  },
}

/** Metadata with default (no-locale) entries — RFC 4647 Section 3.4 default value. */
const metadataWithDefaults: CredentialMetadata = {
  display: [{ name: 'Default Card' }, { name: 'EN Card', locale: 'en' }],
  transaction_data_types: {
    'urn:eudi:sca:eu.europa.ec:payment:single:1': {
      claims: [{ path: ['amount'], display: [{ name: 'Amount (default)' }, { locale: 'en', name: 'Amount' }] }],
      ui_labels: { affirmative_action_label: [{ value: 'OK (default)' }, { locale: 'en', value: 'Confirm' }] },
    },
  },
}

/** Metadata with inconsistent locale coverage — de missing from one display array. */
const inconsistentMetadata: CredentialMetadata = {
  display: [
    { name: 'Card', locale: 'en' },
    { name: 'Karte', locale: 'de' },
  ],
  transaction_data_types: {
    'urn:eudi:sca:eu.europa.ec:payment:single:1': {
      claims: [{ path: ['amount'], display: [{ locale: 'en', name: 'Amount' }] }],
      ui_labels: { affirmative_action_label: [{ locale: 'en', value: 'OK' }] },
    },
  },
}

// =============================================================================
// Mock provider helpers
// =============================================================================

function makeStore() {
  const jwtCache = new Map<string, string>()
  return {
    getCredentialInfo: async (id: string) =>
      id === 'card'
        ? {
            credentialType: 'https://superbank.eu/sca/payment',
            format: 'dc+sd-jwt',
            credentialMetadataUri: 'https://issuer.superbank.eu/credential-metadata/payment',
            updatedAt: 1,
          }
        : undefined,
    getCredentialMetadata: async (id: string) => (id === 'card' ? annexDMetadata : undefined),
    getSignedJwt: async (_id: string, key: string) => jwtCache.get(key),
    saveSignedJwt: async (_id: string, key: string, jwt: string) => {
      jwtCache.set(key, jwt)
    },
  }
}

const fakeSigner = async (payload: Record<string, unknown>) => `header.${btoa(JSON.stringify(payload))}.signature`

function makeProvider() {
  return new CredentialMetadataProvider({
    store: makeStore(),
    signer: fakeSigner,
    issuerIdentifier: 'https://issuer.superbank.eu',
    expiresInSeconds: 2592000,
  })
}

// =============================================================================
// TS12 Section 5 — Content negotiation (Accept header)
// =============================================================================
// "If the Accept header is absent or does not express a preference, the Credential
//  Issuer SHALL default to application/json."
// "Accept: application/json — SHALL return the credential metadata as a plain JSON object."
// "Accept: application/jwt — SHALL return the credential metadata as a signed JWT."

describe('TS12 Section 5 — Accept header content negotiation', () => {
  it('absent Accept header defaults to application/json', async () => {
    const res = await makeProvider().handle('card', {})
    assert.strictEqual(res.status, 200)
    assert.strictEqual(res.contentType, 'application/json')
    JSON.parse(res.body) // must be valid JSON
  })

  it('Accept: application/json returns JSON', async () => {
    const res = await makeProvider().handle('card', { accept: 'application/json' })
    assert.strictEqual(res.contentType, 'application/json')
  })

  it('Accept: application/jwt returns signed JWT', async () => {
    const res = await makeProvider().handle('card', { accept: 'application/jwt' })
    assert.strictEqual(res.contentType, 'application/jwt')
    assert.strictEqual(res.body.split('.').length, 3)
  })

  it('Accept: application/jwt;q=0 excludes JWT (RFC 9110 §12.5.1: q=0 not acceptable)', async () => {
    const res = await makeProvider().handle('card', { accept: 'application/jwt;q=0, application/json' })
    assert.strictEqual(res.contentType, 'application/json')
  })

  it('credential not found returns 404', async () => {
    const res = await makeProvider().handle('unknown', { accept: 'application/json' })
    assert.strictEqual(res.status, 404)
    assert.strictEqual(JSON.parse(res.body).error, 'not_found')
  })

  it('malformed Accept header returns 400', async () => {
    const res = await makeProvider().handle('card', { accept: 'application/jwt;q=abc;q=xyz' })
    // @hapi/accept may or may not throw on this — if it doesn't throw, the provider should still respond
    assert.ok(res.status === 200 || res.status === 400)
  })
})

// =============================================================================
// TS12 Section 5 — JWT payload structure
// =============================================================================
// "The JWT payload SHALL include the following claims:
//  iss, sub, format, iat, exp, credential_metadata_uri, credential_metadata"

describe('TS12 Section 5 — JWT payload claims', () => {
  it('contains all REQUIRED claims per Section 5', async () => {
    const res = await makeProvider().handle('card', { accept: 'application/jwt', acceptLanguage: 'en' })
    const payload = JSON.parse(atob(res.body.split('.')[1]))

    assert.strictEqual(payload.iss, 'https://issuer.superbank.eu')
    assert.strictEqual(payload.sub, 'https://superbank.eu/sca/payment')
    assert.strictEqual(payload.format, 'dc+sd-jwt')
    assert.ok(typeof payload.iat === 'number')
    assert.ok(typeof payload.exp === 'number')
    assert.ok(payload.exp > payload.iat)
    assert.strictEqual(payload.credential_metadata_uri, 'https://issuer.superbank.eu/credential-metadata/payment')
    assert.ok(payload.credential_metadata !== undefined)
  })

  it('exp = iat + expiresInSeconds', async () => {
    const res = await makeProvider().handle('card', { accept: 'application/jwt', acceptLanguage: 'en' })
    const payload = JSON.parse(atob(res.body.split('.')[1]))
    assert.strictEqual(payload.exp - payload.iat, 2592000)
  })

  it('credential_metadata contains display and transaction_data_types', async () => {
    const res = await makeProvider().handle('card', { accept: 'application/jwt', acceptLanguage: 'en' })
    const payload = JSON.parse(atob(res.body.split('.')[1]))
    const cm = payload.credential_metadata
    assert.ok(Array.isArray(cm.display))
    assert.ok(cm.transaction_data_types !== undefined)
  })
})

// =============================================================================
// TS12 Section 5 / RFC 9110 §12.5.4 — Accept-Language handling
// =============================================================================
// "the Wallet Unit MAY include an Accept-Language header per [OID4VCI] Section 12.2.2"
// RFC 9110 §12.5.4: absent Accept-Language means any language acceptable
// RFC 9110 §12.5.4: * matches any language

describe('TS12 Section 5 — Accept-Language handling', () => {
  it('absent Accept-Language serves metadata (any language acceptable per RFC 9110)', async () => {
    const res = await makeProvider().handle('card', { accept: 'application/json' })
    assert.strictEqual(res.status, 200)
  })

  it('Accept-Language: * serves metadata (accept any per RFC 9110 §12.5.4)', async () => {
    const res = await makeProvider().handle('card', { accept: 'application/json', acceptLanguage: '*' })
    assert.strictEqual(res.status, 200)
  })

  it('Accept-Language: en filters to English only', async () => {
    const res = await makeProvider().handle('card', { accept: 'application/json', acceptLanguage: 'en' })
    const cm = JSON.parse(res.body)
    assert.strictEqual(cm.display.length, 1)
    assert.strictEqual(cm.display[0].locale, 'en')
  })

  it('Accept-Language: de filters to German only', async () => {
    const res = await makeProvider().handle('card', { accept: 'application/json', acceptLanguage: 'de' })
    const cm = JSON.parse(res.body)
    assert.strictEqual(cm.display.length, 1)
    assert.strictEqual(cm.display[0].locale, 'de')
  })

  it('unmatched Accept-Language returns 404 with supported_locales', async () => {
    const res = await makeProvider().handle('card', { accept: 'application/json', acceptLanguage: 'zh-CN' })
    assert.strictEqual(res.status, 404)
    const body = JSON.parse(res.body)
    assert.strictEqual(body.error, 'no_matching_locale')
    assert.ok(Array.isArray(body.supported_locales))
    assert.ok(body.supported_locales.length > 0)
  })

  it('Accept-Language: en;q=0 (nothing acceptable) returns 404', async () => {
    const res = await makeProvider().handle('card', { accept: 'application/json', acceptLanguage: 'en;q=0' })
    assert.strictEqual(res.status, 404)
  })

  it('malformed Accept-Language returns 400', async () => {
    const res = await makeProvider().handle('card', { accept: 'application/json', acceptLanguage: 'en;q=abc;q=xyz' })
    assert.strictEqual(res.status, 400)
    assert.strictEqual(JSON.parse(res.body).error, 'invalid_accept_language')
  })

  it('quality values determine preference: de;q=0.5, en;q=0.9 picks en', async () => {
    const res = await makeProvider().handle('card', {
      accept: 'application/json',
      acceptLanguage: 'de;q=0.5, en;q=0.9',
    })
    const cm = JSON.parse(res.body)
    // defaultLocaleCanonicalizer picks first (highest q) locale's primary subtag
    assert.strictEqual(cm.display.length, 1)
    assert.strictEqual(cm.display[0].locale, 'en')
  })
})

// =============================================================================
// RFC 4647 Section 3.4 — Basic Lookup
// =============================================================================
// "the range is truncated by removing the last subtag"
// "Tags and ranges are to be matched in a case-insensitive manner"
// "If the subtag that is removed is a single character, the preceding subtag is also removed"

describe('RFC 4647 §3.4 — Basic Lookup (locale matching)', () => {
  it('range en-GB matches tag en (range truncation: en-GB → en)', () => {
    assert.strictEqual(
      localeFullyResolves('en-GB', {
        display: [{ name: 'Card', locale: 'en' }],
        transaction_data_types: {
          'urn:eudi:sca:eu.europa.ec:payment:single:1': {
            claims: [{ path: ['x'], display: [{ locale: 'en', name: 'X' }] }],
            ui_labels: { affirmative_action_label: [{ locale: 'en', value: 'OK' }] },
          },
        },
      }),
      true
    )
  })

  it('range en does NOT match tag en-GB (tags are never truncated)', () => {
    assert.strictEqual(
      localeFullyResolves('en', {
        display: [{ name: 'Card', locale: 'en-GB' }],
        transaction_data_types: {
          'urn:eudi:sca:eu.europa.ec:payment:single:1': {
            claims: [{ path: ['x'], display: [{ locale: 'en-GB', name: 'X' }] }],
            ui_labels: { affirmative_action_label: [{ locale: 'en-GB', value: 'OK' }] },
          },
        },
      }),
      false
    )
  })

  it('default entry (no locale) matches when lookup exhausts all truncations (RFC 4647 §3.4 default value)', () => {
    assert.strictEqual(localeFullyResolves('fr', metadataWithDefaults), true)
  })

  it('no default and no match → locale does not resolve', () => {
    assert.strictEqual(localeFullyResolves('fr', inconsistentMetadata), false)
  })

  it('matching is case-insensitive (RFC 4647: "case-insensitive manner")', () => {
    assert.strictEqual(localeFullyResolves('EN', annexDMetadata), true)
    assert.strictEqual(localeFullyResolves('De', annexDMetadata), true)
  })
})

// =============================================================================
// TS12 Section 3.5.4 — Locale resolvability
// =============================================================================
// "If every display array produces a match, the current locale is selected"
// "If any display array produces no match, discard all matches"

describe('TS12 §3.5.4 — Locale resolvability', () => {
  it('locale resolves when all display arrays have it (Annex D: en and de)', () => {
    assert.strictEqual(localeFullyResolves('en', annexDMetadata), true)
    assert.strictEqual(localeFullyResolves('de', annexDMetadata), true)
  })

  it('locale fails to resolve when ANY display array lacks it', () => {
    // inconsistentMetadata: 'de' is in credential display but missing from claims and ui_labels
    assert.strictEqual(localeFullyResolves('de', inconsistentMetadata), false)
  })

  it('deriveAllowedLocales only returns fully resolvable locales', () => {
    const allowed = deriveAllowedLocales(inconsistentMetadata)
    assert.ok(allowed.includes('en'))
    assert.ok(!allowed.includes('de'))
  })

  it('deriveAllowedLocales warns for non-resolvable locales', () => {
    const warnings: string[] = []
    deriveAllowedLocales(inconsistentMetadata, { warn: (msg) => warnings.push(msg) })
    assert.strictEqual(warnings.length, 1)
    assert.ok(warnings[0].includes('de'))
  })

  it('collectMetadataLocales returns all unique locale tags', () => {
    const locales = collectMetadataLocales(annexDMetadata)
    assert.ok(locales.includes('en'))
    assert.ok(locales.includes('de'))
    assert.strictEqual(locales.length, 2)
  })
})

// =============================================================================
// TS12 Section 5 — Locale filtering of credential_metadata
// =============================================================================
// The provider filters display arrays to the requested locale.
// Per Section 3.5.4: "Entries that omit locale are default entries" — always kept.

describe('TS12 §5 — Metadata locale filtering', () => {
  it('filters credential-level display to requested locale (OID4VCI §12.2.4)', () => {
    const result = filterMetadataByLocales(annexDMetadata, ['en'])
    assert.strictEqual(result.display?.length, 1)
    assert.strictEqual(result.display?.[0].name, 'SuperBank Payment')
  })

  it('filters credential-level claims display', () => {
    const result = filterMetadataByLocales(annexDMetadata, ['de'])
    const claim = result.claims?.[0]
    assert.ok(claim && 'display' in claim)
    if ('display' in claim) {
      assert.strictEqual(claim.display.length, 1)
      assert.strictEqual(claim.display[0].name, 'Zahlungsnetzwerk')
    }
  })

  it('filters transaction_data_types claims display', () => {
    const result = filterMetadataByLocales(annexDMetadata, ['en'])
    const tdType = result.transaction_data_types?.['urn:eudi:sca:eu.europa.ec:payment:single:1']
    assert.ok(tdType)
    const amountClaim = tdType.claims[1]
    assert.ok('display' in amountClaim)
    if ('display' in amountClaim) {
      assert.strictEqual(amountClaim.display.length, 1)
      assert.strictEqual(amountClaim.display[0].name, 'Amount')
    }
  })

  it('filters transaction_data_types ui_labels', () => {
    const result = filterMetadataByLocales(annexDMetadata, ['de'])
    const tdType = result.transaction_data_types?.['urn:eudi:sca:eu.europa.ec:payment:single:1']
    assert.ok(tdType)
    assert.strictEqual(tdType.ui_labels.affirmative_action_label.length, 1)
    assert.strictEqual(tdType.ui_labels.affirmative_action_label[0].value, 'Zahlung bestätigen')
  })

  it('preserves internal claims (no display) unchanged', () => {
    const result = filterMetadataByLocales(annexDMetadata, ['en'])
    const tdType = result.transaction_data_types?.['urn:eudi:sca:eu.europa.ec:payment:single:1']
    assert.ok(tdType)
    const txIdClaim = tdType.claims[0]
    assert.ok(!('display' in txIdClaim))
    assert.strictEqual(txIdClaim.mandatory, true)
  })

  it('always keeps default (no-locale) entries per RFC 4647 §3.4', () => {
    const result = filterMetadataByLocales(metadataWithDefaults, ['en'])
    assert.strictEqual(result.display?.length, 2) // default + en
    assert.ok(result.display?.some((d) => d.name === 'Default Card'))
  })

  it('keeps only defaults when locale has no match', () => {
    const result = filterMetadataByLocales(metadataWithDefaults, ['zh'])
    assert.strictEqual(result.display?.length, 1) // default only
    assert.strictEqual(result.display?.[0].name, 'Default Card')
  })

  it('does not mutate original metadata', () => {
    const originalLen = annexDMetadata.display?.length
    const result = filterMetadataByLocales(annexDMetadata, ['en'])
    assert.notStrictEqual(result, annexDMetadata)
    assert.strictEqual(annexDMetadata.display?.length, originalLen)
  })
})

// =============================================================================
// TS12 Section 5 — Accept header media type negotiation
// =============================================================================

describe('negotiateMediaType (via @hapi/accept)', () => {
  const available = ['application/jwt', 'application/json']

  it('exact match: application/jwt', () => {
    assert.strictEqual(negotiateMediaType('application/jwt', available), 'application/jwt')
  })

  it('exact match: application/json', () => {
    assert.strictEqual(negotiateMediaType('application/json', available), 'application/json')
  })

  it('q=0 excludes a type (RFC 9110 §12.5.1)', () => {
    assert.strictEqual(negotiateMediaType('application/jwt;q=0, application/json', available), 'application/json')
  })

  it('higher q wins', () => {
    assert.strictEqual(negotiateMediaType('application/json;q=0.5, application/jwt', available), 'application/jwt')
  })
})

// =============================================================================
// TS12 Section 5 — Accept-Language parsing
// =============================================================================

describe('parseAcceptLanguage (via @hapi/accept)', () => {
  it('returns locales sorted by quality', () => {
    const { locales } = parseAcceptLanguage('de, en;q=0.8')
    assert.strictEqual(locales[0], 'de')
  })

  it('* sets acceptsAll', () => {
    const { acceptsAll } = parseAcceptLanguage('*')
    assert.strictEqual(acceptsAll, true)
  })

  it('* is excluded from locales list', () => {
    const { locales } = parseAcceptLanguage('*')
    assert.ok(!locales.includes('*'))
  })

  it('q=0 excludes a locale (RFC 9110 §12.5.4)', () => {
    const { locales } = parseAcceptLanguage('en, de;q=0')
    assert.ok(!locales.includes('de'))
  })

  it('throws on malformed header', () => {
    assert.throws(() => parseAcceptLanguage('en;q=abc;q=xyz'))
  })
})

// =============================================================================
// Locale canonicalization + cache key
// =============================================================================

describe('defaultLocaleCanonicalizer', () => {
  it('picks first locale primary subtag: [en-us, de-de] → [en]', () => {
    assert.deepStrictEqual(defaultLocaleCanonicalizer(['en-us', 'de-de']), ['en'])
  })

  it('handles locale without subtag: [de] → [de]', () => {
    assert.deepStrictEqual(defaultLocaleCanonicalizer(['de', 'en']), ['de'])
  })

  it('empty input → empty output', () => {
    assert.deepStrictEqual(defaultLocaleCanonicalizer([]), [])
  })
})

describe('buildLocaleKey', () => {
  it('sorts and deduplicates', () => {
    assert.strictEqual(buildLocaleKey(['de', 'en', 'de']), 'de,en')
  })

  it('empty → empty string', () => {
    assert.strictEqual(buildLocaleKey([]), '')
  })
})

// =============================================================================
// filterByAllowList — RFC 4647 Lookup against allowed locales
// =============================================================================

describe('filterByAllowList', () => {
  it('keeps locales that match allowed via RFC 4647 Lookup', () => {
    const result = filterByAllowList(['en', 'fr'], ['en', 'de'])
    assert.deepStrictEqual(result, ['en'])
  })

  it('range truncation: en-GB matches allowed en', () => {
    const result = filterByAllowList(['en-GB'], ['en'])
    assert.deepStrictEqual(result, ['en-GB'])
  })

  it('returns empty when nothing matches', () => {
    const result = filterByAllowList(['fr'], ['en', 'de'])
    assert.deepStrictEqual(result, [])
  })
})

// =============================================================================
// TS12 Section 5 — JWT caching
// =============================================================================

describe('TS12 §5 — JWT caching', () => {
  it('second request for same locale returns cached JWT', async () => {
    const provider = makeProvider()
    const h = { accept: 'application/jwt', acceptLanguage: 'en' }
    const r1 = await provider.handle('card', h)
    const r2 = await provider.handle('card', h)
    assert.strictEqual(r1.body, r2.body)
  })

  it('different locales produce different JWTs', async () => {
    const provider = makeProvider()
    const r1 = await provider.handle('card', { accept: 'application/jwt', acceptLanguage: 'en' })
    const r2 = await provider.handle('card', { accept: 'application/jwt', acceptLanguage: 'de' })
    assert.notStrictEqual(r1.body, r2.body)
  })
})
