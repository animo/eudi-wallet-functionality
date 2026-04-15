# @animo-id/eudi-wallet-ts12-credential-metadata-provider

Issuer-side: serve signed per-credential metadata JWTs per TS12 Section 5. Constructs, locale-filters, and caches signed JWTs on demand.

No framework dependency — bring your own JWT signer (jose, credo-ts, node:crypto, etc.).

## Install

```bash
pnpm add @animo-id/eudi-wallet-ts12-credential-metadata-provider
```

## Handler

The `CredentialMetadataProvider` handles requests to the `credential_metadata_uri` endpoint. It loads unsigned metadata from your store, filters it by the requested locale, signs it via the signer you provide, caches it, and returns the appropriate response.

Allowed locales are derived automatically from the metadata per TS12 Section 3.5.4 — only locales that fully resolve across all display arrays are served. A warning is emitted for locales that appear in the metadata but cannot fully resolve.

```ts
import { CredentialMetadataProvider } from '@animo-id/eudi-wallet-ts12-credential-metadata-provider'
import type { CredentialMetadataStore, JwtSigner } from '@animo-id/eudi-wallet-ts12-credential-metadata-provider'

// Bring your own signer — any library that produces compact JWS.
// The signer owns alg, x5c, and key material. It MUST set
// typ: 'credential-metadata+jwt' and include x5c per Section 5.
import { SignJWT, importPKCS8 } from 'jose'

const signer: JwtSigner = async (payload) => {
  const key = await importPKCS8(signingKeyPem, 'ES256')
  return new SignJWT(payload)
    .setProtectedHeader({ typ: 'credential-metadata+jwt', alg: 'ES256', x5c })
    .sign(key)
}

// Implement the store interface — adapt to your database/storage
const store: CredentialMetadataStore = {
  // Lightweight identity — called on every request
  async getCredentialInfo(credentialId) {
    const row = await db.findCredential(credentialId)
    if (!row) return undefined
    return {
      credentialType: row.vct,
      format: row.format,
      credentialMetadataUri: `https://issuer.example.com/credential-metadata/${credentialId}`,
      updatedAt: row.updatedAt, // epoch ms — busts the derived locale cache on change
    }
  },

  // Full metadata with all locales — only called on cache miss
  async getCredentialMetadata(credentialId) {
    return db.getMetadata(credentialId)
    // Returns the OID4VCI Section 12.2.4 credential_metadata object:
    // {
    //   display: [
    //     { name: 'SuperBank Payment', locale: 'en', logo: {...}, ... },
    //     { name: 'SuperBank Zahlung', locale: 'de', logo: {...}, ... },
    //   ],
    //   claims: [
    //     { path: ['payment_network'], display: [{ locale: 'en', name: 'Payment network' }, ...] },
    //   ],
    //   transaction_data_types: {
    //     'urn:eudi:sca:eu.europa.ec:payment:single:1': {
    //       claims: [...],
    //       ui_labels: { affirmative_action_label: [...] },
    //     },
    //   },
    // }
  },

  // Cached signed JWTs, keyed by (credentialId, canonicalLocale)
  async getSignedJwt(credentialId, canonicalLocale) {
    return cache.get(`${credentialId}:${canonicalLocale}`)
  },
  async saveSignedJwt(credentialId, canonicalLocale, jwt) {
    cache.set(`${credentialId}:${canonicalLocale}`, jwt)
  },
}

const provider = new CredentialMetadataProvider({
  store,
  signer,
  issuerIdentifier: 'https://issuer.example.com',
  expiresInSeconds: 2592000, // 30 days
  logger: console, // warns about non-resolvable locales
})
```

In your HTTP handler:

```ts
app.get('/credential-metadata/:id', async (req, res) => {
  const response = await provider.handle(req.params.id, {
    accept: req.headers.accept,
    acceptLanguage: req.headers['accept-language'],
  })
  res.setHeader('Content-Type', response.contentType)
  res.send(response.body)
})
// Accept: application/jwt  → signed JWT (constructed + cached if missing)
// Accept: application/json → locale-filtered JSON (no signing)
// Accept absent            → application/json (Section 5 default)
```

## How locale filtering works

1. The provider derives allowed locales from the metadata: only locales that fully resolve per TS12 Section 3.5.4 (every `display` array across claims and UI labels produces a match). Non-resolvable locales are logged via `logger.warn`.

2. The `Accept-Language` header is parsed (RFC 9110 §12.5.4, quality-sorted, `q=0` excluded) and intersected with the allowed locales.

3. The default locale canonicalizer picks the first (highest-quality) locale and reduces it to its primary language subtag (`en-US` → `en`). Override with `canonicalizeLocale` in the config.

4. The result is used as a cache key. Signed JWTs are cached by `(credentialId, canonicalLocale)` and busted when the store's `updatedAt` changes.

## JWT structure per Section 5

The handler builds the payload and passes it to your signer:

```
Payload (built by the provider):
  { iss, sub, format, iat, exp, credential_metadata_uri, credential_metadata: {...} }

Header (built by your signer):
  { typ: 'credential-metadata+jwt', alg: 'ES256', x5c: [...] }
```

The signer receives the payload, adds the JOSE header with its own `alg`, `x5c`, and key material, and returns a compact JWS string.
