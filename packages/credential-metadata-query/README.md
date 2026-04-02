# @animo-id/eudi-wallet-ts12-credential-metadata-query

Wallet-side: resolve per-credential metadata, preferring signed JWT with fallback to unsigned JSON or inline metadata.

## Install

```bash
pnpm add @animo-id/eudi-wallet-ts12-credential-metadata-query
```

Peer dependency: `@credo-ts/core`

## Setup

Register as a credo-ts module:

```ts
import { CredentialMetadataQueryModule } from '@animo-id/eudi-wallet-ts12-credential-metadata-query'

const agent = new Agent({
  modules: {
    credentialMetadataQuery: new CredentialMetadataQueryModule(),
  },
})
```

## Resolve credential metadata

The unified entry point. Tries signed JWT first, falls back to unsigned JSON, or validates inline metadata:

```ts
const result = await agent.credentialMetadataQuery.resolveCredentialMetadata({
  credentialRecordId: sdJwtVcRecord.id,
  issuerIdentifier: 'https://issuer.example.com',
  credentialType: 'https://pay.example.com/card',

  // Option A: resolve from URI (tries signed JWT → falls back to unsigned JSON)
  credentialMetadataUri: 'https://issuer.example.com/credential-metadata/card',
  credentialX5c: [leafCertBase64, rootCertBase64], // required for JWT verification

  // Option B: use inline metadata directly (when no URI available)
  // credentialMetadata: {
  //   transaction_data_types: {
  //     'urn:eudi:sca:eu.europa.ec:payment:single:1': {
  //       claims: [{ path: ['payee_name'], display: [{ name: 'Payee' }] }],
  //       ui_labels: { affirmative_action_label: [{ value: 'Confirm' }] },
  //     },
  //   },
  // },
})
```

The result is a discriminated union — `credentialMetadata` is always present:

```ts
// result.credentialMetadata is always available:
// {
//   transaction_data_types: {
//     'urn:eudi:sca:eu.europa.ec:payment:single:1': {
//       claims: [...],
//       ui_labels: { affirmative_action_label: [...] }
//     }
//   }
// }

switch (result.source) {
  case 'signed-jwt':
    result.metadataIntegrity // 'sha256-...' — SRI hash for SCA authorization requests
    result.compactJwt        // the raw JWT string
    result.header            // { typ: 'credential-metadata+jwt', alg: 'ES256', x5c: [...] }
    result.payload           // { iss, sub, format, iat, exp, credential_metadata_uri, credential_metadata }
    break
  case 'unsigned-json':
    // fetched as JSON from the URI, no integrity proof
    break
  case 'inline':
    // validated from issuer metadata directly
    break
}
```

## Lower-level API

For direct control over the signed JWT lifecycle:

```ts
// Fetch, verify (6-step Section 4.1.2), and persist
const verified = await agent.credentialMetadataQuery.fetchAndStore({
  credentialMetadataUri: 'https://issuer.example.com/credential-metadata/card',
  issuerIdentifier: 'https://issuer.example.com',
  credentialType: 'https://pay.example.com/card',
  credentialRecordId: sdJwtVcRecord.id,
  credentialX5c: [leafCertBase64, rootCertBase64],
})
// verified.metadataIntegrity — 'sha256-...'
// verified.payload.credential_metadata — the metadata object

// Re-verify stored JWT before presentation (re-fetches on verification failure)
const reverified = await agent.credentialMetadataQuery.getVerifiedMetadata({
  credentialRecordId: sdJwtVcRecord.id,
  credentialX5c: [leafCertBase64, rootCertBase64],
})

// Renew if approaching expiry (default threshold: 1 hour)
await agent.credentialMetadataQuery.renewIfNeeded({
  credentialRecordId: sdJwtVcRecord.id,
  credentialX5c: [leafCertBase64, rootCertBase64],
  thresholdSeconds: 3600,
})

// Compute SRI integrity hash for an arbitrary JWT
const integrity = agent.credentialMetadataQuery.computeMetadataIntegrity(compactJwt)
// 'sha256-...'
```
