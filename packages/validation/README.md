# @animo-id/eudi-wallet-ts12-validation

Zod schemas for EUDI Wallet TS12 data structures.

## Install

```bash
pnpm add @animo-id/eudi-wallet-ts12-validation
```

## Schemas

### SCA credential metadata (Section 4.1)

The `transaction_data_types` object describes what transaction data a credential supports. Keys are URNs starting with `urn:eudi:sca:`, values describe claims and UI labels.

```ts
import { zScaCredentialMetadata } from '@animo-id/eudi-wallet-ts12-validation'

const metadata = zScaCredentialMetadata.parse({
  transaction_data_types: {
    'urn:eudi:sca:eu.europa.ec:payment:single:1': {
      claims: [
        { path: ['payee_name'], mandatory: true, display: [{ name: 'Payee' }] },
        { path: ['amount'], mandatory: true, value_type: 'currency_amount', display: [{ name: 'Amount' }] },
        { path: ['internal_ref'] }, // no display → internal claim
      ],
      ui_labels: {
        affirmative_action_label: [{ value: 'Confirm payment' }],
        denial_action_label: [{ value: 'Cancel' }],
        transaction_title: [{ value: 'Payment of {1} to {0}' }],
      },
    },
  },
  // additional OID4VCI fields (display, etc.) are allowed
})
```

### Credential metadata JWT header & payload (Section 5)

The signed JWT wrapping credential metadata, served at `credential_metadata_uri`.

```ts
import {
  zCredentialMetadataJwtHeader,
  zCredentialMetadataJwtPayload,
} from '@animo-id/eudi-wallet-ts12-validation'

const header = zCredentialMetadataJwtHeader.parse({
  typ: 'credential-metadata+jwt',
  alg: 'ES256',
  x5c: ['MIIBxTCCAWugAwIBAgent...', '...root-ca-base64...'],
})

const payload = zCredentialMetadataJwtPayload.parse({
  iss: 'https://issuer.example.com',
  sub: 'https://pay.example.com/card',
  format: 'dc+sd-jwt',
  iat: 1711929600,
  exp: 1712016000,
  credential_metadata_uri: 'https://issuer.example.com/credential-metadata/card',
  credential_metadata: {
    transaction_data_types: {
      'urn:eudi:sca:eu.europa.ec:payment:single:1': {
        claims: [{ path: ['payee_name'], display: [{ name: 'Payee' }] }],
        ui_labels: {
          affirmative_action_label: [{ value: 'Confirm' }],
        },
      },
    },
  },
})
```

### SCA transaction data entry (Section 4.2)

A transaction data entry from an OpenID4VP authorization request, with an SCA `payload`.

```ts
import { zTransactionDataEntry, isSCATransaction } from '@animo-id/eudi-wallet-ts12-validation'

const entry = zTransactionDataEntry.parse({
  type: 'urn:eudi:sca:eu.europa.ec:payment:single:1',
  credential_ids: ['card_credential'],
  payload: {
    payee_name: 'Coffee Shop',
    amount: '4.50',
    currency: 'EUR',
  },
})

if (isSCATransaction(entry)) {
  // entry.type starts with 'urn:eudi:sca:'
  // entry.payload is the transaction details object
}
```

### Funke QES transaction data

German EUDI Wallet profile for qualified electronic signatures.

```ts
const qesEntry = zTransactionDataEntry.parse({
  type: 'sign_document',
  credential_ids: ['qes_credential'],
  signatureQualifier: 'eu_eidas_qes',
  documentDigests: [
    { label: 'Contract.pdf', hash: 'dGVzdGhhc2g=', hashAlgorithmOID: '2.16.840.1.101.3.4.2.1' },
  ],
})
```

### SCA type matching

SCA type detection is fully configurable — different standards can use different URN prefixes.

```ts
import {
  defaultScaTypeMatcher,
  createScaTypeMatcher,
  isScaAttestationMetadata,
} from '@animo-id/eudi-wallet-ts12-validation'

// Default matcher: matches 'urn:eudi:sca:' prefix
defaultScaTypeMatcher('urn:eudi:sca:eu.europa.ec:payment:single:1') // true
defaultScaTypeMatcher('sign_document')               // false

// Custom matcher for additional standards
const matcher = createScaTypeMatcher('urn:eudi:sca:', 'urn:other:sca:')
matcher('urn:eudi:sca:eu.europa.ec:payment:single:1')  // true
matcher('urn:other:sca:com.example:transfer:1') // true

// isScaAttestationMetadata accepts an optional matcher (defaults to urn:eudi:sca:)
isScaAttestationMetadata({ transaction_data_types: { 'urn:eudi:sca:eu.europa.ec:payment:single:1': {} } }) // true
isScaAttestationMetadata(
  { transaction_data_types: { 'urn:other:sca:com.example:transfer:1': {} } },
  matcher
) // true
```
