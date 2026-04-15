# @animo-id/eudi-wallet-ts12-dcql

DCQL credential set resolution with TS12 transposability verification.

Takes a DCQL query + transaction data from an OID4VP authorization request and resolves it into independent UI slots, each with locale-resolved credential alternatives.

## Install

```bash
pnpm add @animo-id/eudi-wallet-ts12-dcql
```

## Resolve a DCQL query

```ts
import { resolveDcql } from '@animo-id/eudi-wallet-ts12-dcql'
import type {
  DcqlQuery,
  TransactionDataInput,
  WalletConfiguration,
  CredentialMatcher,
  MatchedCredential,
} from '@animo-id/eudi-wallet-ts12-dcql'

// The DCQL query from the OID4VP request
const dcqlQuery: DcqlQuery = {
  credentials: [
    { id: 'payment_card', format: 'dc+sd-jwt', meta: { vct_values: ['https://pay.example.com/card'] } },
    { id: 'pid', format: 'dc+sd-jwt', meta: { vct_values: ['https://example.com/pid'] } },
  ],
  credential_sets: [
    { options: [['payment_card', 'pid']] },
  ],
}

// Transaction data entries from the same request
const transactionData: TransactionDataInput[] = [
  {
    type: 'urn:eudi:sca:eu.europa.ec:payment:single:1',
    credential_ids: ['payment_card'],
    payload: { payee_name: 'Coffee Shop', amount: '4.50' },
  },
]

// Wallet configuration
const config: WalletConfiguration = {
  locales: ['en', 'de'],
  valueTypeResolvers: {
    currency_amount: (raw, locale) => `${raw} EUR`,
    string: (raw) => raw,
  },
  mode: 'light',
}

// Maps DCQL credential queries to wallet credentials
const matchCredentials: CredentialMatcher = (query) => {
  // Return matched credentials from the wallet store
  return walletStore.findByFormat(query.format, query.meta)
}

const result = resolveDcql(dcqlQuery, transactionData, matchCredentials, config)

if (result.ok) {
  result.value.locale // 'en' — selected locale for the presentation
  result.value.credentialSets // resolved credential sets with slots
  //
  // Each credential set contains independent slots:
  // slot.alternatives[0].credentialQueryId — which DCQL query this maps to
  // slot.alternatives[0].credentials — matched wallet credentials with:
  //   .display — locale-resolved credential card metadata
  //   .transactionData?.resolved — locale-resolved transaction display (claims + UI labels)
}
```

## SCA vs non-SCA

`resolveDcql` automatically detects whether the request involves SCA based on `config.scaTypeMatcher` (defaults to matching `urn:eudi:sca:` prefix):

- **SCA present**: strict TS12 rules — locale must satisfy all display arrays, SCA-targeted options must be transposable (Section 3.4). Returns `Err` on failure.
- **No SCA**: best-effort — decomposition never errors, locale is best-effort.

Override the matcher via `WalletConfiguration.scaTypeMatcher` to support additional standards:

```ts
import { createScaTypeMatcher } from '@animo-id/eudi-wallet-ts12-validation'

const config: WalletConfiguration = {
  // ...
  scaTypeMatcher: createScaTypeMatcher('urn:eudi:sca:'),
}
```

## Key types

```ts
// Input: what the wallet provides for each credential query
interface MatchedCredential {
  credentialId: string
  scaMetadata?: ScaCredentialMetadata  // if this is an SCA Attestation
  display?: CredentialDisplayEntry[]   // OID4VCI credential display
}

// Output: fully resolved credential ready for UI
interface ResolvedWalletCredential {
  credentialId: string
  credentialQueryId: string
  display?: ResolvedCredentialDisplay
  requestedClaims?: DcqlClaimsQuery[]
  transactionData?: {
    index: number
    entry: TransactionDataInput
    resolved?: ResolvedTransactionDisplay  // present for SCA entries
  }
}
```
