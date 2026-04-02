# @animo-id/eudi-wallet-ts12-resolver

Locale resolution, value type formatting, and transaction display rendering per TS12 Sections 3.3 and 3.5.

## Install

```bash
pnpm add @animo-id/eudi-wallet-ts12-resolver
```

## Resolve a transaction for display

Main entry point — takes a transaction data entry and credential metadata, resolves all claims and UI labels for the best matching locale:

```ts
import { resolveTransactionDisplay } from '@animo-id/eudi-wallet-ts12-resolver'
import type { ValueTypeResolvers } from '@animo-id/eudi-wallet-ts12-resolver'

const resolvers: ValueTypeResolvers = {
  currency_amount: (raw, locale) => new Intl.NumberFormat(locale, { style: 'currency', currency: 'EUR' }).format(Number(raw)),
  string: (raw) => raw,
}

const result = resolveTransactionDisplay(
  // Transaction data entry from the OID4VP request
  {
    type: 'urn:eudi:sca:eu.europa.ec:payment:single:1',
    credential_ids: ['payment_credential'],
    payload: {
      payee_name: 'Coffee Shop',
      amount: '4.50',
    },
  },
  // Credential metadata (from issuer, contains claims + ui_labels)
  {
    transaction_data_types: {
      'urn:eudi:sca:eu.europa.ec:payment:single:1': {
        claims: [
          { path: ['payee_name'], mandatory: true, display: [{ name: 'Payee', locale: 'en' }] },
          { path: ['amount'], mandatory: true, value_type: 'currency_amount', display: [{ name: 'Amount', locale: 'en' }] },
        ],
        ui_labels: {
          affirmative_action_label: [{ value: 'Confirm payment of {1} to {0}', locale: 'en' }],
          denial_action_label: [{ value: 'Cancel', locale: 'en' }],
        },
      },
    },
  },
  ['en', 'de'], // locale priority list
  resolvers
)

if (result) {
  result.locale // 'en'
  result.type   // 'urn:eudi:sca:eu.europa.ec:payment:single:1'
  result.claims // [{ path: ['payee_name'], label: { value: 'Payee' }, value: { value: 'Coffee Shop' } }, ...]
  result.ui_labels // { affirmative_action_label: { value: 'Confirm payment of €4.50 to Coffee Shop' }, ... }
}
```

Returns `undefined` if the transaction type is not found in the metadata, mandatory claims are missing, or no locale can fully resolve all display arrays.

## Locale selection

RFC 4647 Basic Lookup matching with fallback to the default (no-locale) entry:

```ts
import { selectLocaleEntry } from '@animo-id/eudi-wallet-ts12-resolver'

const entries = [
  { name: 'Zahlung', locale: 'de' },
  { name: 'Payment', locale: 'en' },
  { name: 'Payment (default)' }, // no locale = default fallback
]

selectLocaleEntry(entries, 'en')    // { name: 'Payment', locale: 'en' }
selectLocaleEntry(entries, 'fr')    // { name: 'Payment (default)' }
selectLocaleEntry(entries, 'de-AT') // { name: 'Zahlung', locale: 'de' } — subtag truncation
```

## Value type resolvers

Pluggable map of `value_type` identifiers to formatting functions. Each resolver receives the raw value and locale:

```ts
import type { ValueTypeResolvers } from '@animo-id/eudi-wallet-ts12-resolver'

const resolvers: ValueTypeResolvers = {
  currency_amount: (raw, locale) => `${raw} EUR`,
  date: (raw, locale) => new Date(raw).toLocaleDateString(locale),
  string: (raw) => raw,
}
```

Claims with an unrecognized `value_type` are skipped. Claims without a `value_type` pass through the raw value.

## Lower-level API

```ts
import {
  resolveAllClaims,       // resolve all displayable claims with wildcard expansion
  resolveAllUiLabels,     // resolve all UI labels with placeholder interpolation
  validateMandatoryClaims, // check mandatory claims are present in payload
  getPayloadValue,        // walk a Claims Path Pointer through nested data
} from '@animo-id/eudi-wallet-ts12-resolver'
```
