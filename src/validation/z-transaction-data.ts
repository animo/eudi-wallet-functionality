import { z } from 'zod'
import { zFunkeQesTransaction } from './z-transaction-data-funke'
import {
  URN_SCA_ACCOUNT_ACCESS,
  URN_SCA_EMANDATE,
  URN_SCA_LOGIN_RISK,
  URN_SCA_PAYMENT,
  zAccountAccessPayload,
  zEMandatePayload,
  zLoginPayload,
  zPaymentPayload,
  zTs12Transaction,
} from './z-transaction-data-ts12'

export * from './z-transaction-data-funke'
export * from './z-transaction-data-ts12'

export const zTransactionDataEntry = zTs12Transaction.or(zFunkeQesTransaction)
export const zTransactionData = z.array(zTransactionDataEntry)

export type TransactionDataEntry = z.infer<typeof zTransactionDataEntry>
export type TransactionData = z.infer<typeof zTransactionDataEntry>

export const ts12BuiltinSchemaValidators = {
  [URN_SCA_PAYMENT]: zPaymentPayload,
  [URN_SCA_LOGIN_RISK]: zLoginPayload,
  [URN_SCA_ACCOUNT_ACCESS]: zAccountAccessPayload,
  [URN_SCA_EMANDATE]: zEMandatePayload,
} as const
