import { z } from 'zod'
import { zFunkeQesTransaction } from './z-transaction-data-funke'
import { zScaTransactionDataEntry } from './z-transaction-data-ts12'

export const zTransactionDataEntry = zScaTransactionDataEntry.or(zFunkeQesTransaction)
export const zTransactionData = z.array(zTransactionDataEntry)

export type TransactionDataEntry = z.infer<typeof zTransactionDataEntry>
export type TransactionData = z.infer<typeof zTransactionData>
