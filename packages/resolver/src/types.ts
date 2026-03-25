/** Map of value_type identifiers to resolver functions. */
export type ValueTypeResolvers = Record<string, (rawValue: string, locale: string) => unknown | undefined>

/** A display value resolved to a single typed result. */
export interface ResolvedValue {
  type?: string
  value: unknown
}

/** A displayable claim resolved to a single locale with label and payload value. */
export interface ResolvedClaim {
  path: (string | number | null)[]
  mandatory?: boolean
  label: ResolvedValue
  value: ResolvedValue
}

/** Fully resolved transaction display output. */
export interface ResolvedTransactionDisplay {
  locale: string
  type: string
  claims: ResolvedClaim[]
  ui_labels: Record<string, ResolvedValue>
}
