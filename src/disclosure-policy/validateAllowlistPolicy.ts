import type { X509Certificate } from '@credo-ts/core'

export type AllowListPolicy = {
  allowlist: Array<string>
}

export const validateAllowListPolicy = (
  allowListPolicy: AllowListPolicy,
  relyingPartyAccessCertificate: X509Certificate
) => allowListPolicy.allowlist.includes(relyingPartyAccessCertificate.subject)
