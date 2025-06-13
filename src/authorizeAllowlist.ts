import type { X509Certificate } from '@credo-ts/core'

export const authorizeAllowList = (allowList: Array<string>, relyingPartyAccessCertificate: X509Certificate) =>
  allowList.includes(relyingPartyAccessCertificate.subject)
