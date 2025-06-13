import type { X509Certificate } from '@credo-ts/core'

export const authorizeRootOfTrust = (rootOfTrustDistinguishedName: string, rootCertificates: Array<X509Certificate>) =>
  rootCertificates.some((rc) => rc.subject === rootOfTrustDistinguishedName)
