import type { X509Certificate } from '@credo-ts/core'

// TODO: it is unclear from the spec what is inluded in this type
export type RootOfTrustPolicy = {
  rootOfTrust: string
}

// TODO: I am not sure how to validate this, based on the description
//
// rootOfTrust: the certificate of a RP must be derived from a list of specific root certificates. In the Implementing Acts it's called Specific root of trust. The value has to be the distinguished name of the root certificate.
export const validateRootOfTrustPolicy = (rootOfTrustPolicy: RootOfTrustPolicy) => true
