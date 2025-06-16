import { type AgentContext, type DcqlCredentialsForRequest, X509Certificate } from '@credo-ts/core'
import type { OpenId4VpAuthorizationRequestPayload, OpenId4VpResolvedAuthorizationRequest } from '@credo-ts/openid4vc'
import { type AllowListPolicy, validateAllowListPolicy } from './validateAllowlistPolicy'
import {
  type AttributeBasedAccessControlPolicy,
  validateAttributeBasedAccessControlPolicy,
} from './validateAttributeBasedAccessControlPolicy'
import { type RootOfTrustPolicy, validateRootOfTrustPolicy } from './validateRootOfTrustPolicy'
import { isAuthorizationAttestation } from './verifyAuthorizationAttestation'

export type AuthzPolicy = AllowListPolicy | RootOfTrustPolicy | AttributeBasedAccessControlPolicy

type VerifyAuthorizationForOpenid4VpAuthorizationRequestOptions = {
  resolvedAuthorizationRequest: OpenId4VpResolvedAuthorizationRequest
  matchedCredentials: DcqlCredentialsForRequest
  trustedRootCertificates?: Array<X509Certificate>
}

/**
 *
 * Checks all the matched credentials for additional disclosure policies as set by the issuer
 *
 * Make sure the disclosure policies are set manually on the metadata of the record, under the `__disclosurePolicy` key
 *
 */
export const verifyAuthorizationForOpenid4VpAuthorizationRequest = async (
  agentContext: AgentContext,
  options: VerifyAuthorizationForOpenid4VpAuthorizationRequestOptions
) => {
  for (const [credentialId, matchedCredential] of Object.entries(options.matchedCredentials)) {
    const disclosurePolicy = matchedCredential.credentialRecord.metadata.get<AuthzPolicy>('__disclosurePolicy')

    if (!disclosurePolicy) {
      continue
    }

    if ('allowList' in disclosurePolicy) {
      if (!options.resolvedAuthorizationRequest.signedAuthorizationRequest) {
        throw new Error(
          `Allow list was used and authorization request must be signed. Discovered in credential id: ${credentialId}`
        )
      }

      if (options.resolvedAuthorizationRequest.signedAuthorizationRequest.signer.method !== 'x5c') {
        throw new Error(
          `Allow list was used and authorization request must be signed with x5c to determine the access certificate. Discovered in credential id: ${credentialId}`
        )
      }

      const relyingPartyAccessCertificate = X509Certificate.fromEncodedCertificate(
        options.resolvedAuthorizationRequest.signedAuthorizationRequest.signer.x5c[0]
      )
      if (!validateAllowListPolicy(disclosurePolicy as AllowListPolicy, relyingPartyAccessCertificate)) {
        throw new Error(
          `Allow list policy was used, but the relying party access certificate was not allowed to make the request. Discovered in credential id: ${credentialId}`
        )
      }
      continue
    }

    if ('rootOfTrust' in disclosurePolicy) {
      if (!options.trustedRootCertificates) {
        throw new Error(
          `rootOfTrust disclosure policy found, but no trustedRootCertificates were provided. Discovered in credential id: ${credentialId}`
        )
      }
      if (!validateRootOfTrustPolicy(disclosurePolicy as RootOfTrustPolicy)) {
        throw new Error(
          `allow list policy was used, but the rp access certificate was not allowed to make the request. Discovered in credential id: ${credentialId}`
        )
      }
      continue
    }

    if ('attribute_based_access_control' in disclosurePolicy) {
      const authorizationAttestations = getAuthorizationAttestations(
        options.resolvedAuthorizationRequest.authorizationRequestPayload
      )

      if (
        !validateAttributeBasedAccessControlPolicy(
          agentContext,
          disclosurePolicy as AttributeBasedAccessControlPolicy,
          authorizationAttestations ?? []
        )
      ) {
        throw new Error(
          `Attribute based access control disclosure policy was found, but it did not match the dcql query in the authorization request. Discovered for credentialId: ${credentialId}`
        )
      }
      continue
    }
    throw new Error(`Found an unsupported disclosure policy: ${disclosurePolicy}`)
  }
}

// TODO: credentialId in the verifier_attestation is ignored
const getAuthorizationAttestations = (request: OpenId4VpAuthorizationRequestPayload): Array<string> =>
  request.verifier_attestations
    ?.filter((va) => typeof va.data === 'string' && isAuthorizationAttestation(va.format, va.data))
    .map((va) => va.data as string) ?? []
