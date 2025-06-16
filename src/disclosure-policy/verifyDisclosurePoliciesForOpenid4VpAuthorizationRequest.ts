import { type AgentContext, type DcqlCredentialsForRequest, X509Certificate } from '@credo-ts/core'
import type { OpenId4VpAuthorizationRequestPayload, OpenId4VpResolvedAuthorizationRequest } from '@credo-ts/openid4vc'
import { type AllowListPolicy, validateAllowListPolicy } from './validateAllowlistPolicy'
import {
  type AttributeBasedAccessControlPolicy,
  validateAttributeBasedAccessControlPolicy,
} from './validateAttributeBasedAccessControlPolicy'
import { type RootOfTrustPolicy, validateRootOfTrustPolicy } from './validateRootOfTrustPolicy'
import { isAuthorizationAttestation } from './verifyAuthorizationAttestation'

export type VerifyDisclosurePoliciesForOpenId4VpAuthorizationRequestReturnContext = {
  isValid: boolean
  isSignedWithX509: boolean
  disclosurePolicies: {
    [credentialId: string]: {
      isAllowListPolicyValid?: boolean
      isRootOfTrustPolicyValid?: boolean
      isAttributeBasedAccessControlValid?: boolean
    }
  }
}

export type DisclosurePolicy = AllowListPolicy | RootOfTrustPolicy | AttributeBasedAccessControlPolicy

export type VerifyDisclosurePoliciesForOpenId4VpAuthorizationRequestOptions = {
  resolvedAuthorizationRequest: OpenId4VpResolvedAuthorizationRequest
  matchedCredentials: DcqlCredentialsForRequest
  trustedCertificates?: Array<string>
  allowUntrustedSigned?: boolean
}

/**
 *
 * Checks all the matched credentials for additional disclosure policies as set by the issuer
 *
 * Make sure the disclosure policies are set manually on the metadata of the record, under the `eudi::disclosurePolicy` key
 *
 */
export const verifyAuthorizationForOpenid4VpAuthorizationRequest = async (
  agentContext: AgentContext,
  {
    matchedCredentials,
    resolvedAuthorizationRequest,
    trustedCertificates,
    allowUntrustedSigned,
  }: VerifyDisclosurePoliciesForOpenId4VpAuthorizationRequestOptions
): Promise<VerifyDisclosurePoliciesForOpenId4VpAuthorizationRequestReturnContext> => {
  const err: VerifyDisclosurePoliciesForOpenId4VpAuthorizationRequestReturnContext = {
    isValid: true,
    isSignedWithX509: resolvedAuthorizationRequest.signedAuthorizationRequest?.signer.method === 'x5c',
    disclosurePolicies: {},
  }

  if (resolvedAuthorizationRequest.signedAuthorizationRequest?.signer.method !== 'x5c') {
    return { isValid: false, isSignedWithX509: false, disclosurePolicies: {} }
  }

  const relyingPartyAccessCertificate = X509Certificate.fromEncodedCertificate(
    resolvedAuthorizationRequest.signedAuthorizationRequest.signer.x5c[0]
  )

  for (const [credentialId, matchedCredential] of Object.entries(matchedCredentials)) {
    const disclosurePolicy = matchedCredential.credentialRecord.metadata.get<DisclosurePolicy>('eudi::disclosurePolicy')

    if (!disclosurePolicy) {
      continue
    }

    err.disclosurePolicies[credentialId] = {
      isAllowListPolicyValid:
        'allowList' in disclosurePolicy
          ? validateAllowListPolicy(disclosurePolicy as AllowListPolicy, relyingPartyAccessCertificate)
          : undefined,
      isRootOfTrustPolicyValid:
        'rootOfTrust' in disclosurePolicy
          ? validateRootOfTrustPolicy(disclosurePolicy as RootOfTrustPolicy)
          : undefined,
      isAttributeBasedAccessControlValid:
        'attribute_based_access_control' in disclosurePolicy
          ? await validateAttributeBasedAccessControlPolicy(agentContext, {
              attributeBasedAccessControlPolicy: disclosurePolicy as AttributeBasedAccessControlPolicy,
              accessCertificate: relyingPartyAccessCertificate,
              trustedCertificates,
              allowUntrustedSigned,
              authorizationAttestations: getAuthorizationAttestations(
                resolvedAuthorizationRequest.authorizationRequestPayload
              ),
            })
          : undefined,
    }
  }

  // If there is any error at all, set `isValid` to false
  err.isValid = Object.values(err)
    .map((value) => {
      if (typeof value === 'boolean') return value
      if (typeof value === 'object')
        return Object.values(value).some(
          (v) => v.isAllowListPolicyValid || v.isRootOfTrustPolicyValid || v.isAttributeBasedAccessControlValid
        )
    })
    .every((value) => value !== false)

  return err
}

// TODO: credentialId in the verifier_attestation is ignored
const getAuthorizationAttestations = (request: OpenId4VpAuthorizationRequestPayload): Array<string> =>
  request.verifier_attestations
    ?.filter((va) => typeof va.data === 'string' && isAuthorizationAttestation(va.format, va.data))
    .map((va) => va.data as string) ?? []
