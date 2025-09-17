import type { AgentContext } from '@credo-ts/core'
import type { OpenId4VpResolvedAuthorizationRequest } from '@credo-ts/openid4vc'
import { isRegistrationCertificate, verifyIfRegistrationCertificate } from './verifyRegistrationCertificate'

type VerifyAuthorizationRequestOptions = {
  resolvedAuthorizationRequest: OpenId4VpResolvedAuthorizationRequest
  trustedCertificates?: Array<string>
  allowUntrustedSigned?: boolean
}

/**
 *
 * Verify the Registration certificate if it is included in the authorization request
 * If it is not included, `undefined` will be returned and the caller should handle accordingly
 *
 */
export const verifyRegistrationCertificateInOpenid4VpAuthorizationRequest = async (
  agentContext: AgentContext,
  { resolvedAuthorizationRequest, trustedCertificates, allowUntrustedSigned }: VerifyAuthorizationRequestOptions
) => {
  let registrationCertificateResult: Awaited<ReturnType<typeof verifyIfRegistrationCertificate>> | undefined
  if (!resolvedAuthorizationRequest.authorizationRequestPayload.verifier_attestations) return
  for (const va of resolvedAuthorizationRequest.authorizationRequestPayload.verifier_attestations) {
    if (typeof va.data !== 'string') {
      throw new Error('Authorization Attestations of string are currently only supported')
    }

    if (isRegistrationCertificate(va.format, va.data)) {
      registrationCertificateResult = await verifyIfRegistrationCertificate(agentContext, {
        registrationCertificate: va.data,
        resolvedAuthorizationRequest,
        allowUntrustedSigned,
        trustedCertificates,
      })
    }
  }
  return registrationCertificateResult
}
