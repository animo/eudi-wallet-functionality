import type { AgentContext } from '@credo-ts/core'
import type { OpenId4VpResolvedAuthorizationRequest } from '@credo-ts/openid4vc'
import { isAuthorizationAttestation, verifyAuthorizationAttestation } from './verifyAuthorizationAttestation'
import { isRegistrationCertificate, verifyIfRegistrationCertificate } from './verifyRegistrationCertificate'

export type VerifyAuthorizationRequestOptions = {
  resolvedAuthorizationRequest: OpenId4VpResolvedAuthorizationRequest
  trustedCertificates?: Array<string>
  allowUntrustedSigned?: boolean
}

export const verifyOpenid4VpAuthorizationRequest = async (
  agentContext: AgentContext,
  { resolvedAuthorizationRequest, trustedCertificates, allowUntrustedSigned }: VerifyAuthorizationRequestOptions
) => {
  let registrationCertificate: Awaited<ReturnType<typeof verifyIfRegistrationCertificate>> | undefined
  if (!resolvedAuthorizationRequest.authorizationRequestPayload.verifier_attestations) return
  for (const va of resolvedAuthorizationRequest.authorizationRequestPayload.verifier_attestations) {
    if (va.format !== 'jwt') {
      throw new Error(`only format of 'jwt' is supported`)
    }

    if (typeof va.data !== 'string') {
      throw new Error('Only inline JWTs are supported')
    }

    if (isRegistrationCertificate(agentContext, va.data)) {
      registrationCertificate = await verifyIfRegistrationCertificate(agentContext, {
        registrationCertificate: va.data,
        resolvedAuthorizationRequest,
        allowUntrustedSigned,
        trustedCertificates,
      })
    }

    if (isAuthorizationAttestation(agentContext, va.data)) {
      await verifyAuthorizationAttestation(agentContext, { authorizationAttestation: va.data })
    }
  }
  return registrationCertificate
}
