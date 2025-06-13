import { type AgentContext, JwsService, Jwt, X509Certificate } from '@credo-ts/core'
import type { OpenId4VpResolvedAuthorizationRequest } from '@credo-ts/openid4vc'
import { z } from 'zod'
import { isRegistrationCertificate } from './verifyRegistrationCertificate'

const authorizationAttestationHeaderSchema = z.object({})

const authorizationAttestationPayloadSchema = z.object({})

/**
 *
 * According to: https://bmi.usercontent.opencode.de/eudi-wallet/eidas-2.0-architekturkonzept/flows/OID4VC-with-WRP-attestations/#verifier-attestations
 *
 * "Each credential, that is not a Registration Certificate, is treated as an Authorization Attestation. For possible formats, see the examples section like for SD-JWT-VC."
 *
 */
export const isAuthorizationAttestation = (agentContext: AgentContext, jwt: string) => {
  return !isRegistrationCertificate(agentContext, jwt)
}

export type VerifyAuthorizationAttestationOptions = {
  authorizationAttestation: string
  resolvedAuthorizationRequest: OpenId4VpResolvedAuthorizationRequest
  trustedCertificates?: Array<string>
  allowUntrustedSigned?: boolean
}

export const verifyAuthorizationAttestation = async (
  agentContext: AgentContext,
  {
    authorizationAttestation,
    resolvedAuthorizationRequest: { signedAuthorizationRequest },
    allowUntrustedSigned,
    trustedCertificates,
  }: VerifyAuthorizationAttestationOptions
) => {
  const jwsService = agentContext.dependencyManager.resolve(JwsService)

  let isValidButUntrusted = false
  let isValidAndTrusted = false

  const jwt = Jwt.fromSerializedJwt(authorizationAttestation)

  try {
    const { isValid } = await jwsService.verifyJws(agentContext, {
      jws: authorizationAttestation,
      trustedCertificates,
    })
    isValidAndTrusted = isValid
  } catch {
    if (allowUntrustedSigned) {
      const { isValid } = await jwsService.verifyJws(agentContext, {
        jws: authorizationAttestation,
        trustedCertificates: jwt.header.x5c ?? [],
      })
      isValidButUntrusted = isValid
    }
  }

  if (!signedAuthorizationRequest) {
    throw new Error('Authorization request must be signed for the authorization attestation')
  }

  if (signedAuthorizationRequest.signer.method !== 'x5c') {
    throw new Error(
      'x5c is only supported for key derivation on the authorization request containing a authorization attestation'
    )
  }

  const accessCertificate = X509Certificate.fromEncodedCertificate(signedAuthorizationRequest.signer.x5c[0])

  // TODO: zod validate header + payload
}
