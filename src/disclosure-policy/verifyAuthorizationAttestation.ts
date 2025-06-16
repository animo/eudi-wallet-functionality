import { type AgentContext, JwsService, Jwt, SdJwtVcService, X509Certificate } from '@credo-ts/core'
import type { OpenId4VpResolvedAuthorizationRequest } from '@credo-ts/openid4vc'
import { z } from 'zod'
import { isRegistrationCertificate } from '../registration-certificate/verifyRegistrationCertificate'
import { getAuthorizationDisclosurePolicy } from './getAuthorizationDisclosurePolicy'

// TODO: support multiple authorization attestation formats.
//       Currently, only sd-jwt is defined
const authorizationAttestationHeaderSchema = z.object({
  alg: z.string(),
  typ: z.literal('dc+sd-jwt'),
  x5c: z.array(z.string()),
})

// TODO:
//    - Should we support more hashing confirmation claim values?
const authorizationAttestationPayloadSchema = z.object({
  iss: z.string(),
  sub: z.string(),
  status: z.object({
    status_list: z.object({
      idx: z.number(),
      uri: z.string().url(),
    }),
  }),
  iat: z.number(),
  exp: z.number().optional(),
  cnf: z
    .object({
      'x5t#S256': z.string(),
    })
    .optional(),
})

/**
 *
 * According to: https://bmi.usercontent.opencode.de/eudi-wallet/eidas-2.0-architekturkonzept/flows/OID4VC-with-WRP-attestations/#verifier-attestations
 *
 * "Each credential, that is not a Registration Certificate, is treated as an Authorization Attestation. For possible formats, see the examples section like for SD-JWT-VC."
 *
 */
export const isAuthorizationAttestation = (format: string, jwt: string) => {
  if (format !== 'eudi_registration_certifiate') return false

  return !isRegistrationCertificate(format, jwt)
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
  const sdJwtService = agentContext.dependencyManager.resolve(SdJwtVcService)

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

  authorizationAttestationHeaderSchema.parse(jwt.header)
  const payload = authorizationAttestationPayloadSchema.parse(jwt.payload)

  // Validate the identifier of the issuer.
  // It should be the same that issues the Authorization Certificate as that issues this attestation
  // TODO: what is the Authorization Certificate? Is it the signer of the auth request?

  // TODO: confirm that the `signingCertificate.subject` is the DN of the RP
  if (payload.sub !== accessCertificate.subject) {
    throw new Error('The Subject of the Authorization Attestation should equal the distinguished of the Relying Party')
  }

  const { isValid, verification } = await sdJwtService.verify(agentContext, {
    compactSdJwtVc: authorizationAttestation,
  })

  if (!isValid) {
    throw new Error(
      `Could not verify the sd-jwt authorization attestation. Verifications that failed at '${Object.values(
        verification
      )
        .filter(([, value]) => !value)
        .map(([key]) => key)
        .join(', ')}'`
    )
  }
}
