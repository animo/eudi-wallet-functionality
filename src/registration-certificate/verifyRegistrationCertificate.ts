import { type AgentContext, type DcqlQuery, JwsService, Jwt, X509Certificate } from '@credo-ts/core'
import type { OpenId4VpResolvedAuthorizationRequest } from '@credo-ts/openid4vc'
import { z } from 'zod'
import { isDcqlQueryEqualOrSubset } from './isDcqlQueryEqualOrSubset'

type VerifyRegistrationCertificateOptions = {
  registrationCertificate: string
  resolvedAuthorizationRequest: OpenId4VpResolvedAuthorizationRequest
  trustedCertificates?: Array<string>
  allowUntrustedSigned?: boolean
}

const registrationCertificateHeaderSchema = z
  .object({
    typ: z.literal('rc-rp+jwt'),
    alg: z.string(),
    // sprin-d did not define this
    x5u: z.string().url().optional(),
    // sprin-d did not define this
    'x5t#s256': z.string().optional(),
  })
  .passthrough()

// TODO: does not support intermediaries
const registrationCertificatePayloadSchema = z
  .object({
    credentials: z.array(
      z.object({
        format: z.string(),
        multiple: z.boolean().default(false),
        meta: z
          .object({
            vct_values: z.array(z.string()).optional(),
            doctype_value: z.string().optional(),
          })
          .optional(),
        trusted_authorities: z
          .array(z.object({ type: z.string(), values: z.array(z.string()) }))
          .nonempty()
          .optional(),
        require_cryptographic_holder_binding: z.boolean().default(true),
        claims: z
          .array(
            z.object({
              id: z.string().optional(),
              path: z.array(z.string()).nonempty().nonempty(),
              values: z.array(z.number().or(z.boolean())).optional(),
            })
          )
          .nonempty()
          .optional(),
        claim_sets: z.array(z.array(z.string())).nonempty().optional(),
      })
    ),
    contact: z.object({
      website: z.string().url(),
      'e-mail': z.string().email(),
      phone: z.string(),
    }),
    sub: z.string(),
    // Should be service
    services: z.array(z.object({ lang: z.string(), name: z.string() })),
    public_body: z.boolean().default(false),
    entitlements: z.array(z.any()),
    provided_attestations: z
      .array(
        z.object({
          format: z.string(),
          meta: z.any(),
        })
      )
      .optional(),
    privacy_policy: z.string().url(),
    iat: z.number().optional(),
    exp: z.number().optional(),
    purpose: z
      .array(
        z.object({
          locale: z.string().optional(),
          lang: z.string().optional(),
          name: z.string(),
        })
      )
      .optional(),
    status: z.any(),
  })
  .passthrough()

export const isRegistrationCertificate = (format: string, jwt: string) => {
  if (format !== 'jwt') return false

  try {
    const { header } = Jwt.fromSerializedJwt(jwt)

    if (header.typ !== 'rc-rp+jwt') {
      return true
    }
    return false
  } catch {
    return false
  }
}

/**
 *
 *
 * If it has a header of `rc-rp+jwt` it is validated as a registration certificate according to:
 *  https://bmi.usercontent.opencode.de/eudi-wallet/eidas-2.0-architekturkonzept/flows/Wallet-Relying-Party-Authentication/#registration-certificate
 *
 */
export const verifyIfRegistrationCertificate = async (
  agentContext: AgentContext,
  {
    registrationCertificate,
    trustedCertificates,
    allowUntrustedSigned,
    resolvedAuthorizationRequest: { signedAuthorizationRequest, authorizationRequestPayload, dcql },
  }: VerifyRegistrationCertificateOptions
) => {
  const jwsService = agentContext.dependencyManager.resolve(JwsService)

  let isValidButUntrusted = false
  let isValidAndTrusted = false

  const jwt = Jwt.fromSerializedJwt(registrationCertificate)

  try {
    const { isValid } = await jwsService.verifyJws(agentContext, {
      jws: registrationCertificate,
      trustedCertificates,
    })
    isValidAndTrusted = isValid
  } catch {
    if (allowUntrustedSigned) {
      const { isValid } = await jwsService.verifyJws(agentContext, {
        jws: registrationCertificate,
        trustedCertificates: jwt.header.x5c ?? [],
      })
      isValidButUntrusted = isValid
    }
  }

  if (!signedAuthorizationRequest) {
    throw new Error('Request must be signed for the registration certificate')
  }

  if (signedAuthorizationRequest.signer.method !== 'x5c') {
    throw new Error('x5c is only supported for registration certificate')
  }

  registrationCertificateHeaderSchema.parse(jwt.header)
  const parsedPayload = registrationCertificatePayloadSchema.parse(jwt.payload.toJson())

  const [rpCertEncoded] = signedAuthorizationRequest.signer.x5c
  const rpCert = X509Certificate.fromEncodedCertificate(rpCertEncoded)

  if (rpCert.subject !== parsedPayload.sub) {
    throw new Error(
      `Subject in the certificate of the auth request: '${rpCert.subject}' is not equal to the subject of the registration certificate: '${parsedPayload.sub}'`
    )
  }

  if (parsedPayload.iat && new Date().getTime() / 1000 <= parsedPayload.iat) {
    throw new Error('Issued at timestamp of the registration certificate is in the future')
  }

  // TODO: check the status of the registration certificate

  if (!dcql) {
    throw new Error('DCQL must be used when working registration certificates')
  }

  if (authorizationRequestPayload.presentation_definition || authorizationRequestPayload.presentation_definition_uri) {
    throw new Error('Presentation Exchange is not supported for the registration certificate')
  }

  const isValidDcqlQuery = isDcqlQueryEqualOrSubset(dcql.queryResult, parsedPayload as unknown as DcqlQuery)

  if (!isValidDcqlQuery) {
    throw new Error(
      'DCQL query in the authorization request is not equal or a valid subset of the DCQl query provided in the registration certificate'
    )
  }

  return { isValidButUntrusted, isValidAndTrusted, x509RegistrationCertificate: rpCert }
}
