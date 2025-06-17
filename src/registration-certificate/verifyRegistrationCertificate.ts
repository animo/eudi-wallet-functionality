import { type AgentContext, CredoError, type DcqlQuery, JwsService, Jwt, X509Certificate } from '@credo-ts/core'
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
    const {
      header: { typ },
    } = Jwt.fromSerializedJwt(jwt)
    return typ === 'rc-rp+jwt'
  } catch {
    return false
  }
}

export type VerifyIfRegistrationCertificateReturnContext = {
  isValid: boolean
  isSignedWithX509?: boolean
  isAccessCertificateSubjectEqualToRegistrationCertificate?: boolean
  isTimestampValid?: boolean
  isJwsValid?: boolean
  isRegistrationCertificateQueryEqualOrSubsetOfAuthorizationRequestQuery?: boolean
  isDcqlUsed?: boolean
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
): Promise<VerifyIfRegistrationCertificateReturnContext> => {
  if ((!trustedCertificates || trustedCertificates.length === 0) && !allowUntrustedSigned) {
    throw new Error('Either provide trusted certificates, or allow for untrusted signers')
  }

  const returnContext: VerifyIfRegistrationCertificateReturnContext = {
    isValid: true,
  }

  if (
    !dcql ||
    authorizationRequestPayload.presentation_definition ||
    authorizationRequestPayload.presentation_definition_uri
  ) {
    return {
      isValid: false,
      isDcqlUsed: false,
    }
  }

  if (signedAuthorizationRequest?.signer.method !== 'x5c') {
    return {
      isValid: false,
      isSignedWithX509: false,
    }
  }

  const jwsService = agentContext.dependencyManager.resolve(JwsService)

  const jwt = Jwt.fromSerializedJwt(registrationCertificate)

  const verifySignature = async (certs: Array<string>) => {
    const { isValid } = await jwsService.verifyJws(agentContext, {
      jws: registrationCertificate,
      trustedCertificates: certs,
    })
    return isValid
  }

  try {
    let isValid = true
    if (allowUntrustedSigned) {
      isValid = await verifySignature([...(trustedCertificates ?? []), ...(jwt.header.x5c ?? [])])
    } else {
      isValid = await verifySignature(trustedCertificates ?? [])
    }
    if (!isValid) {
      returnContext.isValid = false
      returnContext.isJwsValid = false
    }
  } catch {
    returnContext.isValid = false
    returnContext.isJwsValid = false
  }

  registrationCertificateHeaderSchema.parse(jwt.header)
  const parsedPayload = registrationCertificatePayloadSchema.parse(jwt.payload.toJson())

  const [rpCertEncoded] = signedAuthorizationRequest.signer.x5c
  const rpCert = X509Certificate.fromEncodedCertificate(rpCertEncoded)

  if (rpCert.subject !== parsedPayload.sub) {
    returnContext.isAccessCertificateSubjectEqualToRegistrationCertificate = false
    returnContext.isValid = false
  }

  if (parsedPayload.iat && new Date().getTime() / 1000 <= parsedPayload.iat) {
    returnContext.isTimestampValid = false
    returnContext.isValid = false
  }

  // TODO: check the status of the registration certificate

  const isValidDcqlQuery = isDcqlQueryEqualOrSubset(dcql.queryResult, parsedPayload as unknown as DcqlQuery)
  if (!isValidDcqlQuery) {
    returnContext.isValid = false
    returnContext.isRegistrationCertificateQueryEqualOrSubsetOfAuthorizationRequestQuery = false
  }

  return returnContext
}
