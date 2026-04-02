import { z } from 'zod'
import { zCredentialMetadata } from './z-sca-attestation-ext'

/**
 * TS12 Section 5 — JOSE header for a credential-metadata JWT.
 *
 * Uses `.loose()` to allow additional JOSE header parameters per RFC 7515.
 */
export const zCredentialMetadataJwtHeader = z
  .object({
    /** REQUIRED. MUST be 'credential-metadata+jwt'. */
    typ: z.literal('credential-metadata+jwt'),
    /** REQUIRED. X.509 certificate chain per RFC 7515 Section 4.1.6. */
    x5c: z.array(z.string()).nonempty(),
    /** REQUIRED. Signature algorithm identifier. */
    alg: z.string(),
  })
  .loose()
export type CredentialMetadataJwtHeader = z.infer<typeof zCredentialMetadataJwtHeader>

/**
 * TS12 Section 5 — Credential metadata JWT payload.
 *
 * Uses `.loose()` to allow additional claims.
 */
export const zCredentialMetadataJwtPayload = z
  .object({
    /** REQUIRED. Credential Issuer Identifier. */
    iss: z.string(),
    /** REQUIRED. Credential type identifier (vct for SD-JWT-VC, doctype for mdoc). */
    sub: z.string(),
    /** REQUIRED. Credential format identifier (e.g., 'dc+sd-jwt', 'mso_mdoc'). */
    format: z.string(),
    /** REQUIRED. Issued-at timestamp (NumericDate per RFC 7519). */
    iat: z.number(),
    /** REQUIRED. Expiration timestamp (NumericDate per RFC 7519). */
    exp: z.number(),
    /** REQUIRED. The URL from which this JWT was served and for re-fetch on renewal. */
    credential_metadata_uri: z.string(),
    /** REQUIRED. The credential metadata object per [OID4VCI] Section 12.2.4, extended with `transaction_data_types` per TS12 Section 4.1. */
    credential_metadata: zCredentialMetadata,
  })
  .loose()
export type CredentialMetadataJwtPayload = z.infer<typeof zCredentialMetadataJwtPayload>
