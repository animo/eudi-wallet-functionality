/** Decoded credential-metadata+jwt header and payload. Parsing only — signature must be verified separately. */
export interface ParsedCredentialMetadataJwt {
  header: Record<string, unknown>
  payload: Record<string, unknown>
  compactJwt: string
}

/**
 * Decode a compact JWT's header and payload without verifying the signature.
 *
 * This is a pure parsing utility — callers MUST verify the signature
 * via a {@link JwtVerifier} before trusting the decoded contents.
 */
export function parseCredentialMetadataJwt(compactJwt: string): ParsedCredentialMetadataJwt {
  const parts = compactJwt.split('.')
  if (parts.length !== 3) {
    throw new Error('Invalid compact JWT format — expected 3 dot-separated parts')
  }
  const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString())
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString())
  return { header, payload, compactJwt }
}
