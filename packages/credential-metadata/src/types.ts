// --- Signing (used by provider) ---

/**
 * Signs credential-metadata+jwt payloads.
 *
 * The signer owns key material, algorithm, and its X.509 certificate chain.
 * It MUST set `typ: 'credential-metadata+jwt'` and include its `x5c` chain
 * in the protected header per TS12 Section 5.
 */
export interface JwtSigner {
  /** Sign a payload and return the compact JWS string. */
  sign(payload: Record<string, unknown>): Promise<string>

  /** The signer's X.509 certificate chain (base64-encoded, leaf first). */
  x5c: string[]
}

// --- Verification (used by wallet) ---

export interface JwtSignatureVerificationResult {
  isValid: boolean
}

export interface CertificateInfo {
  /** The distinguished name subject of the certificate. */
  subject: string
}

/**
 * Verifies credential-metadata+jwt signatures and parses X.509 certificates.
 *
 * The verifier validates signatures against **trust anchors** — root certificates
 * from the Wallet Unit's trust store that establish the chain of trust.
 */
export interface JwtVerifier {
  /**
   * Verify the JWT signature and certificate chain.
   *
   * @param compactJwt The signed JWT to verify.
   * @param trustAnchors Root certificates from the Wallet Unit's trust store,
   *   used to validate the JWT's embedded `x5c` chain.
   */
  verifyJwtSignature(compactJwt: string, trustAnchors?: string[]): Promise<JwtSignatureVerificationResult>

  /** Extract certificate info from a base64-encoded X.509 certificate. */
  parseCertificate(encodedCertificate: string): CertificateInfo
}
