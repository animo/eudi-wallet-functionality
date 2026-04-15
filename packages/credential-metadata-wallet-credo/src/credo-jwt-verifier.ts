import type { JwtVerifier } from '@animo-id/eudi-wallet-ts12-credential-metadata'
import { type AgentContext, JwsService, X509Certificate } from '@credo-ts/core'

/**
 * Create a {@link JwtVerifier} backed by Credo's JwsService and X509Certificate.
 *
 * Resolves `JwsService` from the agent's dependency manager for signature verification
 * and uses `X509Certificate` for certificate parsing.
 *
 * Maps `trustAnchors` to Credo's `trustedCertificates` parameter — root certificates
 * from the Wallet Unit's trust store used to validate the JWT's embedded `x5c` chain.
 */
export function createCredoJwtVerifier(agentContext: AgentContext): JwtVerifier {
  const jwsService = agentContext.dependencyManager.resolve(JwsService)

  return {
    async verifyJwtSignature(compactJwt, trustAnchors) {
      const { isValid } = await jwsService.verifyJws(agentContext, {
        jws: compactJwt,
        trustedCertificates: trustAnchors,
      })
      return { isValid }
    },

    parseCertificate(encodedCertificate) {
      const cert = X509Certificate.fromEncodedCertificate(encodedCertificate)
      return { subject: cert.subject }
    },
  }
}
