import type { JwtSigner } from '@animo-id/eudi-wallet-ts12-credential-metadata'
import type { AgentContext, X509Certificate } from '@credo-ts/core'
import { JwsService } from '@credo-ts/core'

export interface CredoJwtSignerOptions {
  /**
   * The signer's X.509 certificate chain. Leaf first.
   * The leaf certificate's key is used for signing, and the full chain
   * is included in the `x5c` JOSE header of every signed JWT.
   */
  x5c: X509Certificate[]
}

/**
 * Create a {@link JwtSigner} backed by Credo's JwsService and the signer's
 * own X.509 certificate chain.
 *
 * The returned signer:
 * - Uses the leaf certificate's private key for signing
 * - Includes the full chain in the `x5c` protected header
 * - Sets `typ: 'credential-metadata+jwt'` per TS12 Section 5
 * - Derives `alg` from the leaf certificate's key type
 */
export function createCredoJwtSigner(agentContext: AgentContext, options: CredoJwtSignerOptions): JwtSigner {
  const jwsService = agentContext.dependencyManager.resolve(JwsService)
  const leafCert = options.x5c[0]
  const keyId = leafCert.publicJwk.keyId
  const alg = leafCert.publicJwk.supportedSignatureAlgorithms[0]
  const x5c = options.x5c.map((cert) => cert.toString('base64'))

  return {
    x5c,

    async sign(payload: Record<string, unknown>): Promise<string> {
      return jwsService.createJwsCompact(agentContext, {
        payload: Buffer.from(JSON.stringify(payload)),
        keyId,
        protectedHeaderOptions: {
          alg,
          typ: 'credential-metadata+jwt',
          x5c,
        },
      })
    },
  }
}
