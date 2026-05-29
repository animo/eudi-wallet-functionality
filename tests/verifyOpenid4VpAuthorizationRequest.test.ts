import { AskarModule } from '@credo-ts/askar'
import { Agent } from '@credo-ts/core'
import { agentDependencies } from '@credo-ts/node'
import { OpenId4VcModule } from '@credo-ts/openid4vc'
import { NativeAskar } from '@openwallet-foundation/askar-nodejs'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { verifyOpenid4VpAuthorizationRequest } from '../src'

const trustedCertificates = [
  `-----BEGIN CERTIFICATE-----
MIIBdTCCARugAwIBAgIUHsSmbGuWAVZVXjqoidqAVClGx4YwCgYIKoZIzj0EAwIw
GzEZMBcGA1UEAwwQR2VybWFuIFJlZ2lzdHJhcjAeFw0yNTAzMzAxOTU4NTFaFw0y
NjAzMzAxOTU4NTFaMBsxGTAXBgNVBAMMEEdlcm1hbiBSZWdpc3RyYXIwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAASQWCESFd0Ywm9sK87XxqxDP4wOAadEKgcZFVX7
npe3ALFkbjsXYZJsTGhVp0+B5ZtUao2NsyzJCKznPwTz2wJcoz0wOzAaBgNVHREE
EzARgg9mdW5rZS13YWxsZXQuZGUwHQYDVR0OBBYEFMxnKLkGifbTKrxbGXcFXK6R
FQd3MAoGCCqGSM49BAMCA0gAMEUCIQD4RiLJeuVDrEHSvkPiPfBvMxAXRC6PuExo
pUGCFdfNLQIgHGSa5u5ZqUtCrnMiaEageO71rjzBlov0YUH4+6ELioY=
-----END CERTIFICATE-----`,
]

const modules = {
  askar: new AskarModule({ askar: NativeAskar.instance, store: { id: 'secure-id', key: 'secure-key' } }),
  openid4vc: new OpenId4VcModule(),
}

// Skip until re-implemented based on etsi spec
describe.skip('verify openid4vp authorization request', () => {
  describe.skip('According to https://funke-wallet.de', () => {
    let agent: Agent<typeof modules>

    beforeAll(async () => {
      agent = new Agent({
        config: {},
        modules,
        dependencies: agentDependencies,
      })
      await agent.initialize()
    })

    beforeEach(() => {
      expect(agent.isInitialized).toBe(true)
    })

    afterAll(async () => {
      await agent.shutdown()
    })

    it('Successfully verify: draft-24, valid request, dcql', async () => {
      const authorizationRequestUrl =
        'openid4vp://?client_id=x509_san_dns%3Afunke-wallet.de&request_uri=https%3A%2F%2Ffunke-wallet.de%2Foid4vp%2Fdraft-24%2Fvalid-request%2Fdcql'

      const request = await agent.openid4vc.holder.resolveOpenId4VpAuthorizationRequest(authorizationRequestUrl, {
        trustedCertificates,
      })

      const result = await verifyOpenid4VpAuthorizationRequest(agent.context, {
        resolvedAuthorizationRequest: request,
        trustedCertificates,
      })

      expect(result?.[0].isValidAndTrusted).toBe(true)
      expect(result?.[0].isValidButUntrusted).toBe(false)
    })

    it('Successfully verify: draft-24, valid request, dcql, allow all certificates', async () => {
      const authorizationRequestUrl =
        'openid4vp://?client_id=x509_san_dns%3Afunke-wallet.de&request_uri=https%3A%2F%2Ffunke-wallet.de%2Foid4vp%2Fdraft-24%2Fvalid-request%2Fdcql'

      const request = await agent.openid4vc.holder.resolveOpenId4VpAuthorizationRequest(authorizationRequestUrl, {
        trustedCertificates,
      })

      const result = await verifyOpenid4VpAuthorizationRequest(agent.context, {
        resolvedAuthorizationRequest: request,
        allowUntrustedSigned: true,
      })

      expect(result?.[0].isValidAndTrusted).toBe(false)
      expect(result?.[0].isValidButUntrusted).toBe(true)
    })

    it('Fail verify: draft-24, valid request, pex', async () => {
      const authorizationRequestUrl =
        'openid4vp://?client_id=x509_san_dns%3Afunke-wallet.de&request_uri=https%3A%2F%2Ffunke-wallet.de%2Foid4vp%2Fdraft-24%2Fvalid-request%2Fpex'

      const request = await agent.openid4vc.holder.resolveOpenId4VpAuthorizationRequest(authorizationRequestUrl, {
        trustedCertificates,
      })

      await expect(
        verifyOpenid4VpAuthorizationRequest(agent.context, {
          resolvedAuthorizationRequest: request,
          trustedCertificates,
        })
      ).rejects.toThrow()
    })

    it('Fail verify: draft-24, overasking, dcql', async () => {
      const authorizationRequestUrl =
        'openid4vp://?client_id=x509_san_dns%3Afunke-wallet.de&request_uri=https%3A%2F%2Ffunke-wallet.de%2Foid4vp%2Fdraft-24%2Foverask%2Fdcql'

      const request = await agent.openid4vc.holder.resolveOpenId4VpAuthorizationRequest(authorizationRequestUrl, {
        trustedCertificates,
      })

      await expect(
        verifyOpenid4VpAuthorizationRequest(agent.context, {
          resolvedAuthorizationRequest: request,
          trustedCertificates,
        })
      ).rejects.toThrow()
    })
  })
})
