import { equal, ok, rejects, strictEqual } from 'node:assert'
import { after, before, beforeEach, suite, test } from 'node:test'
import { AskarModule } from '@credo-ts/askar'
import { Agent } from '@credo-ts/core'
import { agentDependencies } from '@credo-ts/node'
import { OpenId4VcHolderModule } from '@credo-ts/openid4vc'
import { askar } from '@openwallet-foundation/askar-nodejs'
import { verifyRegistrationCertificateInOpenid4VpAuthorizationRequest } from '../src'

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
  askar: new AskarModule({ askar, store: { id: 'secure-id', key: 'secure-key' } }),
  oid4vc: new OpenId4VcHolderModule(),
}

suite('verify openid4vp authorization request', () => {
  suite('According to https://funke-wallet.de', () => {
    let agent: Agent<typeof modules>

    before(async () => {
      agent = new Agent({
        config: {
          label: 'Test Agent For Eudi Auth Request Verification',
        },
        modules,
        dependencies: agentDependencies,
      })
      await agent.initialize()
    })

    beforeEach(() => {
      ok(agent.isInitialized)
    })

    after(async () => {
      await agent.shutdown()
    })

    test('Successfully verify: draft-24, valid request, dcql', async () => {
      const authorizationRequestUrl =
        'openid4vp://?client_id=x509_san_dns%3Afunke-wallet.de&request_uri=https%3A%2F%2Ffunke-wallet.de%2Foid4vp%2Fdraft-24%2Fvalid-request%2Fdcql'

      const request = await agent.modules.oid4vc.resolveOpenId4VpAuthorizationRequest(authorizationRequestUrl, {
        trustedCertificates,
      })

      const result = await verifyRegistrationCertificateInOpenid4VpAuthorizationRequest(agent.context, {
        resolvedAuthorizationRequest: request,
        trustedCertificates,
      })

      equal(result?.isValid, true)
    })

    test('Successfully verify: draft-24, valid request, dcql, allow all certificates', async () => {
      const authorizationRequestUrl =
        'openid4vp://?client_id=x509_san_dns%3Afunke-wallet.de&request_uri=https%3A%2F%2Ffunke-wallet.de%2Foid4vp%2Fdraft-24%2Fvalid-request%2Fdcql'

      const request = await agent.modules.oid4vc.resolveOpenId4VpAuthorizationRequest(authorizationRequestUrl, {
        trustedCertificates,
      })

      const result = await verifyRegistrationCertificateInOpenid4VpAuthorizationRequest(agent.context, {
        resolvedAuthorizationRequest: request,
        allowUntrustedSigned: true,
      })

      equal(result?.isValid, true)
    })

    test('Fail verify: draft-24, valid request, pex', async () => {
      const authorizationRequestUrl =
        'openid4vp://?client_id=x509_san_dns%3Afunke-wallet.de&request_uri=https%3A%2F%2Ffunke-wallet.de%2Foid4vp%2Fdraft-24%2Fvalid-request%2Fpex'

      const request = await agent.modules.oid4vc.resolveOpenId4VpAuthorizationRequest(authorizationRequestUrl, {
        trustedCertificates,
      })

      await rejects(
        verifyRegistrationCertificateInOpenid4VpAuthorizationRequest(agent.context, {
          resolvedAuthorizationRequest: request,
          trustedCertificates,
        })
      )
    })

    test('Fail verify: draft-24, overasking, dcql', async () => {
      const authorizationRequestUrl =
        'openid4vp://?client_id=x509_san_dns%3Afunke-wallet.de&request_uri=https%3A%2F%2Ffunke-wallet.de%2Foid4vp%2Fdraft-24%2Foverask%2Fdcql'

      const request = await agent.modules.oid4vc.resolveOpenId4VpAuthorizationRequest(authorizationRequestUrl, {
        trustedCertificates,
      })

      const result = await verifyRegistrationCertificateInOpenid4VpAuthorizationRequest(agent.context, {
        resolvedAuthorizationRequest: request,
        trustedCertificates,
      })

      strictEqual(result?.isValid, false)
      equal(result?.isRegistrationCertificateQueryEqualOrSubsetOfAuthorizationRequestQuery, false)
    })
  })
})
