import type { CredentialMetadataProvider } from '@animo-id/eudi-wallet-ts12-credential-metadata-provider'

/**
 * Request handler for the `credential_metadata_uri` endpoint.
 *
 * Compatible with Express, Hono, and any framework using `(req, res) => void`.
 */
export type CredentialMetadataRouterHandler = (
  req: { params: { credentialId: string }; headers: Record<string, string | string[] | undefined> },
  res: { status(code: number): { type(contentType: string): { send(body: string): void } } }
) => Promise<void>

/**
 * Create a request handler for `GET /:credentialId` that delegates to the
 * agnostic {@link CredentialMetadataProvider}.
 *
 * @example Express
 * ```typescript
 * import { Router } from 'express'
 * const router = Router()
 * router.get('/:credentialId', createCredentialMetadataHandler(provider))
 * app.use('/credential-metadata', router)
 * ```
 */
export function createCredentialMetadataHandler(provider: CredentialMetadataProvider): CredentialMetadataRouterHandler {
  return async (req, res) => {
    const { credentialId } = req.params
    const accept = typeof req.headers.accept === 'string' ? req.headers.accept : undefined
    const acceptLanguage =
      typeof req.headers['accept-language'] === 'string' ? req.headers['accept-language'] : undefined

    const result = await provider.handle(credentialId, { accept, acceptLanguage })
    res.status(result.status).type(result.contentType).send(result.body)
  }
}
