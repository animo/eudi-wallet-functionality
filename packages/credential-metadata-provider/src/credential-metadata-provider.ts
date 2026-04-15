import type { CredentialMetadata } from '@animo-id/eudi-wallet-ts12-validation'
import {
  buildLocaleKey,
  defaultLocaleCanonicalizer,
  deriveAllowedLocales,
  filterByAllowList,
  filterMetadataByLocales,
  negotiateMediaType,
  parseAcceptLanguage,
} from './filter-locale'
import type { CredentialMetadataProviderConfig, CredentialMetadataResponse } from './types'

function jsonResponse(status: number, body: string): CredentialMetadataResponse {
  return { status, contentType: 'application/json', body }
}

function jwtResponse(jwt: string): CredentialMetadataResponse {
  return { status: 200, contentType: 'application/jwt', body: jwt }
}

function errorResponse(status: number, error: string, supportedLocales?: string[]): CredentialMetadataResponse {
  return jsonResponse(status, JSON.stringify({ error, supported_locales: supportedLocales }))
}

/**
 * TS12 Section 5 — Handler for the `credential_metadata_uri` endpoint.
 */
export class CredentialMetadataProvider {
  private readonly config: CredentialMetadataProviderConfig
  private derivedLocaleCache = new Map<string, { updatedAt: number; locales: string[]; metadata: CredentialMetadata }>()

  constructor(config: CredentialMetadataProviderConfig) {
    this.config = config
  }

  async handle(
    credentialId: string,
    headers: { accept?: string; acceptLanguage?: string }
  ): Promise<CredentialMetadataResponse> {
    const { store, canonicalizeLocale = defaultLocaleCanonicalizer } = this.config

    // Content type negotiation (TS12 Section 5: absent Accept defaults to JSON)
    let acceptsJwt = false
    if (headers.accept !== undefined) {
      try {
        acceptsJwt = negotiateMediaType(headers.accept, ['application/jwt', 'application/json']) === 'application/jwt'
      } catch {
        return errorResponse(400, 'invalid_accept_header')
      }
    }

    const info = await store.getCredentialInfo(credentialId)
    if (!info) return errorResponse(404, 'not_found')

    const derived = await this.getOrDeriveLocales(credentialId, info.updatedAt)
    if (!derived) return errorResponse(404, 'not_found')

    // Language negotiation
    let inputLocales: string[]
    if (headers.acceptLanguage === undefined) {
      inputLocales = derived.locales
    } else {
      let parsed: { locales: string[]; acceptsAll: boolean }
      try {
        parsed = parseAcceptLanguage(headers.acceptLanguage)
      } catch {
        return errorResponse(400, 'invalid_accept_language')
      }

      if (parsed.acceptsAll) {
        inputLocales = derived.locales
      } else if (parsed.locales.length === 0) {
        return errorResponse(404, 'no_matching_locale', derived.locales)
      } else {
        inputLocales = filterByAllowList(parsed.locales, derived.locales)
        if (inputLocales.length === 0) {
          return errorResponse(404, 'no_matching_locale', derived.locales)
        }
      }
    }

    const selectedLocales = canonicalizeLocale(inputLocales)
    const localeKey = buildLocaleKey(selectedLocales)

    if (acceptsJwt) {
      const cached = await store.getSignedJwt(credentialId, localeKey)
      if (cached) return jwtResponse(cached)
    }

    const filteredMetadata = filterMetadataByLocales(derived.metadata, selectedLocales)

    if (!acceptsJwt) return jsonResponse(200, JSON.stringify(filteredMetadata))

    const nowSeconds = Math.floor(Date.now() / 1000)
    const payload: Record<string, unknown> = {
      iss: this.config.issuerIdentifier,
      sub: info.credentialType,
      format: info.format,
      iat: nowSeconds,
      exp: nowSeconds + this.config.expiresInSeconds,
      credential_metadata_uri: info.credentialMetadataUri,
      credential_metadata: filteredMetadata,
    }

    const jwt = await this.config.signer.sign(payload)
    await store.saveSignedJwt(credentialId, localeKey, jwt)

    return jwtResponse(jwt)
  }

  private async getOrDeriveLocales(
    credentialId: string,
    updatedAt: number
  ): Promise<{ locales: string[]; metadata: CredentialMetadata } | undefined> {
    const cached = this.derivedLocaleCache.get(credentialId)
    if (cached && cached.updatedAt === updatedAt) {
      return cached
    }
    const metadata = await this.config.store.getCredentialMetadata(credentialId)
    if (!metadata) return undefined
    const locales = deriveAllowedLocales(metadata, this.config.logger)
    this.derivedLocaleCache.set(credentialId, { updatedAt, locales, metadata })
    return { locales, metadata }
  }
}
