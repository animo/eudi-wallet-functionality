export class EudiWalletExtensionsError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'EudiWalletExtensionsError'
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, EudiWalletExtensionsError)
    }
  }
}

export class Ts12IntegrityError extends EudiWalletExtensionsError {
  constructor(uri: string, integrity: string) {
    super(`Invalid integrity for ${uri}, expected ${integrity}`)
    this.name = 'Ts12IntegrityError'
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, Ts12IntegrityError)
    }
  }
}
