export class EudiWalletExtensionsError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'EudiWalletExtensionsError'
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, EudiWalletExtensionsError)
    }
  }
}
