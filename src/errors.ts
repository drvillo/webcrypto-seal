/**
 * Crypto-domain error types for sealed-box and verifier failures.
 * Codes are frozen so app catch blocks that match on `code` keep working.
 */

export class SealedBoxError extends Error {
  readonly code: string

  constructor(code: string, message: string) {
    super(message)
    this.name = 'SealedBoxError'
    this.code = code
  }
}

/**
 * Raised when a verifier check fails (wrong key / tampered verifier).
 * Preserves the historical `WRONG_VAULT_PASSWORD` code for app compatibility.
 * Product adapters may re-export an alias (e.g. WrongVaultPasswordError).
 */
export class VerifierMismatchError extends Error {
  readonly code = 'WRONG_VAULT_PASSWORD' as const

  constructor(message = 'Incorrect vault password.') {
    super(message)
    this.name = 'VerifierMismatchError'
  }
}
