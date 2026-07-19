/**
 * Shared crypto-domain types — no product vocabulary.
 */

export interface KdfParams {
  memory: number
  time: number
  parallelism: number
}

export interface AsymmetricKeypair {
  publicKey: Uint8Array
  privateKey: Uint8Array
  publicKeyEnvelope: string
  keyId: string
}

/** Canonical AES-GCM result for both payload encrypt and key wrap. */
export interface AesGcmResult {
  ciphertext: Uint8Array
  nonce: Uint8Array
  authTag: Uint8Array
}

export interface ParsedSealedKey {
  keyId: string
  ciphertext: Uint8Array
}

export interface ParsedEncryptedPrivateKey {
  keyId: string
  nonce: Uint8Array
  ciphertextWithTag: Uint8Array
}
