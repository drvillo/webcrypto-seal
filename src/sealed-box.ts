/**
 * Lazy libsodium sealed-box primitives (keypair, seal, open).
 * Parse/format helpers live in wire.ts and are re-exported here for a single import point.
 */

import type sodiumType from 'libsodium-wrappers'
import { MAX_SEALED_PAYLOAD_BYTES, X25519_KEY_BYTES } from './constants.js'
import { SealedBoxError } from './errors.js'
import type { AsymmetricKeypair } from './types.js'
import {
  computeKeyId,
  formatEncryptedPrivateKey,
  formatPublicKey,
  formatSealedKey,
  parseEncryptedPrivateKey,
  parsePublicKey,
  parseSealedKey,
  validatePublicKeyFingerprint,
} from './wire.js'

export type { AsymmetricKeypair } from './types.js'
export {
  ENCRYPTED_PRIVATE_KEY_PREFIX,
  PUBLIC_KEY_PREFIX,
  SEALED_KEY_PREFIX,
} from './constants.js'
export { SealedBoxError } from './errors.js'
export {
  computeKeyId,
  formatEncryptedPrivateKey,
  formatPublicKey,
  formatSealedKey,
  parseEncryptedPrivateKey,
  parsePublicKey,
  parseSealedKey,
  validatePublicKeyFingerprint,
}
export type { ParsedEncryptedPrivateKey, ParsedSealedKey } from './types.js'
export { fromBase64Url, toBase64Url, assertCanonicalBase64Url } from './encoding.js'

let sodiumPromise: Promise<typeof sodiumType> | null = null

function getSodium(): Promise<typeof sodiumType> {
  if (!sodiumPromise) {
    sodiumPromise = import('libsodium-wrappers').then(async ({ default: sodium }) => {
      await sodium.ready
      return sodium
    })
  }
  return sodiumPromise
}

function normalizeBytes(bytes: Uint8Array): Uint8Array {
  const copy = new Uint8Array(bytes.length)
  copy.set(bytes)
  return copy
}

export async function validatePrivateKeyPair(
  privateKey: Uint8Array,
  publicKeyEnvelope: string
): Promise<void> {
  if (privateKey.length !== X25519_KEY_BYTES) {
    throw new SealedBoxError('INVALID_PRIVATE_KEY', 'Private key must be 32 bytes.')
  }
  const publicKey = parsePublicKey(publicKeyEnvelope)
  const sodium = await getSodium()
  const derivedPublicKey = sodium.crypto_scalarmult_base(privateKey)
  if (!sodium.memcmp(derivedPublicKey, publicKey)) {
    throw new SealedBoxError('KEYPAIR_MISMATCH', 'Private key does not match stored public key.')
  }
}

export async function zeroSensitiveBytes(bytes: Uint8Array): Promise<void> {
  const sodium = await getSodium()
  sodium.memzero(bytes)
}

export async function generateKeypair(): Promise<AsymmetricKeypair> {
  const sodium = await getSodium()
  const keypair = sodium.crypto_box_keypair()
  const publicKey = normalizeBytes(keypair.publicKey)
  const privateKey = normalizeBytes(keypair.privateKey)
  const derivedPublicKey = sodium.crypto_scalarmult_base(privateKey)
  if (!sodium.memcmp(publicKey, derivedPublicKey)) {
    throw new SealedBoxError('KEYPAIR_MISMATCH', 'Generated keypair is inconsistent.')
  }
  const publicKeyEnvelope = formatPublicKey(publicKey)
  const keyId = await computeKeyId(publicKey)
  return { publicKey, privateKey, publicKeyEnvelope, keyId }
}

export async function sealBytes(plaintext: Uint8Array, publicKey: Uint8Array): Promise<Uint8Array> {
  if (publicKey.length !== X25519_KEY_BYTES) {
    throw new SealedBoxError('INVALID_PUBLIC_KEY', 'Public key must be 32 bytes.')
  }
  if (plaintext.length > MAX_SEALED_PAYLOAD_BYTES) {
    throw new SealedBoxError('PAYLOAD_TOO_LARGE', 'Plaintext exceeds sealed-box limit.')
  }
  const sodium = await getSodium()
  // Copy into a fresh ArrayBuffer — jsdom TextEncoder views can trip libsodium type checks.
  return normalizeBytes(sodium.crypto_box_seal(normalizeBytes(plaintext), publicKey))
}

export async function openSealedBytes(
  ciphertext: Uint8Array,
  publicKey: Uint8Array,
  privateKey: Uint8Array
): Promise<Uint8Array> {
  if (publicKey.length !== X25519_KEY_BYTES || privateKey.length !== X25519_KEY_BYTES) {
    throw new SealedBoxError('INVALID_KEYPAIR', 'Public and private keys must be 32 bytes.')
  }
  const sodium = await getSodium()
  try {
    return normalizeBytes(sodium.crypto_box_seal_open(ciphertext, publicKey, privateKey))
  } catch {
    throw new SealedBoxError('OPEN_FAILED', 'Unable to open sealed payload with this keypair.')
  }
}
