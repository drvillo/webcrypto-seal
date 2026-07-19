/**
 * WASM-free + Argon2-free parse/format helpers for sealed envelopes.
 * Backs the `./wire` package subpath — safe for SSR/API routes.
 *
 * This module must stay free of sodium WASM and Argon2 hash imports.
 */

import {
  ENCRYPTED_PRIVATE_KEY_PREFIX,
  MAX_SEALED_PAYLOAD_BYTES,
  PUBLIC_KEY_PREFIX,
  SEALED_KEY_PREFIX,
  X25519_KEY_BYTES,
} from './constants.js'
import { fromBase64Url, toBase64Url } from './encoding.js'
import { SealedBoxError } from './errors.js'
import type { ParsedEncryptedPrivateKey, ParsedSealedKey } from './types.js'

export {
  ENCRYPTED_PRIVATE_KEY_PREFIX,
  PUBLIC_KEY_PREFIX,
  SEALED_KEY_PREFIX,
} from './constants.js'
export { SealedBoxError } from './errors.js'
export type { ParsedEncryptedPrivateKey, ParsedSealedKey } from './types.js'

function normalizeBytes(bytes: Uint8Array): Uint8Array {
  const copy = new Uint8Array(bytes.length)
  copy.set(bytes)
  return copy
}

export async function computeKeyId(publicKey: Uint8Array): Promise<string> {
  if (publicKey.length !== X25519_KEY_BYTES) {
    throw new SealedBoxError('INVALID_PUBLIC_KEY', 'Public key must be 32 bytes.')
  }
  const digest = await crypto.subtle.digest('SHA-256', normalizeBytes(publicKey) as BufferSource)
  return toBase64Url(new Uint8Array(digest))
}

export function formatPublicKey(publicKey: Uint8Array): string {
  if (publicKey.length !== X25519_KEY_BYTES) {
    throw new SealedBoxError('INVALID_PUBLIC_KEY', 'Public key must be 32 bytes.')
  }
  return `${PUBLIC_KEY_PREFIX}${toBase64Url(publicKey)}`
}

export function parsePublicKey(envelope: string): Uint8Array {
  if (!envelope.startsWith(PUBLIC_KEY_PREFIX)) {
    throw new SealedBoxError('INVALID_PREFIX', 'Public key envelope has invalid prefix.')
  }
  const encoded = envelope.slice(PUBLIC_KEY_PREFIX.length)
  return fromBase64Url(encoded, X25519_KEY_BYTES)
}

export async function validatePublicKeyFingerprint(publicKeyEnvelope: string): Promise<string> {
  const publicKey = parsePublicKey(publicKeyEnvelope)
  if (publicKey.every((byte) => byte === 0)) {
    throw new SealedBoxError('INVALID_PUBLIC_KEY', 'Public key is all zeros.')
  }
  return computeKeyId(publicKey)
}

export function formatSealedKey(ciphertext: Uint8Array, keyId: string): string {
  if (!keyId) {
    throw new SealedBoxError('INVALID_KEY_ID', 'Key ID is required.')
  }
  if (ciphertext.length === 0 || ciphertext.length > MAX_SEALED_PAYLOAD_BYTES) {
    throw new SealedBoxError('INVALID_CIPHERTEXT', 'Sealed ciphertext has invalid length.')
  }
  return `${SEALED_KEY_PREFIX}${keyId}.${toBase64Url(ciphertext)}`
}

export function parseSealedKey(envelope: string): ParsedSealedKey {
  if (!envelope.startsWith(SEALED_KEY_PREFIX)) {
    throw new SealedBoxError('INVALID_PREFIX', 'Sealed key envelope has invalid prefix.')
  }
  const body = envelope.slice(SEALED_KEY_PREFIX.length)
  const separatorIndex = body.indexOf('.')
  if (separatorIndex <= 0) {
    throw new SealedBoxError('INVALID_ENVELOPE', 'Sealed key envelope is malformed.')
  }
  const keyId = body.slice(0, separatorIndex)
  const encoded = body.slice(separatorIndex + 1)
  if (!keyId || !encoded) {
    throw new SealedBoxError('INVALID_ENVELOPE', 'Sealed key envelope is malformed.')
  }
  const ciphertext = fromBase64Url(encoded)
  if (ciphertext.length === 0 || ciphertext.length > MAX_SEALED_PAYLOAD_BYTES) {
    throw new SealedBoxError('INVALID_CIPHERTEXT', 'Sealed ciphertext has invalid length.')
  }
  return { keyId, ciphertext }
}

export function formatEncryptedPrivateKey(
  keyId: string,
  nonce: Uint8Array,
  ciphertextWithTag: Uint8Array
): string {
  if (!keyId) {
    throw new SealedBoxError('INVALID_KEY_ID', 'Key ID is required.')
  }
  if (nonce.length !== 12) {
    throw new SealedBoxError('INVALID_NONCE', 'Private-key nonce must be 12 bytes.')
  }
  if (ciphertextWithTag.length === 0) {
    throw new SealedBoxError('INVALID_CIPHERTEXT', 'Encrypted private key is empty.')
  }
  return `${ENCRYPTED_PRIVATE_KEY_PREFIX}${keyId}.${toBase64Url(nonce)}.${toBase64Url(ciphertextWithTag)}`
}

export function parseEncryptedPrivateKey(envelope: string): ParsedEncryptedPrivateKey {
  if (!envelope.startsWith(ENCRYPTED_PRIVATE_KEY_PREFIX)) {
    throw new SealedBoxError('INVALID_PREFIX', 'Encrypted private key envelope has invalid prefix.')
  }
  const body = envelope.slice(ENCRYPTED_PRIVATE_KEY_PREFIX.length)
  const firstDot = body.indexOf('.')
  const secondDot = body.indexOf('.', firstDot + 1)
  if (firstDot <= 0 || secondDot <= firstDot + 1 || secondDot === body.length - 1) {
    throw new SealedBoxError('INVALID_ENVELOPE', 'Encrypted private key envelope is malformed.')
  }
  const keyId = body.slice(0, firstDot)
  const nonce = fromBase64Url(body.slice(firstDot + 1, secondDot), 12)
  const ciphertextWithTag = fromBase64Url(body.slice(secondDot + 1))
  return { keyId, nonce, ciphertextWithTag }
}
