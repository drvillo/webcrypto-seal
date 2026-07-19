/**
 * AES-256-GCM payload encrypt/decrypt, key wrap, verifier, and secret-byte wrap helpers.
 * Canonical result shape is AesGcmResult — no product field names.
 */

import { SECRET_WRAP_INFO, VERIFIER_PLAINTEXT } from './constants.js'
import {
  base64ToUint8Array,
  computeChecksum,
  normalizeUint8Array,
  uint8ArrayToBase64,
} from './encoding.js'
import { VerifierMismatchError } from './errors.js'
import type { AesGcmResult } from './types.js'

export type { AesGcmResult } from './types.js'
export { computeChecksum }

export function generateSalt(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(16))
}

export function generateDek(): Uint8Array {
  const dek = new Uint8Array(32)
  crypto.getRandomValues(dek)
  return dek
}

export async function encryptPayload(
  plaintext: Uint8Array,
  dek: Uint8Array
): Promise<AesGcmResult> {
  const nonce = crypto.getRandomValues(new Uint8Array(12))
  const key = await crypto.subtle.importKey(
    'raw',
    normalizeUint8Array(dek),
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  )
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: normalizeUint8Array(nonce),
      tagLength: 128,
    },
    key,
    normalizeUint8Array(plaintext)
  )
  const ciphertextWithTag = new Uint8Array(ciphertext)
  const authTag = ciphertextWithTag.slice(-16)
  const ciphertextOnly = ciphertextWithTag.slice(0, -16)
  return { ciphertext: ciphertextOnly, nonce, authTag }
}

export async function decryptPayload(
  encrypted: AesGcmResult,
  dek: Uint8Array
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    'raw',
    normalizeUint8Array(dek),
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  )
  const ciphertextWithTag = new Uint8Array(encrypted.ciphertext.length + encrypted.authTag.length)
  ciphertextWithTag.set(encrypted.ciphertext)
  ciphertextWithTag.set(encrypted.authTag, encrypted.ciphertext.length)
  const plaintext = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: normalizeUint8Array(encrypted.nonce),
      tagLength: 128,
    },
    key,
    ciphertextWithTag
  )
  return new Uint8Array(plaintext)
}

export async function wrapKey(keyBytes: Uint8Array, wrappingKey: Uint8Array): Promise<AesGcmResult> {
  const nonce = crypto.getRandomValues(new Uint8Array(12))
  const key = await crypto.subtle.importKey(
    'raw',
    normalizeUint8Array(wrappingKey),
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  )
  const encrypted = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: normalizeUint8Array(nonce),
      tagLength: 128,
    },
    key,
    normalizeUint8Array(keyBytes)
  )
  const encryptedWithTag = new Uint8Array(encrypted)
  const authTag = encryptedWithTag.slice(-16)
  const ciphertext = encryptedWithTag.slice(0, -16)
  return { ciphertext, nonce, authTag }
}

export async function unwrapKey(encrypted: AesGcmResult, wrappingKey: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    'raw',
    normalizeUint8Array(wrappingKey),
    { name: 'AES-GCM' },
    false,
    ['decrypt']
  )
  const encryptedWithTag = new Uint8Array(encrypted.ciphertext.length + encrypted.authTag.length)
  encryptedWithTag.set(encrypted.ciphertext)
  encryptedWithTag.set(encrypted.authTag, encrypted.ciphertext.length)
  const unwrapped = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: normalizeUint8Array(encrypted.nonce),
      tagLength: 128,
    },
    key,
    encryptedWithTag
  )
  return new Uint8Array(unwrapped)
}

export async function createVerifier(key: Uint8Array): Promise<string> {
  const nonce = crypto.getRandomValues(new Uint8Array(12))
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    normalizeUint8Array(key),
    { name: 'AES-GCM' },
    false,
    ['encrypt']
  )
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: normalizeUint8Array(nonce), tagLength: 128 },
    cryptoKey,
    normalizeUint8Array(VERIFIER_PLAINTEXT)
  )
  const encryptedWithTag = new Uint8Array(encrypted)
  const out = new Uint8Array(nonce.length + encryptedWithTag.length)
  out.set(nonce, 0)
  out.set(encryptedWithTag, nonce.length)
  return uint8ArrayToBase64(out)
}

export async function verifyWithVerifier(
  key: Uint8Array,
  verifierCiphertextBase64: string
): Promise<void> {
  let verifierBytes: Uint8Array
  try {
    verifierBytes = base64ToUint8Array(verifierCiphertextBase64)
  } catch {
    throw new VerifierMismatchError()
  }

  const nonceLength = 12
  const minLength = nonceLength + 16 + 1
  if (verifierBytes.length < minLength) throw new VerifierMismatchError()

  const nonce = verifierBytes.slice(0, nonceLength)
  const ciphertextWithTag = verifierBytes.slice(nonceLength)

  try {
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      normalizeUint8Array(key),
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    )
    await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: normalizeUint8Array(nonce), tagLength: 128 },
      cryptoKey,
      ciphertextWithTag
    )
  } catch {
    throw new VerifierMismatchError()
  }
}

/**
 * Derive a 32-byte wrapping key from secret bytes via HKDF-SHA256
 * with frozen info = SECRET_WRAP_INFO (`lsk-wrap`).
 */
export async function deriveWrapKeyFromSecret(
  secretBytes: Uint8Array,
  salt: Uint8Array
): Promise<Uint8Array> {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    normalizeUint8Array(secretBytes),
    { name: 'HKDF' },
    false,
    ['deriveBits']
  )
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      salt: normalizeUint8Array(salt),
      info: SECRET_WRAP_INFO,
      hash: 'SHA-256',
    },
    baseKey,
    256
  )
  return normalizeUint8Array(new Uint8Array(bits))
}

export async function wrapKeyWithSecret(
  keyBytes: Uint8Array,
  secretBytes: Uint8Array,
  salt: Uint8Array
): Promise<AesGcmResult> {
  const wrapKeyBytes = await deriveWrapKeyFromSecret(secretBytes, salt)
  return wrapKey(keyBytes, wrapKeyBytes)
}

export async function unwrapKeyWithSecret(
  encrypted: AesGcmResult,
  secretBytes: Uint8Array,
  salt: Uint8Array
): Promise<Uint8Array> {
  const wrapKeyBytes = await deriveWrapKeyFromSecret(secretBytes, salt)
  return unwrapKey(encrypted, wrapKeyBytes)
}
