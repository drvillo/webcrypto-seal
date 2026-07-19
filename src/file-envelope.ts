/**
 * File ciphertext packing: ciphertext ‖ nonce(12) ‖ tag(16), plus sealed upload helpers.
 * Callers must supply an opaque `kind` — nothing is hard-coded here.
 */

import { decryptPayload, encryptPayload, generateDek } from './aes-gcm.js'
import { computeChecksum } from './encoding.js'
import type { AesGcmResult } from './types.js'
import { openContextualKey, sealContextualKey } from './contextual-seal.js'

const NONCE_LENGTH = 12
const AUTH_TAG_LENGTH = 16

export function packCiphertextEnvelope(encrypted: AesGcmResult): Uint8Array {
  const packed = new Uint8Array(
    encrypted.ciphertext.length + encrypted.nonce.length + encrypted.authTag.length
  )
  packed.set(encrypted.ciphertext)
  packed.set(encrypted.nonce, encrypted.ciphertext.length)
  packed.set(encrypted.authTag, encrypted.ciphertext.length + encrypted.nonce.length)
  return packed
}

export function unpackCiphertextEnvelope(packed: Uint8Array): AesGcmResult {
  const ciphertextOnly = packed.slice(0, -(NONCE_LENGTH + AUTH_TAG_LENGTH))
  const nonce = packed.slice(-(NONCE_LENGTH + AUTH_TAG_LENGTH), -AUTH_TAG_LENGTH)
  const authTag = packed.slice(-AUTH_TAG_LENGTH)
  return { ciphertext: ciphertextOnly, nonce, authTag }
}

export interface EncryptBytesForSealedUploadInput {
  publicKey: Uint8Array
  keyId: string
  scopeId: string
  resourceId: string
  /** Opaque caller-supplied kind — required; never hard-coded by the package. */
  kind: string
}

export interface EncryptBytesForSealedUploadResult {
  ciphertext: Uint8Array
  sealedKey: string
  ciphertextChecksum: string
}

export async function encryptBytesForSealedUpload(
  plaintext: Uint8Array,
  input: EncryptBytesForSealedUploadInput
): Promise<EncryptBytesForSealedUploadResult> {
  const dek = generateDek()
  const encrypted = await encryptPayload(plaintext, dek)
  const ciphertext = packCiphertextEnvelope(encrypted)
  const ciphertextChecksum = await computeChecksum(ciphertext)
  const sealedKey = await sealContextualKey({
    kind: input.kind,
    scopeId: input.scopeId,
    resourceId: input.resourceId,
    key: dek,
    publicKey: input.publicKey,
    keyId: input.keyId,
  })
  return { ciphertext, sealedKey, ciphertextChecksum }
}

export interface DecryptBytesFromSealedUploadInput {
  privateKey: Uint8Array
  publicKey: Uint8Array
  scopeId: string
  resourceId: string
  kind: string
  sealedKey: string
}

export async function decryptBytesFromSealedUpload(
  packedCiphertext: Uint8Array,
  input: DecryptBytesFromSealedUploadInput
): Promise<Uint8Array> {
  const dek = await openContextualKey({
    kind: input.kind,
    scopeId: input.scopeId,
    resourceId: input.resourceId,
    envelope: input.sealedKey,
    privateKey: input.privateKey,
    publicKey: input.publicKey,
  })
  return decryptPayload(unpackCiphertextEnvelope(packedCiphertext), dek)
}
