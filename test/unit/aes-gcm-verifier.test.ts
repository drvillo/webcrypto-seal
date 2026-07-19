import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import {
  createVerifier,
  decryptPayload,
  encryptPayload,
  generateDek,
  generateSalt,
  unwrapKey,
  verifyWithVerifier,
  wrapKey,
} from '../../src/aes-gcm.js'
import { base64ToUint8Array, uint8ArrayToBase64 } from '../../src/encoding.js'
import { VerifierMismatchError } from '../../src/errors.js'
import { deriveMasterKey } from '../../src/kdf.js'

const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), '../fixtures')
const golden = JSON.parse(readFileSync(join(fixturesDir, 'golden-vectors.json'), 'utf8'))

describe('aes-gcm / verifier', () => {
  it('encryptPayload / decryptPayload round-trip with AesGcmResult shape', async () => {
    const plaintext = new TextEncoder().encode('Hello, World!')
    const dek = generateDek()
    const encrypted = await encryptPayload(plaintext, dek)
    expect(encrypted.ciphertext).toBeDefined()
    expect(encrypted.nonce.length).toBe(12)
    expect(encrypted.authTag.length).toBe(16)
    expect('encryptedDek' in encrypted).toBe(false)
    const decrypted = await decryptPayload(encrypted, dek)
    expect(Array.from(decrypted)).toEqual(Array.from(plaintext))
  })

  it('wrapKey / unwrapKey round-trip with same AesGcmResult shape', async () => {
    const keyBytes = generateDek()
    const wrappingKey = generateDek()
    const wrapped = await wrapKey(keyBytes, wrappingKey)
    expect(wrapped.ciphertext).toBeDefined()
    expect(wrapped.nonce.length).toBe(12)
    expect(wrapped.authTag.length).toBe(16)
    expect('encryptedDek' in wrapped).toBe(false)
    const unwrapped = await unwrapKey(wrapped, wrappingKey)
    expect(unwrapped).toEqual(keyBytes)
  })

  it('fails to decrypt with wrong key', async () => {
    const plaintext = new TextEncoder().encode('Test message')
    const encrypted = await encryptPayload(plaintext, generateDek())
    await expect(decryptPayload(encrypted, generateDek())).rejects.toThrow()
  })

  it('encryptPayload produces different ciphertexts for the same plaintext and key', async () => {
    const plaintext = new TextEncoder().encode('Test message')
    const dek = generateDek()
    const encrypted1 = await encryptPayload(plaintext, dek)
    const encrypted2 = await encryptPayload(plaintext, dek)
    expect(encrypted1.nonce).not.toEqual(encrypted2.nonce)
    expect(encrypted1.ciphertext).not.toEqual(encrypted2.ciphertext)
  })

  it('generateDek produces 32 random bytes', () => {
    const a = generateDek()
    const b = generateDek()
    expect(a.length).toBe(32)
    expect(a).not.toEqual(b)
  })

  it('verifies correct key and rejects wrong key with VerifierMismatchError', async () => {
    const params = { memory: 1024, time: 1, parallelism: 1 }
    const salt = new Uint8Array(16).fill(7)
    const key = await deriveMasterKey('correct-password', salt, params)
    const wrongKey = await deriveMasterKey('wrong-password', salt, params)
    const verifier = await createVerifier(key)
    await expect(verifyWithVerifier(key, verifier)).resolves.toBeUndefined()
    await expect(verifyWithVerifier(wrongKey, verifier)).rejects.toBeInstanceOf(VerifierMismatchError)
  })

  it('rejects tampered and truncated verifier ciphertext', async () => {
    const params = { memory: 1024, time: 1, parallelism: 1 }
    const salt = new Uint8Array(16).fill(9)
    const key = await deriveMasterKey('correct-password', salt, params)
    const verifier = await createVerifier(key)

    const bytes = base64ToUint8Array(verifier)
    bytes[20] = bytes[20] ^ 0xff
    await expect(verifyWithVerifier(key, uint8ArrayToBase64(bytes))).rejects.toBeInstanceOf(
      VerifierMismatchError
    )

    const truncated = uint8ArrayToBase64(base64ToUint8Array(verifier).slice(0, 20))
    await expect(verifyWithVerifier(key, truncated)).rejects.toBeInstanceOf(VerifierMismatchError)
  })

  it('locks verifier domain separator bytes', () => {
    expect(golden.domain_separators.verifier_utf8).toBe('1bridge-vault-verifier-v1')
  })

  it('generateSalt produces 16 random bytes', () => {
    const a = generateSalt()
    const b = generateSalt()
    expect(a.length).toBe(16)
    expect(a).not.toEqual(b)
  })
})
