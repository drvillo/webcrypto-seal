/**
 * Offline-consumer contract proof (SC-4, D-06).
 *
 * Node ≥20 required: global Web Crypto + base64 (btoa/atob) APIs.
 *
 * openContextualKey input contract:
 *   { envelope, privateKey, publicKey, scopeId, resourceId, kind }
 *   → key bytes | throws CONTEXT_MISMATCH
 *
 * No network calls; no analytics.
 * Offline seal/open depends on lazy libsodium WASM loading under headless Node.
 */
// @vitest-environment node

import { describe, expect, it } from 'vitest'
import {
  createVerifier,
  decryptBytesFromSealedUpload,
  deriveMasterKey,
  encryptBytesForSealedUpload,
  generateKeypair,
  openContextualKey,
  sealContextualKey,
  SEALED_KEY_PREFIX,
  VerifierMismatchError,
  verifyWithVerifier,
} from '../../src/index.js'
// Parse-only via WASM-free ./wire subpath — call before any seal/keypair.
import { formatPublicKey, parsePublicKey, parseSealedKey } from '../../src/wire.js'

describe('node offline consumer', () => {
  it('runs without window', () => {
    expect(typeof window).toBe('undefined')
  })

  it('parse-only via /wire path before any seal', () => {
    // Package consumers import `@drvillo/webcrypto-seal/wire`
    expect('@drvillo/webcrypto-seal/wire').toContain('/wire')
    const publicKey = crypto.getRandomValues(new Uint8Array(32))
    const envelope = formatPublicKey(publicKey)
    expect(parsePublicKey(envelope)).toEqual(publicKey)
  })

  it('deriveMasterKey works without a Worker', async () => {
    const salt = crypto.getRandomValues(new Uint8Array(16))
    const master = await deriveMasterKey('offline-password', salt, {
      memory: 1024,
      time: 1,
      parallelism: 1,
    })
    expect(master.length).toBe(32)
  })

  it('generateKeypair + sealContextualKey + openContextualKey round-trip under Node', async () => {
    const keypair = await generateKeypair()
    const key = crypto.getRandomValues(new Uint8Array(32))
    const kind = 'offline-kind'
    const envelope = await sealContextualKey({
      kind,
      scopeId: 'offline-scope',
      resourceId: 'offline-resource',
      key,
      publicKey: keypair.publicKey,
      keyId: keypair.keyId,
    })
    const opened = await openContextualKey({
      envelope,
      privateKey: keypair.privateKey,
      publicKey: keypair.publicKey,
      scopeId: 'offline-scope',
      resourceId: 'offline-resource',
      kind,
    })
    expect(Array.from(opened)).toEqual(Array.from(key))
  })

  it('openContextualKey fails closed with CONTEXT_MISMATCH on wrong context', async () => {
    const keypair = await generateKeypair()
    const key = crypto.getRandomValues(new Uint8Array(32))
    const kind = 'offline-kind'
    const envelope = await sealContextualKey({
      kind,
      scopeId: 'offline-scope',
      resourceId: 'offline-resource',
      key,
      publicKey: keypair.publicKey,
      keyId: keypair.keyId,
    })
    await expect(
      openContextualKey({
        envelope,
        privateKey: keypair.privateKey,
        publicKey: keypair.publicKey,
        scopeId: 'wrong-scope',
        resourceId: 'offline-resource',
        kind,
      })
    ).rejects.toMatchObject({ code: 'CONTEXT_MISMATCH' })
  })

  it('createVerifier + verifyWithVerifier reject wrong key with VerifierMismatchError', async () => {
    const salt = new Uint8Array(16).fill(3)
    const key = await deriveMasterKey('correct', salt, { memory: 1024, time: 1, parallelism: 1 })
    const wrong = await deriveMasterKey('wrong', salt, { memory: 1024, time: 1, parallelism: 1 })
    const verifier = await createVerifier(key)
    await expect(verifyWithVerifier(key, verifier)).resolves.toBeUndefined()
    await expect(verifyWithVerifier(wrong, verifier)).rejects.toBeInstanceOf(VerifierMismatchError)
  })

  it('encryptBytesForSealedUpload with explicit kind seals and decrypts', async () => {
    const keypair = await generateKeypair()
    const plaintext = new TextEncoder().encode('offline-file-bytes')
    const kind = 'offline-upload-kind'
    const result = await encryptBytesForSealedUpload(plaintext, {
      publicKey: keypair.publicKey,
      keyId: keypair.keyId,
      scopeId: 'offline-scope',
      resourceId: 'offline-doc',
      kind,
    })
    expect(result.sealedKey.startsWith(SEALED_KEY_PREFIX)).toBe(true)
    expect(result.sealedKey.startsWith('v3.sb1.')).toBe(true)
    const parsed = parseSealedKey(result.sealedKey)
    expect(parsed.keyId).toBe(keypair.keyId)

    const decrypted = await decryptBytesFromSealedUpload(result.ciphertext, {
      privateKey: keypair.privateKey,
      publicKey: keypair.publicKey,
      scopeId: 'offline-scope',
      resourceId: 'offline-doc',
      kind,
      sealedKey: result.sealedKey,
    })
    expect(Array.from(decrypted)).toEqual(Array.from(plaintext))
  })
})
