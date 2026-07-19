import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import {
  ENCRYPTED_PRIVATE_KEY_PREFIX,
  PUBLIC_KEY_PREFIX,
  SEALED_KEY_PREFIX,
  SealedBoxError,
  computeKeyId,
  formatEncryptedPrivateKey,
  formatPublicKey,
  formatSealedKey,
  fromBase64Url,
  generateKeypair,
  openSealedBytes,
  parseEncryptedPrivateKey,
  parsePublicKey,
  parseSealedKey,
  sealBytes,
  toBase64Url,
  validatePublicKeyFingerprint,
} from '../../src/sealed-box.js'

const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), '../fixtures')
const golden = JSON.parse(readFileSync(join(fixturesDir, 'golden-vectors.json'), 'utf8'))

describe('sealed-box', () => {
  describe('generateKeypair', () => {
    it('generates a 32-byte X25519 keypair with envelope and fingerprint', async () => {
      const keypair = await generateKeypair()
      expect(keypair.publicKey.length).toBe(32)
      expect(keypair.privateKey.length).toBe(32)
      expect(keypair.publicKeyEnvelope.startsWith(PUBLIC_KEY_PREFIX)).toBe(true)
      expect(keypair.keyId).toBe(await computeKeyId(keypair.publicKey))
      expect(keypair.keyId.length).toBe(43)
    })
  })

  describe('sealBytes / openSealedBytes', () => {
    it('round-trips a 32-byte payload', async () => {
      const keypair = await generateKeypair()
      const dek = crypto.getRandomValues(new Uint8Array(32))
      const sealed = await sealBytes(dek, keypair.publicKey)
      expect(sealed.length).toBe(80)
      const opened = await openSealedBytes(sealed, keypair.publicKey, keypair.privateKey)
      expect(opened).toEqual(dek)
    })

    it('fails to open with a different keypair', async () => {
      const keypairA = await generateKeypair()
      const keypairB = await generateKeypair()
      const dek = crypto.getRandomValues(new Uint8Array(32))
      const sealed = await sealBytes(dek, keypairA.publicKey)
      await expect(
        openSealedBytes(sealed, keypairB.publicKey, keypairB.privateKey)
      ).rejects.toBeInstanceOf(SealedBoxError)
    })

    it('fails to open tampered ciphertext', async () => {
      const keypair = await generateKeypair()
      const dek = crypto.getRandomValues(new Uint8Array(32))
      const sealed = await sealBytes(dek, keypair.publicKey)
      sealed[0] ^= 0xff
      await expect(
        openSealedBytes(sealed, keypair.publicKey, keypair.privateKey)
      ).rejects.toBeInstanceOf(SealedBoxError)
    })
  })

  describe('formatSealedKey / parseSealedKey', () => {
    it('round-trips sealed key envelopes with v3.sb1 prefix', async () => {
      const keypair = await generateKeypair()
      const dek = crypto.getRandomValues(new Uint8Array(32))
      const sealed = await sealBytes(dek, keypair.publicKey)
      const envelope = formatSealedKey(sealed, keypair.keyId)
      expect(envelope.startsWith(SEALED_KEY_PREFIX)).toBe(true)
      const parsed = parseSealedKey(envelope)
      expect(parsed.keyId).toBe(keypair.keyId)
      expect(parsed.ciphertext).toEqual(sealed)
      const opened = await openSealedBytes(parsed.ciphertext, keypair.publicKey, keypair.privateKey)
      expect(opened).toEqual(dek)
    })

    it('rejects malformed sealed key envelopes', () => {
      expect(() => parseSealedKey('v2.sb1.bad')).toThrow(SealedBoxError)
      expect(() => parseSealedKey('v3.sb1.only-key-id')).toThrow(SealedBoxError)
    })

    it('locks golden prefixes and sealed envelope format', () => {
      expect(PUBLIC_KEY_PREFIX).toBe(golden.prefixes.PUBLIC_KEY_PREFIX)
      expect(SEALED_KEY_PREFIX).toBe(golden.prefixes.SEALED_DEK_PREFIX)
      expect(ENCRYPTED_PRIVATE_KEY_PREFIX).toBe(golden.prefixes.ENCRYPTED_PRIVATE_KEY_PREFIX)
      const parsed = parseSealedKey(golden.sealed_envelope.format_sealed_dek_envelope)
      expect(parsed.keyId).toBe(golden.sealed_envelope.key_id)
    })
  })

  describe('public key envelopes', () => {
    it('formats and parses v3.x25519 public keys', async () => {
      const keypair = await generateKeypair()
      const parsed = parsePublicKey(keypair.publicKeyEnvelope)
      expect(parsed).toEqual(keypair.publicKey)
    })

    it('validates public key fingerprint', async () => {
      const keypair = await generateKeypair()
      const keyId = await validatePublicKeyFingerprint(keypair.publicKeyEnvelope)
      expect(keyId).toBe(keypair.keyId)
    })

    it('rejects invalid public key prefix', async () => {
      await expect(validatePublicKeyFingerprint('v2.x25519.abc')).rejects.toBeInstanceOf(SealedBoxError)
    })
  })

  describe('encrypted private key envelopes', () => {
    it('round-trips v3.a256gcm envelopes', () => {
      const keyId = 'test-key-id'
      const nonce = crypto.getRandomValues(new Uint8Array(12))
      const ciphertextWithTag = crypto.getRandomValues(new Uint8Array(48))
      const envelope = formatEncryptedPrivateKey(keyId, nonce, ciphertextWithTag)
      expect(envelope.startsWith(ENCRYPTED_PRIVATE_KEY_PREFIX)).toBe(true)
      const parsed = parseEncryptedPrivateKey(envelope)
      expect(parsed.keyId).toBe(keyId)
      expect(parsed.nonce).toEqual(nonce)
      expect(parsed.ciphertextWithTag).toEqual(ciphertextWithTag)
    })

    it('rejects non-canonical base64url in sealed key parse', () => {
      expect(() => parseSealedKey('v3.sb1.key-id.A+B')).toThrow(SealedBoxError)
    })
  })

  describe('base64url helpers', () => {
    it('encodes and decodes canonical base64url', () => {
      const bytes = crypto.getRandomValues(new Uint8Array(32))
      const encoded = toBase64Url(bytes)
      expect(encoded).not.toMatch(/[+/=]/)
      expect(fromBase64Url(encoded, 32)).toEqual(bytes)
    })
  })
})
