import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { encryptPayload } from '../../src/aes-gcm.js'
import { SEALED_KEY_PREFIX } from '../../src/constants.js'
import { computeChecksum } from '../../src/encoding.js'
import {
  decryptBytesFromSealedUpload,
  encryptBytesForSealedUpload,
  packCiphertextEnvelope,
  unpackCiphertextEnvelope,
} from '../../src/file-envelope.js'
import { generateKeypair } from '../../src/sealed-box.js'

const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), '../fixtures')
const golden = JSON.parse(readFileSync(join(fixturesDir, 'golden-vectors.json'), 'utf8'))

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

describe('file-envelope', () => {
  it('locks packed length rule and checksum against golden file_pack', async () => {
    const packed = hexToBytes(golden.file_pack.packed_hex)
    expect(packed.length).toBe(golden.file_pack.packed_len)
    expect(packed.length).toBe(
      golden.file_pack.ciphertext_len + golden.file_pack.nonce_len + golden.file_pack.tag_len
    )
    expect(await computeChecksum(packed)).toBe(golden.file_pack.checksum_hex)

    const unpacked = unpackCiphertextEnvelope(packed)
    expect(unpacked.ciphertext.length).toBe(golden.file_pack.ciphertext_len)
    expect(unpacked.nonce.length).toBe(12)
    expect(unpacked.authTag.length).toBe(16)
    expect(packCiphertextEnvelope(unpacked)).toEqual(packed)
  })

  it('packCiphertextEnvelope follows ciphertext ‖ nonce(12) ‖ tag(16)', async () => {
    const plaintext = hexToBytes(golden.file_pack.plaintext_hex)
    const dek = hexToBytes(golden.file_pack.dek_hex)
    // Random nonce — assert structural rules, not golden packed_hex
    const encrypted = await encryptPayload(plaintext, dek)
    const packed = packCiphertextEnvelope(encrypted)
    expect(packed.length).toBe(encrypted.ciphertext.length + 12 + 16)
    expect(unpackCiphertextEnvelope(packed)).toEqual(encrypted)
  })

  it('encryptBytesForSealedUpload requires explicit kind and round-trips', async () => {
    const keypair = await generateKeypair()
    const plaintext = new TextEncoder().encode('sealed-upload-bytes-v1')
    const kind = 'example-upload-kind'
    const result = await encryptBytesForSealedUpload(plaintext, {
      publicKey: keypair.publicKey,
      keyId: keypair.keyId,
      scopeId: 'scope-upload',
      resourceId: 'res-upload',
      kind,
    })
    expect(result.sealedKey.startsWith(SEALED_KEY_PREFIX)).toBe(true)
    expect(result.ciphertextChecksum).toBe(await computeChecksum(result.ciphertext))

    const decrypted = await decryptBytesFromSealedUpload(result.ciphertext, {
      privateKey: keypair.privateKey,
      publicKey: keypair.publicKey,
      scopeId: 'scope-upload',
      resourceId: 'res-upload',
      kind,
      sealedKey: result.sealedKey,
    })
    expect(Array.from(decrypted)).toEqual(Array.from(plaintext))
  })
})
