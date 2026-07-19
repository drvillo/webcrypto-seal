import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import {
  deriveWrapKeyFromSecret,
  unwrapKeyWithSecret,
  wrapKeyWithSecret,
} from '../../src/aes-gcm.js'
import { SECRET_WRAP_INFO } from '../../src/constants.js'

const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), '../fixtures')
const golden = JSON.parse(readFileSync(join(fixturesDir, 'golden-vectors.json'), 'utf8'))

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

describe('wrap-with-secret', () => {
  it('locks SECRET_WRAP_INFO to UTF-8 lsk-wrap', () => {
    expect(new TextDecoder().decode(SECRET_WRAP_INFO)).toBe('lsk-wrap')
    expect(golden.secret_wrap.hkdf_info_utf8).toBe('lsk-wrap')
  })

  it('deriveWrapKeyFromSecret returns 32-byte Uint8Array', async () => {
    const v = golden.secret_wrap
    const wrapKey = await deriveWrapKeyFromSecret(
      hexToBytes(v.vendor_secret_hex),
      hexToBytes(v.salt_hex)
    )
    expect(wrapKey).toBeInstanceOf(Uint8Array)
    expect(wrapKey.length).toBe(32)
  })

  it('unwraps golden secret_wrap ciphertext via unwrapKeyWithSecret', async () => {
    const v = golden.secret_wrap
    const ciphertextTag = hexToBytes(v.ciphertext_tag_hex)
    const authTag = ciphertextTag.slice(-16)
    const ciphertext = ciphertextTag.slice(0, -16)
    const unwrapped = await unwrapKeyWithSecret(
      { ciphertext, nonce: hexToBytes(v.nonce_hex), authTag },
      hexToBytes(v.vendor_secret_hex),
      hexToBytes(v.salt_hex)
    )
    expect(Array.from(unwrapped)).toEqual(Array.from(hexToBytes(v.lsk_hex)))
  })

  it('round-trips via wrapKeyWithSecret / unwrapKeyWithSecret', async () => {
    const secret = crypto.getRandomValues(new Uint8Array(32))
    const salt = crypto.getRandomValues(new Uint8Array(16))
    const keyBytes = crypto.getRandomValues(new Uint8Array(32))
    const wrapped = await wrapKeyWithSecret(keyBytes, secret, salt)
    expect(wrapped.ciphertext.length).toBe(32)
    expect(wrapped.nonce.length).toBe(12)
    expect(wrapped.authTag.length).toBe(16)
    expect('encryptedDek' in wrapped).toBe(false)
    const unwrapped = await unwrapKeyWithSecret(wrapped, secret, salt)
    expect(unwrapped).toEqual(keyBytes)
  })
})
