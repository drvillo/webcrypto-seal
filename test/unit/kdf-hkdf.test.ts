import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { HIERARCHICAL_KEK_INFO } from '../../src/constants.js'
import { deriveChildKey } from '../../src/hierarchical.js'
import { DEFAULT_KDF_PARAMS, deriveMasterKey, type KdfParams } from '../../src/kdf.js'
import { generateSalt } from '../../src/aes-gcm.js'

const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), '../fixtures')
const golden = JSON.parse(readFileSync(join(fixturesDir, 'golden-vectors.json'), 'utf8'))

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

describe('kdf / hierarchical', () => {
  const testPassword = 'test-password-12345'
  const testKdfParams: KdfParams = {
    memory: 65536,
    time: 3,
    parallelism: 4,
  }

  it('locks DEFAULT_KDF_PARAMS against golden fixtures', () => {
    expect(DEFAULT_KDF_PARAMS).toEqual({
      memory: golden.kdf.DEFAULT_KDF_PARAMS.memory,
      time: golden.kdf.DEFAULT_KDF_PARAMS.time,
      parallelism: golden.kdf.DEFAULT_KDF_PARAMS.parallelism,
    })
  })

  it('reproduces golden Argon2id master key', async () => {
    const v = golden.kdf.argon2id_vector
    const master = await deriveMasterKey(v.password, hexToBytes(v.salt_hex), {
      memory: v.params.memory,
      time: v.params.time,
      parallelism: v.params.parallelism,
    })
    expect(bytesToHex(master)).toBe(v.master_key_hex)
  }, 60000)

  it('reproduces golden HKDF child key', async () => {
    const v = golden.hkdf
    const child = await deriveChildKey(hexToBytes(v.master_key_hex), hexToBytes(v.salt_hex))
    expect(bytesToHex(child)).toBe(v.child_key_hex)
    expect(new TextDecoder().decode(HIERARCHICAL_KEK_INFO)).toBe(v.info_utf8)
  })

  it('deriveMasterKey is deterministic for same password/salt', async () => {
    const salt = generateSalt()
    const a = await deriveMasterKey(testPassword, salt, testKdfParams)
    const b = await deriveMasterKey(testPassword, salt, testKdfParams)
    expect(a).toEqual(b)
    expect(a.length).toBe(32)
  }, 30000)

  it('deriveChildKey is deterministic', async () => {
    const master = await deriveMasterKey(testPassword, generateSalt(), testKdfParams)
    const salt = generateSalt()
    const a = await deriveChildKey(master, salt)
    const b = await deriveChildKey(master, salt)
    expect(a).toEqual(b)
    expect(a.length).toBe(32)
  }, 30000)
})
