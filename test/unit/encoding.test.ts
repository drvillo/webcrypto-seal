import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import {
  base64ToUint8Array,
  computeChecksum,
  fromBase64Url,
  toBase64Url,
  uint8ArrayToBase64,
} from '../../src/encoding.js'

const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), '../fixtures')
const golden = JSON.parse(readFileSync(join(fixturesDir, 'golden-vectors.json'), 'utf8'))

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

describe('encoding', () => {
  it('reproduces encoding_edge base64url and standard base64', () => {
    const edge = golden.encoding_edge
    const input = hexToBytes(edge.input_hex)
    expect(uint8ArrayToBase64(input)).toBe(edge.standard_base64_with_plus_slash)
    expect(toBase64Url(input)).toBe(edge.canonical_base64url)
    expect(fromBase64Url(edge.canonical_base64url)).toEqual(input)
  })

  it('reproduces large-array standard base64 with 8192 chunking', () => {
    const edge = golden.encoding_edge
    const large = new Uint8Array(edge.large_input_len)
    for (let i = 0; i < large.length; i++) large[i] = (i * 17 + 3) % 256
    expect(Array.from(large.slice(0, 32)).map((b) => b.toString(16).padStart(2, '0')).join('')).toBe(
      edge.large_input_hex_prefix
    )
    expect(uint8ArrayToBase64(large)).toBe(edge.large_standard_base64)
  })

  it('reproduces verifier_pack standard base64 packing', () => {
    const pack = golden.verifier_pack
    const bytes = hexToBytes(pack.nonce_ciphertext_tag_hex)
    expect(uint8ArrayToBase64(bytes)).toBe(pack.standard_base64)
    expect(base64ToUint8Array(pack.standard_base64)).toEqual(bytes)
  })

  it('reproduces checksum lowercase hex', async () => {
    const checksum = await computeChecksum(hexToBytes(golden.checksum.packed_hex))
    expect(checksum).toBe(golden.checksum.sha256_lowercase_hex)
  })

  it('round-trips empty and small arrays', () => {
    const empty = new Uint8Array([])
    expect(base64ToUint8Array(uint8ArrayToBase64(empty))).toEqual(empty)
    const small = new Uint8Array([1, 2, 3, 4, 5])
    expect(base64ToUint8Array(uint8ArrayToBase64(small))).toEqual(small)
  })
})
