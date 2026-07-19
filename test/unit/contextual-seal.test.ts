import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'
import { openContextualKey, sealContextualKey } from '../../src/contextual-seal.js'
import { SealedBoxError } from '../../src/errors.js'
import { generateKeypair, openSealedBytes, parsePublicKey, parseSealedKey } from '../../src/sealed-box.js'
import { SEALED_KEY_PREFIX } from '../../src/constants.js'

const fixturesDir = join(dirname(fileURLToPath(import.meta.url)), '../fixtures')
const golden = JSON.parse(readFileSync(join(fixturesDir, 'golden-vectors.json'), 'utf8'))

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

describe('contextual-seal', () => {
  it('locks contextual JSON wire shape including vaultId field', () => {
    const obj = JSON.parse(golden.contextual_json)
    expect(obj).toEqual(golden.contextual_json_object)
    expect(Object.keys(obj)).toEqual(['v', 'kind', 'vaultId', 'resourceId', 'key'])
    expect(golden.contextual_json).toContain('"vaultId"')
  })

  it('opens golden sealed envelope with matching context', async () => {
    const env = golden.sealed_envelope
    const key = await openContextualKey({
      envelope: env.envelope,
      privateKey: hexToBytes(env.private_key_hex),
      publicKey: parsePublicKey(env.public_key_envelope),
      scopeId: env.vault_id,
      resourceId: env.resource_id,
      kind: env.kind,
    })
    expect(Array.from(key)).toEqual(Array.from(hexToBytes(env.plaintext_key_hex)))
  })

  it('fails closed with CONTEXT_MISMATCH on wrong scopeId / resourceId / kind', async () => {
    const env = golden.sealed_envelope
    const base = {
      envelope: env.envelope,
      privateKey: hexToBytes(env.private_key_hex),
      publicKey: parsePublicKey(env.public_key_envelope),
      scopeId: env.vault_id,
      resourceId: env.resource_id,
      kind: env.kind,
    }

    await expect(openContextualKey({ ...base, scopeId: 'wrong-scope' })).rejects.toMatchObject({
      code: 'CONTEXT_MISMATCH',
    })
    await expect(openContextualKey({ ...base, resourceId: 'wrong-resource' })).rejects.toMatchObject({
      code: 'CONTEXT_MISMATCH',
    })
    await expect(openContextualKey({ ...base, kind: 'wrong-kind' })).rejects.toMatchObject({
      code: 'CONTEXT_MISMATCH',
    })
    await expect(openContextualKey({ ...base, scopeId: 'wrong-scope' })).rejects.toBeInstanceOf(
      SealedBoxError
    )
  })

  it('round-trips sealContextualKey / openContextualKey with opaque kind', async () => {
    const keypair = await generateKeypair()
    const key = crypto.getRandomValues(new Uint8Array(32))
    const kind = 'example-opaque-kind'
    const envelope = await sealContextualKey({
      kind,
      scopeId: 'scope-1',
      resourceId: 'res-1',
      key,
      publicKey: keypair.publicKey,
      keyId: keypair.keyId,
    })
    expect(envelope.startsWith(SEALED_KEY_PREFIX)).toBe(true)

    const opened = await openContextualKey({
      envelope,
      privateKey: keypair.privateKey,
      publicKey: keypair.publicKey,
      scopeId: 'scope-1',
      resourceId: 'res-1',
      kind,
    })
    expect(Array.from(opened)).toEqual(Array.from(key))

    // Wire payload uses vaultId for scopeId
    const { ciphertext } = parseSealedKey(envelope)
    const plaintext = await openSealedBytes(ciphertext, keypair.publicKey, keypair.privateKey)
    const parsed = JSON.parse(new TextDecoder().decode(plaintext))
    expect(parsed.vaultId).toBe('scope-1')
    expect(parsed.kind).toBe(kind)
  })
})
