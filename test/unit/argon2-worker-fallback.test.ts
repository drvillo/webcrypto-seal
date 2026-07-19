/**
 * Worker failure surfaces a typed error; sync deriveMasterKey remains the golden path.
 * No Vercel analytics — package must never depend on track().
 */
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  Argon2WorkerError,
  deriveMasterKeyInWorker,
  terminateArgon2Worker,
} from '../../src/argon2-worker/client.js'
import { deriveMasterKey } from '../../src/kdf.js'

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

describe('argon2-worker fallback', () => {
  beforeEach(() => {
    terminateArgon2Worker()
  })

  afterEach(() => {
    terminateArgon2Worker()
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  })

  it('rejects with Argon2WorkerError when Worker is unavailable', async () => {
    vi.stubGlobal('window', globalThis)
    vi.stubGlobal('Worker', undefined)

    await expect(
      deriveMasterKeyInWorker('password', new Uint8Array(16), {
        memory: 1024,
        time: 1,
        parallelism: 1,
      })
    ).rejects.toSatisfy(
      (err: unknown) =>
        err instanceof Argon2WorkerError && err.reason === 'Argon2 worker unavailable'
    )
  })

  it('sync deriveMasterKey still matches golden when worker path fails', async () => {
    vi.stubGlobal('window', globalThis)
    vi.stubGlobal('Worker', undefined)

    await expect(
      deriveMasterKeyInWorker('x', new Uint8Array(16), {
        memory: 1024,
        time: 1,
        parallelism: 1,
      })
    ).rejects.toBeInstanceOf(Argon2WorkerError)

    const v = golden.kdf.argon2id_vector
    const master = await deriveMasterKey(v.password, hexToBytes(v.salt_hex), {
      memory: v.params.memory,
      time: v.params.time,
      parallelism: v.params.parallelism,
    })
    expect(bytesToHex(master)).toBe(v.master_key_hex)
  }, 60000)

  it('src has zero @vercel/analytics / track( usage', async () => {
    const { readdirSync, readFileSync: read, statSync } = await import('node:fs')
    const srcRoot = join(dirname(fileURLToPath(import.meta.url)), '../../src')

    function walk(dir: string): string[] {
      const out: string[] = []
      for (const name of readdirSync(dir)) {
        const path = join(dir, name)
        if (statSync(path).isDirectory()) out.push(...walk(path))
        else if (name.endsWith('.ts')) out.push(path)
      }
      return out
    }

    const hits: string[] = []
    for (const file of walk(srcRoot)) {
      const text = read(file, 'utf8')
      if (text.includes('@vercel/analytics') || /\btrack\s*\(/.test(text)) {
        hits.push(file)
      }
    }
    expect(hits).toEqual([])
  })
})
