/**
 * Browser smoke: Argon2id module Worker returns a 32-byte master key.
 * Uses short KDF params for speed; production callers must use stored vault params.
 */
import { afterEach, describe, expect, it } from 'vitest'
import {
  deriveMasterKeyInWorker,
  terminateArgon2Worker,
} from '../../src/argon2-worker/client'

describe('argon2-worker browser smoke', () => {
  afterEach(() => {
    terminateArgon2Worker()
  })

  it('deriveMasterKeyInWorker returns a 32-byte key', async () => {
    const salt = new Uint8Array(16)
    crypto.getRandomValues(salt)

    const key = await deriveMasterKeyInWorker('browser-smoke-password', salt, {
      memory: 1024,
      time: 1,
      parallelism: 1,
    })

    expect(key).toBeInstanceOf(Uint8Array)
    expect(key.length).toBe(32)
  }, 60000)
})
