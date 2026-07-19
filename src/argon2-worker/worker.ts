/// <reference lib="webworker" />

/**
 * Argon2id Web Worker — offloads master-key derivation from the main thread.
 * No analytics, no product imports. Callers must pass stored vault KDF params.
 */

import { argon2id } from '@noble/hashes/argon2.js'

interface DeriveMessage {
  id: number
  password: string
  salt: number[]
  params: {
    memory: number
    time: number
    parallelism: number
  }
}

self.onmessage = (event: MessageEvent<DeriveMessage>) => {
  const { id, password, salt, params } = event.data
  const passwordBytes = new TextEncoder().encode(password)
  const saltBytes = new Uint8Array(salt)

  const hash = argon2id(passwordBytes, saltBytes, {
    t: params.time,
    m: params.memory,
    p: params.parallelism,
    dkLen: 32,
  })

  self.postMessage({ id, hash: Array.from(hash) })
}

export {}
