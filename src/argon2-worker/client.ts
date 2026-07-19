/**
 * Browser Argon2id worker client.
 *
 * Import from `@drvillo/webcrypto-seal/argon2-worker` only in
 * browser apps. Node / CLI must use sync `deriveMasterKey` from the package root.
 *
 * On worker failure or unavailability, rejects so the caller can fall back to
 * `deriveMasterKey` — this module never silently depends on analytics.
 */

import type { KdfParams } from '../types.js'

export class Argon2WorkerError extends Error {
  readonly reason: string

  constructor(reason: string) {
    super(reason)
    this.name = 'Argon2WorkerError'
    this.reason = reason
  }
}

let worker: Worker | null = null
let nextId = 0
const pending = new Map<
  number,
  { resolve: (value: Uint8Array) => void; reject: (reason: Error) => void }
>()

function getWorker(): Worker | null {
  if (typeof window === 'undefined' || typeof Worker === 'undefined') return null
  if (!worker) {
    // Resolves against the published dist chunk next to this client
    // (dist/argon2-worker/worker.js). Vite maps .js → .ts during source tests.
    // type:'module' — dist worker is ESM with @noble/hashes bundled in.
    worker = new Worker(new URL('./worker.js', import.meta.url), {
      type: 'module',
    })
    worker.onmessage = (event: MessageEvent<{ id: number; hash: number[] }>) => {
      const handler = pending.get(event.data.id)
      if (!handler) return
      pending.delete(event.data.id)
      handler.resolve(new Uint8Array(event.data.hash))
    }
    worker.onerror = (event) => {
      const reason = event.message || 'Argon2 worker failed'
      for (const [, handler] of pending) {
        handler.reject(new Argon2WorkerError(reason))
      }
      pending.clear()
      worker?.terminate()
      worker = null
    }
  }
  return worker
}

/** Tear down the shared worker (e.g. after unlock completes). */
export function terminateArgon2Worker(): void {
  worker?.terminate()
  worker = null
  pending.clear()
}

/**
 * Derive a 32-byte master key via Argon2id in a Web Worker.
 * Rejects with `Argon2WorkerError` when Worker is unavailable or fails —
 * callers should catch and fall back to sync `deriveMasterKey`.
 */
export function deriveMasterKeyInWorker(
  password: string,
  salt: Uint8Array,
  params: KdfParams
): Promise<Uint8Array> {
  const activeWorker = getWorker()
  if (!activeWorker) {
    return Promise.reject(new Argon2WorkerError('Argon2 worker unavailable'))
  }

  const id = ++nextId
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject })
    activeWorker.postMessage({
      id,
      password,
      salt: Array.from(salt),
      params,
    })
  })
}
