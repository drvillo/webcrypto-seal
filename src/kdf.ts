/**
 * Argon2id master-key derivation (sync @noble/hashes path).
 * Default for Node/CLI. Browser apps may optionally use
 * `@drvillo/browser-seal-crypto-asymmetric/argon2-worker` and fall back here.
 */

import { argon2id } from '@noble/hashes/argon2.js'
import { normalizeUint8Array } from './encoding.js'
import type { KdfParams } from './types.js'

export type { KdfParams } from './types.js'

export const DEFAULT_KDF_PARAMS: KdfParams = {
  memory: 65536,
  time: 12,
  parallelism: 4,
}

export async function deriveMasterKey(
  password: string,
  salt: Uint8Array,
  params: KdfParams
): Promise<Uint8Array> {
  const passwordBytes = new TextEncoder().encode(password)
  const hash = argon2id(passwordBytes, salt, {
    t: params.time,
    m: params.memory,
    p: params.parallelism,
    dkLen: 32,
  })
  return normalizeUint8Array(hash)
}
