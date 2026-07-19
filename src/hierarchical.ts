/**
 * Hierarchical child-key derivation via HKDF-SHA256.
 */

import { HIERARCHICAL_KEK_INFO } from './constants.js'
import { normalizeUint8Array } from './encoding.js'

/**
 * Derive a 32-byte child key from a master key.
 * Defaults `info` to the frozen hierarchical domain separator.
 */
export async function deriveChildKey(
  masterKey: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array = HIERARCHICAL_KEK_INFO
): Promise<Uint8Array> {
  const baseKey = await crypto.subtle.importKey(
    'raw',
    normalizeUint8Array(masterKey),
    { name: 'HKDF' },
    false,
    ['deriveBits']
  )

  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: normalizeUint8Array(salt),
      info: normalizeUint8Array(info),
    },
    baseKey,
    256
  )

  return normalizeUint8Array(new Uint8Array(bits))
}
