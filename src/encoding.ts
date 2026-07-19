/**
 * Three frozen encodings used by the scheme:
 * (a) canonical base64url — envelope payloads
 * (b) standard base64 with 8192-byte chunking — verifier packing
 * (c) lowercase hex SHA-256 — checksums
 *
 * Must work in Node ≥20 (global Web APIs) and browser. No Buffer optimization.
 */

import { SealedBoxError } from './errors.js'

function normalizeUint8Array(arr: Uint8Array): Uint8Array<ArrayBuffer> {
  const buffer = new ArrayBuffer(arr.length)
  const normalized = new Uint8Array(buffer)
  normalized.set(arr)
  return normalized as Uint8Array<ArrayBuffer>
}

export function toBase64Url(bytes: Uint8Array): string {
  const binary = Array.from(bytes, (byte) => String.fromCharCode(byte)).join('')
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

function fromBase64UrlUnsafe(encoded: string): Uint8Array {
  const padded = encoded.replace(/-/g, '+').replace(/_/g, '/')
  const padLength = (4 - (padded.length % 4)) % 4
  const base64 = padded + '='.repeat(padLength)
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

export function assertCanonicalBase64Url(encoded: string): void {
  if (!encoded || !/^[A-Za-z0-9_-]+$/.test(encoded)) {
    throw new SealedBoxError('INVALID_ENCODING', 'Envelope contains non-canonical base64url.')
  }
  const decoded = fromBase64UrlUnsafe(encoded)
  if (toBase64Url(decoded) !== encoded) {
    throw new SealedBoxError('INVALID_ENCODING', 'Envelope contains non-canonical base64url.')
  }
}

export function fromBase64Url(encoded: string, expectedLength?: number): Uint8Array {
  assertCanonicalBase64Url(encoded)
  const padded = encoded.replace(/-/g, '+').replace(/_/g, '/')
  const padLength = (4 - (padded.length % 4)) % 4
  const base64 = padded + '='.repeat(padLength)
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  if (expectedLength !== undefined && bytes.length !== expectedLength) {
    throw new SealedBoxError('INVALID_LENGTH', 'Decoded payload has invalid length.')
  }
  return bytes
}

/**
 * Standard base64 (not url-safe). Chunks at 8192 to avoid stack overflow on large arrays.
 */
export function uint8ArrayToBase64(bytes: Uint8Array): string {
  let binary = ''
  const chunkSize = 8192
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.slice(i, i + chunkSize)
    for (let j = 0; j < chunk.length; j++) {
      binary += String.fromCharCode(chunk[j])
    }
  }
  return btoa(binary)
}

export function base64ToUint8Array(base64: string): Uint8Array {
  const binary = atob(base64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes
}

/** SHA-256 digest as lowercase hex. */
export async function computeChecksum(data: Uint8Array): Promise<string> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', normalizeUint8Array(data))
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('')
}

export { normalizeUint8Array }
