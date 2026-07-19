/**
 * Contextual sealed-key envelopes.
 * `kind` is an opaque caller-supplied string — the package never defines its values.
 * JSON wire fields remain `{ v, kind, vaultId, resourceId, key }` for compatibility.
 */

import { fromBase64Url, toBase64Url } from './encoding.js'
import { SealedBoxError } from './errors.js'
import { formatSealedKey, openSealedBytes, parseSealedKey, sealBytes } from './sealed-box.js'

export interface SealContextualKeyInput {
  /** Scope id written to the frozen wire field `vaultId`. */
  scopeId: string
  resourceId: string
  /** Opaque caller-supplied kind string. */
  kind: string
  key: Uint8Array
  publicKey: Uint8Array
  keyId: string
}

export interface OpenContextualKeyInput {
  scopeId: string
  resourceId: string
  kind: string
  envelope: string
  privateKey: Uint8Array
  publicKey: Uint8Array
}

function buildContextualPayload(
  kind: string,
  scopeId: string,
  resourceId: string,
  key: Uint8Array
): Uint8Array {
  const json = JSON.stringify({
    v: 1,
    kind,
    vaultId: scopeId,
    resourceId,
    key: toBase64Url(key),
  })
  return new TextEncoder().encode(json)
}

function parseContextualPayload(
  plaintext: Uint8Array,
  expected: { scopeId: string; resourceId: string; kind: string }
): Uint8Array {
  let parsed: {
    v?: number
    kind?: string
    vaultId?: string
    resourceId?: string
    key?: string
  }
  try {
    parsed = JSON.parse(new TextDecoder().decode(plaintext))
  } catch {
    throw new SealedBoxError('INVALID_PAYLOAD', 'Sealed envelope payload is not valid JSON.')
  }

  if (
    parsed.v !== 1 ||
    parsed.kind !== expected.kind ||
    parsed.vaultId !== expected.scopeId ||
    parsed.resourceId !== expected.resourceId ||
    !parsed.key
  ) {
    throw new SealedBoxError(
      'CONTEXT_MISMATCH',
      'Sealed envelope does not match the expected context.'
    )
  }

  return fromBase64Url(parsed.key)
}

export async function sealContextualKey(input: SealContextualKeyInput): Promise<string> {
  const payload = buildContextualPayload(input.kind, input.scopeId, input.resourceId, input.key)
  const sealed = await sealBytes(payload, input.publicKey)
  return formatSealedKey(sealed, input.keyId)
}

export async function openContextualKey(input: OpenContextualKeyInput): Promise<Uint8Array> {
  const { ciphertext } = parseSealedKey(input.envelope)
  const plaintext = await openSealedBytes(ciphertext, input.publicKey, input.privateKey)
  const key = parseContextualPayload(plaintext, {
    scopeId: input.scopeId,
    resourceId: input.resourceId,
    kind: input.kind,
  })
  if (key.length !== 32) {
    throw new SealedBoxError('INVALID_KEY', 'Opened key has invalid length.')
  }
  return key
}
