#!/usr/bin/env node
/**
 * Offline Node consumer proof — seal/open + fail-closed CONTEXT_MISMATCH.
 *
 * Requires Node ≥20 and a local build (`pnpm build`) or an installed package.
 * Does not call any network APIs.
 *
 * Usage (from package root after build):
 *   node examples/offline-node-seal.mjs
 */

import { createRequire } from 'node:module'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const require = createRequire(import.meta.url)

// Resolve the built package from the sibling checkout (no registry / no network).
const pkgRoot = join(__dirname, '..')
const pkg = await import(join(pkgRoot, 'dist', 'index.js'))

const {
  generateKeypair,
  sealContextualKey,
  openContextualKey,
  createVerifier,
  verifyWithVerifier,
  computeChecksum,
  SealedBoxError,
} = pkg

function bytesEqual(a, b) {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false
  return true
}

function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}

async function main() {
  // Touch require so unused-import linters stay quiet if tree-shaken elsewhere.
  void require

  const keypair = await generateKeypair()
  const key = crypto.getRandomValues(new Uint8Array(32))
  // Opaque caller-supplied kind (example consumer value — not a package export).
  const kind = 'document-dek'
  const scopeId = 'offline-scope-a'
  const resourceId = 'offline-resource-1'

  const envelope = await sealContextualKey({
    kind,
    scopeId,
    resourceId,
    key,
    publicKey: keypair.publicKey,
    keyId: keypair.keyId,
  })
  console.log('sealed envelope prefix:', envelope.slice(0, 8))

  const opened = await openContextualKey({
    envelope,
    privateKey: keypair.privateKey,
    publicKey: keypair.publicKey,
    kind,
    scopeId,
    resourceId,
  })

  if (!bytesEqual(opened, key)) {
    console.error('FAIL: opened key does not match sealed key')
    process.exit(1)
  }
  console.log('openContextualKey: recovered key OK (%d bytes)', opened.length)

  // Fail-closed path: wrong vaultId / scopeId → CONTEXT_MISMATCH
  try {
    await openContextualKey({
      envelope,
      privateKey: keypair.privateKey,
      publicKey: keypair.publicKey,
      kind,
      scopeId: 'wrong-scope',
      resourceId,
    })
    console.error('FAIL: expected CONTEXT_MISMATCH on wrong scopeId')
    process.exit(1)
  } catch (err) {
    if (!(err instanceof SealedBoxError) || err.code !== 'CONTEXT_MISMATCH') {
      console.error('FAIL: unexpected error on wrong context:', err)
      process.exit(1)
    }
    console.log('caught CONTEXT_MISMATCH (fail-closed) as expected:', err.code)
  }

  const verifier = await createVerifier(key)
  await verifyWithVerifier(key, verifier)
  console.log('createVerifier + verifyWithVerifier: accept OK')

  const checksum = await computeChecksum(key)
  console.log('checksum (hex):', checksum)
  console.log('checksum length:', checksum.length, '(expected 64 hex chars)')
  console.log('key preview (hex, first 8 bytes):', toHex(key.slice(0, 8)))

  console.log('offline-node-seal: OK')
  process.exit(0)
}

main().catch((err) => {
  console.error(err)
  process.exit(1)
})
