# @drvillo/webcrypto-seal

Encryption-scheme primitives for asymmetric sealed-box crypto (X25519 sealed box, Argon2id KDF, AES-GCM, contextual seals). 

## Install

```bash
pnpm add @drvillo/webcrypto-seal
# or: npm install @drvillo/webcrypto-seal
```

Requires **Node ≥20** (global Web Crypto + `btoa`/`atob`). Same APIs are used in the browser.

## Runtime support

This library is the cryptographic layer for [1bridge.xyz](https://1bridge.xyz). It targets **browser and Node ≥20** as first-class consumers via Web Crypto and standard base64 APIs.   
  
Allows developing offline Node / CLI tools that seal and open 1Bridge-compatible ciphertext.


| Entry                                   | Runtime            | Notes                                                       |
| --------------------------------------- | ------------------ | ----------------------------------------------------------- |
| `@drvillo/webcrypto-seal`               | Browser + Node ≥20 | Full scheme (lazy-loads libsodium WASM for seal/open)       |
| `@drvillo/webcrypto-seal/wire`          | Browser + Node ≥20 | **Parse-only**, WASM-free envelope helpers for server / SSR |
| `@drvillo/webcrypto-seal/argon2-worker` | Browser only       | Optional Argon2id Web Worker client                         |


- **Seal/open under Node:** libsodium WASM works headless in Node ≥20 (no browser DOM required). Offline tools can round-trip contextual seals without a window.
- **Seal/open in the browser:** CSP must allow `'wasm-unsafe-eval'` (not broad `'unsafe-eval'`). Prefer the WASM-free `./wire` subpath on the server / SSR so Node never loads sodium.
- Server / SSR code that only validates envelopes should import from `./wire` only.



## Quick start

```ts
import {
  deriveMasterKey,
  deriveChildKey,
  generateKeypair,
  sealContextualKey,
  openContextualKey,
  encryptBytesForSealedUpload,
  createVerifier,
  verifyWithVerifier,
  DEFAULT_KDF_PARAMS,
} from '@drvillo/webcrypto-seal'

const salt = crypto.getRandomValues(new Uint8Array(16))
const master = await deriveMasterKey(password, salt, DEFAULT_KDF_PARAMS)
const child = await deriveChildKey(master, scopeId) // HKDF; historical info label frozen

const { publicKey, privateKey, keyId } = await generateKeypair()

// kind is an opaque caller-supplied string — not defined by this package
const dek = crypto.getRandomValues(new Uint8Array(32))
const envelope = await sealContextualKey({
  kind: 'document-dek', // example consumer value (see below)
  scopeId,              // written to frozen wire field `vaultId`
  resourceId,
  key: dek,
  publicKey,
  keyId,
})

const opened = await openContextualKey({
  envelope,
  privateKey,
  publicKey,
  kind: 'document-dek',
  scopeId,
  resourceId,
})

const upload = await encryptBytesForSealedUpload(plaintextBytes, {
  publicKey,
  keyId,
  scopeId,
  resourceId,
  kind: 'document-dek',
})
```

Prefer contextual seal APIs (`sealContextualKey` / `openContextualKey` / `encryptBytesForSealedUpload`) over low-level `sealBytes`.

## Export map


| Subpath           | What it exports                                                                                               |
| ----------------- | ------------------------------------------------------------------------------------------------------------- |
| `.` (root barrel) | Full scheme: KDF, hierarchical derive, AES-GCM, sealed box, contextual seal, file envelope, encodings, errors |
| `./argon2-worker` | `deriveMasterKeyInWorker`, `terminateArgon2Worker` (browser only)                                             |
| `./wire`          | Parse/format helpers only (`parseSealedKey`, `formatPublicKey`, …) — **no WASM**                              |




## Contextual `kind` (caller-supplied)

`kind` is an **opaque string supplied by the caller**. This package does **not** export kind constants or a kind enum.

Example consumer values used by 1Bridge (documented here only — **not** package exports):

- `document-dek` — document DEK sealed to an owner public key
- `signing-lsk` — signing link secret key sealed to an owner public key

Any other stable string works for offline tools; mismatch on open throws `CONTEXT_MISMATCH`.

## Wire compatibility locks

These byte values are **immutable** — changing them breaks existing ciphertext:


| Lock                         | Value / rule                                                      |
| ---------------------------- | ----------------------------------------------------------------- |
| Hierarchical HKDF info       | UTF-8 `1bridge-vault-kek-v1`                                      |
| Verifier plaintext           | UTF-8 `1bridge-vault-verifier-v1`                                 |
| Secret-wrap HKDF info        | UTF-8 `lsk-wrap`                                                  |
| Contextual JSON field        | Wire field is `vaultId` even when TypeScript params use `scopeId` |
| Public key prefix            | `v3.x25519.`                                                      |
| Sealed key prefix            | `v3.sb1.`                                                         |
| Encrypted private key prefix | `v3.a256gcm.`                                                     |




### Three frozen encodings

1. **Canonical base64url** — sealed-box / public-key / encrypted-private-key envelope payloads
2. **Standard base64** (8192-byte chunking) — unlock verifier packing
3. **Lowercase hex SHA-256** — ciphertext checksums (`computeChecksum`)



## Argon2 worker (browser)

Browser apps can offload Argon2id to a classic Web Worker:

```ts
import { deriveMasterKeyInWorker, terminateArgon2Worker } from '@drvillo/webcrypto-seal/argon2-worker'
import { deriveMasterKey } from '@drvillo/webcrypto-seal'

async function derive(password: string, salt: Uint8Array, params: KdfParams) {
  try {
    const key = await deriveMasterKeyInWorker(password, salt, params)
    terminateArgon2Worker()
    return key
  } catch {
    // Worker unavailable or failed — sync path is the source of truth
    return deriveMasterKey(password, salt, params)
  }
}
```

**Node / CLI:** never import `./argon2-worker`. Use root `deriveMasterKey` only (no Worker).

**Next.js:** import the subpath from client components / browser-only modules. The worker chunk is published at `dist/argon2-worker/worker.js` next to the client; bundlers resolve `new URL('./worker.js', import.meta.url)` against that layout. The client constructs a **module** Worker (`{ type: 'module' }`) with `@noble/hashes` bundled into the worker chunk so no bare imports are required at runtime.

**CSP:** classic Workers need `worker-src` / `script-src` that allow your origin blob/module workers. That is separate from `wasm-unsafe-eval`, which is only required for the libsodium seal/open path — not for the Argon2 worker.

Always pass **stored KDF params** into the worker (do not invent weaker params client-side). Sync golden-vector tests on `deriveMasterKey` remain the compatibility lock.

## Offline Node example

After `pnpm build` (or install from npm), prove seal/open + fail-closed context check with no network:

```bash
node examples/offline-node-seal.mjs
```

The script imports the built package, seals a contextual key, opens it successfully, catches `CONTEXT_MISMATCH` on a wrong `vaultId`/`scopeId`, runs verifier round-trip, and prints a checksum. It does not call any network APIs.

## License

MIT