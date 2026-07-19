# @drvillo/browser-seal-crypto-asymmetric

Encryption-scheme primitives for asymmetric sealed-box crypto (X25519 sealed box, Argon2id KDF, AES-GCM, contextual seals). **Not** a product SDK — no vault, document-request, share, or signing concepts live here.

## Install

```bash
pnpm add @drvillo/browser-seal-crypto-asymmetric
```

## Dual runtime

Despite the `browser-` name prefix (naming consistency with sibling `@drvillo/browser-*` packages), this library targets **browser and Node ≥20**. Node ≥20 is required for global Web Crypto and base64 APIs used by the scheme.

| Entry | Runtime | Notes |
|-------|---------|-------|
| `@drvillo/browser-seal-crypto-asymmetric` | Browser + Node ≥20 | Full scheme (lazy-loads libsodium WASM for seal/open) |
| `@drvillo/browser-seal-crypto-asymmetric/wire` | Browser + Node ≥20 | **Parse-only**, WASM-free envelope helpers for server / SSR |
| `@drvillo/browser-seal-crypto-asymmetric/argon2-worker` | Browser only | Optional Argon2id Web Worker client |

Server / SSR code that must not load libsodium WASM should import from `./wire` only.

## Argon2 worker (browser)

Browser apps can offload Argon2id to a classic Web Worker:

```ts
import { deriveMasterKeyInWorker, terminateArgon2Worker } from '@drvillo/browser-seal-crypto-asymmetric/argon2-worker'
import { deriveMasterKey } from '@drvillo/browser-seal-crypto-asymmetric'

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

Always pass **stored vault KDF params** into the worker (do not invent weaker params client-side). Sync golden-vector tests on `deriveMasterKey` remain the compatibility lock.

## License

MIT
