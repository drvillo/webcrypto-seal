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
| `@drvillo/browser-seal-crypto-asymmetric/argon2-worker` | Browser | Optional Argon2id Web Worker client |

Server / SSR code that must not load libsodium WASM should import from `./wire` only.

## Status

Scaffold only (`0.1.0` pre-crypto). Real primitives land in subsequent releases. Do not publish until crypto + tests land.

## License

MIT
