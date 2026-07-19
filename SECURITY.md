# Security

This package is an **encryption-scheme library** only. Product concepts (auth, sessions, authorization, vaults, document requests, share links, signing workflows) belong in consumers — not in this package.

## Threat boundaries

| Threat | Mitigation |
|--------|------------|
| **API misuse** (e.g. sealing raw key material without contextual binding) | Prefer contextual seal APIs once shipped; document low-level `sealBytes` as advanced; fail closed on wire parse |
| **Key material logging / stringification** | No console logging of secrets in package code; export wipe helpers; never put key bytes in thrown messages |
| **Wire-format confusion / prefix stripping** | Strict prefix + keyId + canonical encoding checks; fail closed on invalid envelopes |
| **Argon2 parameter downgrade** | Export strong `DEFAULT_KDF_PARAMS`; callers must persist and reuse stored params for verify |
| **Supply-chain confusion** | Locked npm name `@drvillo/browser-seal-crypto-asymmetric`; public MIT repo; pin versions in consumers; `prepublishOnly` gates typecheck/test/build |
| **CSP blocking WASM** | Root entry lazy-loads `libsodium-wrappers` WASM. Consumers that seal/open in-browser need CSP `'wasm-unsafe-eval'` (not broad `'unsafe-eval'`). Prefer `./wire` on the server to avoid WASM entirely |

## What this package does not do

- Authentication, session management, or access control
- OTP / token pepper / vendor-secret string formatting
- Product orchestration (unlock, rotation, migration flows)

Consumers are responsible for authz, secret handling at rest, and CSP configuration.

## Reporting

Report security issues privately to the repository maintainers. Do not open public issues for undisclosed vulnerabilities.
