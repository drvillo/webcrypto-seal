# Security

This package is an **encryption-scheme library** only. Product concepts (auth, sessions, authorization, vaults, document requests, share links, signing workflows, OTP) belong in consumers — not in this package.

**Trust boundary:** the package provides cryptographic scheme primitives (KDF, hierarchical derive, sealed box, AES-GCM, wire encode/decode). **Authorization and access control are entirely the consumer's responsibility.** Correct seal/open does not imply the caller is allowed to perform the operation.

## Threat boundaries (ASVS-aligned)

| Threat | ASVS theme | Mitigation |
|--------|------------|------------|
| **API misuse** (e.g. sealing raw key material without contextual binding) | V5 Input / V9 Crypto | Prefer contextual seal APIs (`sealContextualKey` / `openContextualKey`); treat low-level `sealBytes` as advanced; fail closed on wire parse |
| **Key material logging / stringification** | V8 Data protection | No console logging of secrets in package code; export wipe helpers (`zeroSensitiveBytes`); never put key bytes in thrown messages |
| **Wire-format confusion / prefix stripping** | V5 Input validation | Strict prefix + keyId + canonical encoding checks; fail closed on invalid envelopes; contextual open fails with `CONTEXT_MISMATCH` on scope/resource/kind drift |
| **Argon2 parameter handling / downgrade** | V2 Auth / V9 Crypto | Export strong `DEFAULT_KDF_PARAMS`; callers must **persist and reuse stored params** for verify — never invent weaker client-side params for unlock |
| **Supply-chain confusion** | V14 Config | Locked npm name `@drvillo/browser-seal-crypto-asymmetric`; public MIT repo; **pin exact versions** in consumers (e.g. `"0.1.0"`); `prepublishOnly` gates typecheck/test/build; no download postinstall hooks |
| **WASM / CSP blocking** | V14 Config | Root entry lazy-loads `libsodium-wrappers` WASM. Browser consumers that seal/open need CSP `'wasm-unsafe-eval'` (not broad `'unsafe-eval'`). Prefer `./wire` on the server to avoid WASM entirely |
| **Timing on verifier compare** | V9 Crypto | Verifier check uses AES-GCM decrypt of fixed plaintext — treat failure as opaque (`VerifierMismatchError`); do not branch on partial plaintext; consumers must not log verifier ciphertext next to candidate keys |

## Contextual binding

`openContextualKey` binds opened key material to caller-supplied `scopeId` + `resourceId` + `kind`. The JSON wire field for scope remains **`vaultId`** (frozen). Wrong context → `SealedBoxError` with code `CONTEXT_MISMATCH` (fail closed). This is a crypto binding, not an authorization decision.

## What this package does not do

- Authentication, session management, or access control
- OTP / token pepper / vendor-secret string formatting
- Product orchestration (unlock, rotation, migration flows)
- Network I/O, telemetry, or analytics

Consumers are responsible for authz, secret handling at rest, CSP configuration, and pinning published package versions.

## Reporting

Report security issues privately to the repository maintainers. Do not open public issues for undisclosed vulnerabilities.
