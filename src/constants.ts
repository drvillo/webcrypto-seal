/**
 * Frozen wire prefixes and historical domain-separator labels.
 * Byte values must never change — they are compatibility locks.
 */

export const PUBLIC_KEY_PREFIX = 'v3.x25519.'
/** Sealed-key envelope prefix (historical alias value `v3.sb1.`). */
export const SEALED_KEY_PREFIX = 'v3.sb1.'
export const ENCRYPTED_PRIVATE_KEY_PREFIX = 'v3.a256gcm.'

/** HKDF info for hierarchical child-key derivation (UTF-8 bytes). */
export const HIERARCHICAL_KEK_INFO = new TextEncoder().encode('1bridge-vault-kek-v1')

/** AES-GCM plaintext sealed into the unlock verifier. */
export const VERIFIER_PLAINTEXT = new TextEncoder().encode('1bridge-vault-verifier-v1')

/** HKDF info for secret-byte key wrap (UTF-8 `lsk-wrap`). */
export const SECRET_WRAP_INFO = new TextEncoder().encode('lsk-wrap')

export const X25519_KEY_BYTES = 32
export const MAX_SEALED_PAYLOAD_BYTES = 4096
