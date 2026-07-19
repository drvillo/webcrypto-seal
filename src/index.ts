/**
 * @drvillo/webcrypto-seal — encryption-scheme primitives for 1bridge.xyz.
 * Crypto-domain public API only — no product vocabulary.
 */

export const PACKAGE_NAME = '@drvillo/webcrypto-seal'

export {
  HIERARCHICAL_KEK_INFO,
  VERIFIER_PLAINTEXT,
  SECRET_WRAP_INFO,
  PUBLIC_KEY_PREFIX,
  SEALED_KEY_PREFIX,
  ENCRYPTED_PRIVATE_KEY_PREFIX,
} from './constants.js'

export { SealedBoxError, VerifierMismatchError } from './errors.js'

export type {
  AsymmetricKeypair,
  KdfParams,
  AesGcmResult,
  ParsedSealedKey,
  ParsedEncryptedPrivateKey,
} from './types.js'

export {
  toBase64Url,
  fromBase64Url,
  assertCanonicalBase64Url,
  uint8ArrayToBase64,
  base64ToUint8Array,
  computeChecksum,
} from './encoding.js'

export { DEFAULT_KDF_PARAMS, deriveMasterKey } from './kdf.js'
export { deriveChildKey } from './hierarchical.js'

export {
  generateSalt,
  generateDek,
  encryptPayload,
  decryptPayload,
  wrapKey,
  unwrapKey,
  createVerifier,
  verifyWithVerifier,
  deriveWrapKeyFromSecret,
  wrapKeyWithSecret,
  unwrapKeyWithSecret,
} from './aes-gcm.js'

export {
  generateKeypair,
  sealBytes,
  openSealedBytes,
  zeroSensitiveBytes,
  validatePrivateKeyPair,
  computeKeyId,
  formatPublicKey,
  parsePublicKey,
  formatSealedKey,
  parseSealedKey,
  formatEncryptedPrivateKey,
  parseEncryptedPrivateKey,
  validatePublicKeyFingerprint,
} from './sealed-box.js'

export {
  sealContextualKey,
  openContextualKey,
  type SealContextualKeyInput,
  type OpenContextualKeyInput,
} from './contextual-seal.js'

export {
  packCiphertextEnvelope,
  unpackCiphertextEnvelope,
  encryptBytesForSealedUpload,
  decryptBytesFromSealedUpload,
  type EncryptBytesForSealedUploadInput,
  type EncryptBytesForSealedUploadResult,
  type DecryptBytesFromSealedUploadInput,
} from './file-envelope.js'
