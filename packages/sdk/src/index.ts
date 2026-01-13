// Core client
export { MantlePassClient } from './client';

// Types
export type {
  PasskeyCredential,
  WebAuthnAssertion,
  ContractSignature,
  WalletInfo,
  ExecuteParams,
  BatchExecuteParams,
  MantlePassConfig,
  WalletState,
} from './types';

// WebAuthn utilities
export {
  registerPasskey,
  signChallenge,
  formatSignatureForContract,
  isWebAuthnSupported,
  isPlatformAuthenticatorAvailable,
} from './webauthn';

// Encoding utilities
export {
  base64UrlToBytes,
  bytesToBase64Url,
  bytesToHex,
  hexToBytes,
  bytesToBigInt,
  bigIntToBytes32,
  parseDerSignature,
} from './utils';
