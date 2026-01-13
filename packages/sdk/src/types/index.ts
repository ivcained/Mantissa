import type { Address, Hex } from 'viem';

/**
 * Passkey credential returned from WebAuthn
 */
export interface PasskeyCredential {
  /** Base64URL encoded credential ID */
  id: string;
  /** Raw credential ID bytes */
  rawId: Uint8Array;
  /** P-256 public key X coordinate */
  publicKeyX: bigint;
  /** P-256 public key Y coordinate */
  publicKeyY: bigint;
}

/**
 * WebAuthn assertion result
 */
export interface WebAuthnAssertion {
  /** Raw authenticator data */
  authenticatorData: Uint8Array;
  /** Client data JSON string */
  clientDataJSON: string;
  /** Signature r component */
  r: bigint;
  /** Signature s component */
  s: bigint;
}

/**
 * Signature formatted for contract
 */
export interface ContractSignature {
  authenticatorData: Hex;
  clientDataJSON: string;
  r: bigint;
  s: bigint;
}

/**
 * Wallet info after creation
 */
export interface WalletInfo {
  /** The wallet contract address */
  address: Address;
  /** The credential ID hash */
  credentialIdHash: Hex;
  /** The passkey credential */
  credential: PasskeyCredential;
}

/**
 * Parameters for executing a transaction
 */
export interface ExecuteParams {
  /** Target contract address */
  target: Address;
  /** ETH value to send (in wei) */
  value?: bigint;
  /** Calldata */
  data?: Hex;
}

/**
 * Batch transaction parameters
 */
export interface BatchExecuteParams {
  /** Array of targets */
  targets: Address[];
  /** Array of values */
  values: bigint[];
  /** Array of calldatas */
  datas: Hex[];
}

/**
 * SDK configuration
 */
export interface MantlePassConfig {
  /** RPC URL for Mantle */
  rpcUrl: string;
  /** Factory contract address */
  factoryAddress: Address;
  /** Chain ID (5003 for Mantle Sepolia, 5000 for Mantle Mainnet) */
  chainId?: number;
  /** RP ID for WebAuthn (e.g., "mantlepass.xyz") */
  rpId?: string;
}

/**
 * Wallet state
 */
export interface WalletState {
  /** Wallet address */
  address: Address;
  /** Current nonce */
  nonce: bigint;
  /** Recovery address */
  recoveryAddress: Address;
  /** Active passkey count */
  activePasskeyCount: number;
  /** All credential IDs */
  credentialIds: Hex[];
}
