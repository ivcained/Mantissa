import type { PasskeyCredential, WebAuthnAssertion, ContractSignature } from '../types';
import {
  bytesToBase64Url,
  bytesToHex,
  extractP256PublicKey,
  parseDerSignature,
  base64UrlToBytes,
} from '../utils';

/**
 * WebAuthn registration options
 */
export interface RegisterPasskeyOptions {
  /** Relying Party ID (e.g., "mantlepass.xyz") */
  rpId: string;
  /** Relying Party name for display */
  rpName?: string;
  /** User ID (can be any unique identifier) */
  userId: string;
  /** User display name */
  userName: string;
}

/**
 * Register a new passkey using WebAuthn
 */
export async function registerPasskey(
  options: RegisterPasskeyOptions
): Promise<PasskeyCredential> {
  const { rpId, rpName = rpId, userId, userName } = options;

  // Generate random user ID bytes
  const userIdBytes = new TextEncoder().encode(userId);

  // WebAuthn creation options
  const createOptions: CredentialCreationOptions = {
    publicKey: {
      rp: {
        id: rpId,
        name: rpName,
      },
      user: {
        id: userIdBytes,
        name: userName,
        displayName: userName,
      },
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      pubKeyCredParams: [
        {
          type: 'public-key',
          alg: -7, // ES256 (P-256 with SHA-256)
        },
      ],
      authenticatorSelection: {
        authenticatorAttachment: 'platform',
        residentKey: 'required',
        userVerification: 'required',
      },
      timeout: 60000,
      attestation: 'none',
    },
  };

  // Create credential
  const credential = (await navigator.credentials.create(
    createOptions
  )) as PublicKeyCredential;

  if (!credential) {
    throw new Error('Failed to create passkey');
  }

  const response = credential.response as AuthenticatorAttestationResponse;
  const publicKeyBytes = response.getPublicKey();

  if (!publicKeyBytes) {
    throw new Error('Failed to get public key from credential');
  }

  // Extract x,y coordinates from the public key
  const { x, y } = extractP256PublicKey(new Uint8Array(publicKeyBytes));

  return {
    id: bytesToBase64Url(new Uint8Array(credential.rawId)),
    rawId: new Uint8Array(credential.rawId),
    publicKeyX: x,
    publicKeyY: y,
  };
}

/**
 * Sign a challenge using an existing passkey
 */
export async function signChallenge(
  challenge: Uint8Array,
  rpId: string,
  credentialId?: string
): Promise<WebAuthnAssertion> {
  // Convert to ArrayBuffer for type compatibility
  const challengeBuffer = new Uint8Array(challenge).buffer as ArrayBuffer;
  
  const allowCreds: PublicKeyCredentialDescriptor[] | undefined = credentialId
    ? [
        {
          type: 'public-key',
          id: new Uint8Array(base64UrlToBytes(credentialId)).buffer as ArrayBuffer,
        },
      ]
    : undefined;

  const getOptions: CredentialRequestOptions = {
    publicKey: {
      challenge: challengeBuffer,
      rpId,
      userVerification: 'required',
      timeout: 60000,
      allowCredentials: allowCreds,
    },
  };

  const assertion = (await navigator.credentials.get(
    getOptions
  )) as PublicKeyCredential;

  if (!assertion) {
    throw new Error('Failed to get passkey assertion');
  }

  const response = assertion.response as AuthenticatorAssertionResponse;

  // Parse the DER-encoded signature
  const { r, s } = parseDerSignature(new Uint8Array(response.signature));

  // Decode clientDataJSON
  const clientDataJSON = new TextDecoder().decode(response.clientDataJSON);

  return {
    authenticatorData: new Uint8Array(response.authenticatorData),
    clientDataJSON,
    r,
    s,
  };
}

/**
 * Format a WebAuthn assertion for contract verification
 */
export function formatSignatureForContract(
  assertion: WebAuthnAssertion
): ContractSignature {
  return {
    authenticatorData: bytesToHex(assertion.authenticatorData),
    clientDataJSON: assertion.clientDataJSON,
    r: assertion.r,
    s: assertion.s,
  };
}

/**
 * Create a challenge from transaction hash
 */
export function createChallenge(transactionHash: Uint8Array): Uint8Array {
  // The challenge is the transaction hash itself
  return transactionHash;
}

/**
 * Check if WebAuthn is supported
 */
export function isWebAuthnSupported(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof window.PublicKeyCredential !== 'undefined' &&
    typeof navigator.credentials !== 'undefined'
  );
}

/**
 * Check if platform authenticator is available
 */
export async function isPlatformAuthenticatorAvailable(): Promise<boolean> {
  if (!isWebAuthnSupported()) {
    return false;
  }

  try {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}
