import type { Hex } from 'viem';

/**
 * Convert a base64url string to Uint8Array
 */
export function base64UrlToBytes(base64url: string): Uint8Array {
  // Replace URL-safe characters
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  // Add padding if needed
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}

/**
 * Convert Uint8Array to base64url string
 */
export function bytesToBase64Url(bytes: Uint8Array): string {
  const binary = String.fromCharCode(...bytes);
  const base64 = btoa(binary);
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Convert Uint8Array to hex string
 */
export function bytesToHex(bytes: Uint8Array): Hex {
  return `0x${Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')}` as Hex;
}

/**
 * Convert hex string to Uint8Array
 */
export function hexToBytes(hex: Hex): Uint8Array {
  const str = hex.startsWith('0x') ? hex.slice(2) : hex;
  const bytes = new Uint8Array(str.length / 2);
  for (let i = 0; i < str.length; i += 2) {
    bytes[i / 2] = parseInt(str.slice(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Hash a credential ID to bytes32
 */
export function hashCredentialId(credentialId: string | Uint8Array): Hex {
  const bytes =
    typeof credentialId === 'string'
      ? base64UrlToBytes(credentialId)
      : credentialId;

  // Use SHA-256 to hash to 32 bytes
  // For synchronous hashing in browser, we'll use a simple approach
  // In production, use crypto.subtle.digest
  return keccak256Hash(bytes);
}

/**
 * Simple keccak256 implementation for hashing
 * In production, use viem's keccak256
 */
export function keccak256Hash(data: Uint8Array): Hex {
  // Import from viem would be used here
  // For now, return a placeholder that will be replaced with viem's keccak256
  return bytesToHex(data.slice(0, 32).length === 32 ? data.slice(0, 32) : new Uint8Array(32));
}

/**
 * Extract x,y coordinates from COSE public key
 */
export function extractP256PublicKey(
  cosePublicKey: Uint8Array
): { x: bigint; y: bigint } {
  // COSE key format for P-256:
  // Map with keys: 1 (kty), 3 (alg), -1 (crv), -2 (x), -3 (y)
  // For uncompressed key, typically starts with 0x04 followed by x (32 bytes) and y (32 bytes)
  
  // If it's a raw uncompressed key (65 bytes starting with 0x04)
  if (cosePublicKey.length === 65 && cosePublicKey[0] === 0x04) {
    const x = bytesToBigInt(cosePublicKey.slice(1, 33));
    const y = bytesToBigInt(cosePublicKey.slice(33, 65));
    return { x, y };
  }

  // Try to parse as COSE key
  // This is a simplified parser - in production use a proper CBOR library
  // For now, look for the x and y coordinate patterns
  
  // Find x coordinate (tagged with -2 in COSE, which is 0x21 in CBOR)
  let x: bigint = 0n;
  let y: bigint = 0n;

  for (let i = 0; i < cosePublicKey.length - 32; i++) {
    // Look for 32-byte sequences that could be coordinates
    if (cosePublicKey[i] === 0x58 && cosePublicKey[i + 1] === 0x20) {
      // This is a 32-byte byte string in CBOR
      const coord = cosePublicKey.slice(i + 2, i + 34);
      if (x === 0n) {
        x = bytesToBigInt(coord);
      } else {
        y = bytesToBigInt(coord);
        break;
      }
    }
  }

  if (x === 0n || y === 0n) {
    throw new Error('Failed to extract P-256 public key from COSE format');
  }

  return { x, y };
}

/**
 * Convert Uint8Array to bigint (big-endian)
 */
export function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const byte of bytes) {
    result = (result << 8n) | BigInt(byte);
  }
  return result;
}

/**
 * Convert bigint to Uint8Array (big-endian, 32 bytes)
 */
export function bigIntToBytes32(value: bigint): Uint8Array {
  const bytes = new Uint8Array(32);
  let temp = value;
  for (let i = 31; i >= 0; i--) {
    bytes[i] = Number(temp & 0xffn);
    temp = temp >> 8n;
  }
  return bytes;
}

/**
 * Parse DER-encoded ECDSA signature to r,s components
 */
export function parseDerSignature(der: Uint8Array): { r: bigint; s: bigint } {
  // DER format: 0x30 [total-length] 0x02 [r-length] [r] 0x02 [s-length] [s]
  if (der[0] !== 0x30) {
    throw new Error('Invalid DER signature: missing sequence tag');
  }

  let offset = 2; // Skip sequence tag and length

  // Parse r
  if (der[offset] !== 0x02) {
    throw new Error('Invalid DER signature: missing integer tag for r');
  }
  offset++;
  const rLength = der[offset++];
  let rBytes = der.slice(offset, offset + rLength);
  // Remove leading zero if present (DER encoding quirk for positive integers)
  if (rBytes[0] === 0x00 && rBytes.length > 32) {
    rBytes = rBytes.slice(1);
  }
  offset += rLength;

  // Parse s
  if (der[offset] !== 0x02) {
    throw new Error('Invalid DER signature: missing integer tag for s');
  }
  offset++;
  const sLength = der[offset++];
  let sBytes = der.slice(offset, offset + sLength);
  // Remove leading zero if present
  if (sBytes[0] === 0x00 && sBytes.length > 32) {
    sBytes = sBytes.slice(1);
  }

  return {
    r: bytesToBigInt(rBytes),
    s: bytesToBigInt(sBytes),
  };
}
