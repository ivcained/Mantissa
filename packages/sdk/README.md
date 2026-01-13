# @mantlepass/sdk

TypeScript SDK for MantlePass passkey-native smart wallets.

## Installation

```bash
npm install @mantlepass/sdk
```

## Quick Start

```typescript
import { MantlePassClient, createPasskey, signWithPasskey } from '@mantlepass/sdk';

// Create a passkey (triggers biometric prompt)
const credential = await createPasskey({
  name: 'My Wallet',
  displayName: 'Demo User',
});

// Initialize client
const client = new MantlePassClient({
  rpcUrl: 'https://rpc.sepolia.mantle.xyz',
  factoryAddress: '0x...',
  credential,
});

// Create wallet on-chain
const wallet = await client.createWallet();
console.log('Wallet address:', wallet.address);

// Send transaction
const txHash = await client.sendTransaction({
  to: '0x...',
  value: 1000000000000000000n, // 1 MNT
});
```

## API Reference

### `MantlePassClient`

Main client for interacting with MantlePass wallets.

```typescript
const client = new MantlePassClient({
  rpcUrl: string;           // RPC endpoint
  factoryAddress: string;   // Factory contract address
  credential?: PasskeyCredential;  // Optional passkey
});
```

#### Methods

- `createWallet()` - Deploy a new wallet
- `getWalletAddress(credentialIdHash)` - Compute wallet address
- `sendTransaction({ to, value, data })` - Sign and send transaction
- `isWalletDeployed(address)` - Check if wallet exists

### `createPasskey(options)`

Create a new passkey using WebAuthn.

```typescript
const credential = await createPasskey({
  name: string;        // Username/identifier
  displayName: string; // Display name
  rpId?: string;       // Relying party ID (defaults to hostname)
});
```

Returns:
```typescript
{
  id: string;           // Base64URL credential ID
  rawId: Uint8Array;    // Raw credential ID bytes
  publicKeyX: bigint;   // P-256 public key X coordinate
  publicKeyY: bigint;   // P-256 public key Y coordinate
}
```

### `signWithPasskey(challenge, rpId?)`

Sign a challenge using an existing passkey.

```typescript
const signature = await signWithPasskey(
  challengeBytes,  // Uint8Array
  'localhost'      // Optional rpId
);
```

Returns:
```typescript
{
  authenticatorData: Uint8Array;
  clientDataJSON: Uint8Array;
  signature: Uint8Array;
  r: bigint;
  s: bigint;
}
```

## Utilities

### Encoding/Decoding

```typescript
import { 
  bytesToHex, 
  hexToBytes, 
  bytesToBase64Url, 
  base64UrlToBytes 
} from '@mantlepass/sdk';

bytesToHex(new Uint8Array([1, 2, 3]));  // '0x010203'
hexToBytes('0x010203');                  // Uint8Array([1, 2, 3])
```

### Hash Functions

```typescript
import { sha256, keccak256, hashCredentialId } from '@mantlepass/sdk';

const hash = await sha256(data);
const ethHash = keccak256(data);
const idHash = await hashCredentialId(credentialId);
```

## Network Configuration

```typescript
// Mantle Sepolia (testnet)
const client = new MantlePassClient({
  rpcUrl: 'https://rpc.sepolia.mantle.xyz',
  factoryAddress: '0x...',
});

// Mantle Mainnet
const client = new MantlePassClient({
  rpcUrl: 'https://rpc.mantle.xyz',
  factoryAddress: '0x...',
});
```

## License

MIT
