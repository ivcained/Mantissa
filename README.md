# Mantissa 🔐

**Passkey-native smart wallet for Mantle L2**

Create and manage smart contract wallets using device biometrics (Face ID, Touch ID, fingerprint) instead of seed phrases. No more 12-word mnemonics to backup!

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Solidity](https://img.shields.io/badge/solidity-0.8.28-purple.svg)
![Mantle](https://img.shields.io/badge/network-Mantle%20L2-green.svg)


## Demo 

https://github.com/user-attachments/assets/445136dc-ba2c-4eb7-93ed-1a661c3251f0



## ✨ Features

- **🔐 Seedless Authentication** - Use device biometrics instead of seed phrases
- **📱 WebAuthn/FIDO2** - Industry-standard passkey protocol
- **⛽ ERC-4337 Compatible** - Account abstraction ready
- **🔑 Multi-Owner Support** - Add backup passkeys for recovery
- **⚡ Mantle Optimized** - Built for low gas costs on Mantle L2

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    User Device                          │
│  ┌─────────────┐    ┌──────────────┐    ┌───────────┐  │
│  │  Biometric  │───▶│   Passkey    │───▶│  Wallet   │  │
│  │   Prompt    │    │  (WebAuthn)  │    │   SDK     │  │
│  └─────────────┘    └──────────────┘    └───────────┘  │
└────────────────────────────┬────────────────────────────┘
                             │ Sign Transaction
                             ▼
┌─────────────────────────────────────────────────────────┐
│                    Mantle L2                            │
│  ┌─────────────────┐    ┌───────────────────────────┐  │
│  │ MantissaFactory│───▶│  MantissaWallet (Clone)  │  │
│  │ (Deploys Wallets)│    │  • P-256 Signature Verify │  │
│  └─────────────────┘    │  • Execute Transactions   │  │
│                          │  • Multi-Owner Support    │  │
│                          └───────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## 📦 Packages

| Package | Description |
|---------|-------------|
| [`packages/contracts`](./packages/contracts) | Solidity smart contracts (Foundry) |
| [`packages/sdk`](./packages/sdk) | TypeScript SDK for passkey + wallet integration |
| [`packages/demo`](./packages/demo) | Next.js demo application |

## 🚀 Quick Start

### Prerequisites

- [Node.js 18+](https://nodejs.org/)
- [Foundry](https://book.getfoundry.sh/getting-started/installation)

### Installation

```bash
# Clone the repo
git clone https://github.com/subh/keymantle.git
cd keymantle

# Install dependencies
npm install

# Build all packages
npm run build
```

### Run Demo

```bash
# Terminal 1: Start local Mantle fork
cd packages/contracts
anvil --fork-url https://rpc.sepolia.mantle.xyz

# Terminal 2: Deploy contracts
PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
forge script script/Deploy.s.sol --rpc-url http://127.0.0.1:8545 --broadcast

# Terminal 3: Run demo app
cd packages/demo
npm run dev
```

Open http://localhost:3000 and click "Create Passkey Wallet"!

## 📚 Documentation

### Smart Contracts

The core contracts implement a passkey-authenticated smart wallet:

- **`MantissaWallet.sol`** - Smart wallet with P-256 signature verification
- **`MantissaFactory.sol`** - Factory for deploying wallets (CREATE2)
- **`WebAuthnVerifier.sol`** - On-chain WebAuthn signature verification

See [packages/contracts/DEPLOYMENT.md](./packages/contracts/DEPLOYMENT.md) for deployment instructions.

### SDK Usage

```typescript
import { MantissaClient } from '@mantlepass/sdk';

// Initialize client
const client = new MantissaClient({
  rpcUrl: 'https://rpc.sepolia.mantle.xyz',
  factoryAddress: '0x...',
});

// Create wallet with passkey
const wallet = await client.createWallet({
  name: 'My Wallet',
});

// Sign and send transaction
const txHash = await client.sendTransaction({
  to: '0x...',
  value: 1000000000000000000n, // 1 MNT
  data: '0x',
});
```

### Networks

| Network | Chain ID | Factory Address |
|---------|----------|-----------------|
| Mantle Sepolia | 5003 | `TBD` |
| Mantle Mainnet | 5000 | `TBD` |
| Local (Anvil) | 5003 | `0xae13506deae7f82ea5c1c646d0b6693b220a4bb8` |

## 🧪 Testing

```bash
# Run contract tests
cd packages/contracts
forge test -vvv

# Run SDK tests
cd packages/sdk
npm test
```

## 🛠️ Development

### Project Structure

```
keymantle/
├── packages/
│   ├── contracts/          # Solidity contracts
│   │   ├── src/           # Contract source files
│   │   ├── test/          # Foundry tests
│   │   └── script/        # Deployment scripts
│   ├── sdk/               # TypeScript SDK
│   │   └── src/
│   │       ├── client/    # MantissaClient
│   │       ├── webauthn/  # Passkey utilities
│   │       └── utils/     # Helpers
│   └── demo/              # Next.js demo app
├── package.json           # Monorepo root
└── README.md
```

### Build Commands

```bash
# Build everything
npm run build

# Build specific package
npm run build --workspace=packages/sdk

# Run tests
npm test
```

## 🔐 Security

- **P-256 (secp256r1)** - Hardware-backed elliptic curve cryptography
- **WebAuthn** - W3C standard for passwordless authentication
- **On-chain verification** - All signatures verified by smart contracts
- **No private key exposure** - Keys never leave secure hardware

### Audit Status

⚠️ **Not audited** - This is experimental software. Use at your own risk.

## 🗺️ Roadmap

- [x] Core smart contracts
- [x] TypeScript SDK
- [x] Demo application
- [ ] ERC-4337 Bundler integration
- [ ] Social recovery module
- [ ] Session keys for dApps
- [ ] Mobile SDK (React Native)
- [ ] Hardware wallet backup

## 📄 License

MIT License - see [LICENSE](./LICENSE) for details.

## 🤝 Contributing

Contributions welcome! Please read our [Contributing Guide](./CONTRIBUTING.md) first.

## 🔗 Links

- [Mantle Network](https://mantle.xyz)
- [WebAuthn Spec](https://w3c.github.io/webauthn/)
- [ERC-4337](https://eips.ethereum.org/EIPS/eip-4337)
