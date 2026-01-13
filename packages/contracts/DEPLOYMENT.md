# MantlePass Deployment Guide

Complete guide to deploying MantlePass smart contracts on all environments.

## Prerequisites

1. **Install Foundry**
   ```bash
   curl -L https://foundry.paradigm.xyz | bash
   foundryup
   ```

2. **Create a Wallet** (if you don't have one)
   ```bash
   cast wallet new
   ```
   Save the address and private key securely.

---

## Network Configuration

| Network | Chain ID | RPC URL |
|---------|----------|---------|
| **Localnet (Anvil)** | 31337 | http://127.0.0.1:8545 |
| **Mantle Sepolia (Testnet)** | 5003 | https://rpc.sepolia.mantle.xyz |
| **Mantle Mainnet** | 5000 | https://rpc.mantle.xyz |

---

## 1. Localnet (Anvil) - Recommended for Development

No tokens needed. Uses Anvil's pre-funded test accounts.

### Start Local Node

```bash
# Option A: Fresh local chain
anvil

# Option B: Fork Mantle Sepolia (recommended)
anvil --fork-url https://rpc.sepolia.mantle.xyz
```

### Deploy

```bash
cd packages/contracts

# Use Anvil's default test private key (pre-funded with 10000 ETH)
PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
forge script script/Deploy.s.sol \
  --rpc-url http://127.0.0.1:8545 \
  --broadcast
```

### Verify Deployment

```bash
# Check the deployed address in the output or:
cat broadcast/Deploy.s.sol/5003/run-latest.json | grep contractAddress
```

---

## 2. Mantle Sepolia Testnet

Requires testnet MNT for gas.

### Get Testnet MNT

Use one of these faucets:
- [Mantle Official Faucet](https://faucet.sepolia.mantle.xyz/)
- [QuickNode Faucet](https://faucet.quicknode.com/mantle/sepolia)
- [HackQuest Faucet](https://www.hackquest.io/faucets/5003)

### Deploy

```bash
cd packages/contracts

# Set your private key (without 0x prefix works too)
export PRIVATE_KEY=your_private_key_here

# Deploy
forge script script/Deploy.s.sol \
  --rpc-url https://rpc.sepolia.mantle.xyz \
  --broadcast

# Or one-liner:
PRIVATE_KEY=0x... forge script script/Deploy.s.sol --rpc-url https://rpc.sepolia.mantle.xyz --broadcast
```

### Verify on Block Explorer

```bash
forge verify-contract \
  --chain-id 5003 \
  --rpc-url https://rpc.sepolia.mantle.xyz \
  --etherscan-api-key $MANTLESCAN_API_KEY \
  <DEPLOYED_ADDRESS> \
  src/MantlePassFactory.sol:MantlePassFactory
```

---

## 3. Mantle Mainnet

⚠️ **Real funds required. Double-check everything before deploying.**

### Deploy

```bash
cd packages/contracts

# Use a secure method for your private key
export PRIVATE_KEY=your_mainnet_private_key

# Deploy with confirmation
forge script script/Deploy.s.sol \
  --rpc-url https://rpc.mantle.xyz \
  --broadcast \
  --verify
```

### Verify on MantleScan

```bash
forge verify-contract \
  --chain-id 5000 \
  --rpc-url https://rpc.mantle.xyz \
  --etherscan-api-key $MANTLESCAN_API_KEY \
  <DEPLOYED_ADDRESS> \
  src/MantlePassFactory.sol:MantlePassFactory
```

---

## Environment Variables

Create a `.env` file in `packages/contracts/`:

```bash
# Private key (keep secret!)
PRIVATE_KEY=0x...

# For contract verification
MANTLESCAN_API_KEY=your_api_key

# RPC URLs (optional overrides)
MANTLE_SEPOLIA_RPC=https://rpc.sepolia.mantle.xyz
MANTLE_MAINNET_RPC=https://rpc.mantle.xyz
```

Load it before deploying:
```bash
source .env
```

> ⚠️ **Never commit `.env` to git!** Add it to `.gitignore`.

---

## Deployed Addresses

Update this section after deployment:

### Localnet (Anvil Fork)
| Contract | Address |
|----------|---------|
| MantlePassFactory | `0xae13506deae7f82ea5c1c646d0b6693b220a4bb8` |

### Mantle Sepolia Testnet
| Contract | Address |
|----------|---------|
| MantlePassFactory | `TBD` |

### Mantle Mainnet
| Contract | Address |
|----------|---------|
| MantlePassFactory | `TBD` |

---

## Troubleshooting

### "PRIVATE_KEY not found"
```bash
export PRIVATE_KEY=0x...
# Then run the deploy command
```

### "Insufficient funds"
- Localnet: Use Anvil's pre-funded key
- Testnet: Get MNT from faucet
- Mainnet: Ensure wallet has MNT for gas

### "RPC connection failed"
```bash
# Check if RPC is reachable
curl -X POST https://rpc.sepolia.mantle.xyz -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'
```

### Anvil not starting
```bash
# Kill any existing Anvil process
pkill anvil
# Restart
anvil --fork-url https://rpc.sepolia.mantle.xyz
```
