import {
  createPublicClient,
  createWalletClient,
  http,
  type Address,
  type Hex,
  type PublicClient,
  type WalletClient,
  keccak256,
  encodePacked,
  encodeAbiParameters,
  parseAbiParameters,
  encodeFunctionData,
} from 'viem';
import { mantleSepoliaTestnet, mantle } from 'viem/chains';
import type {
  MantlePassConfig,
  PasskeyCredential,
  WalletInfo,
  ExecuteParams,
  BatchExecuteParams,
  WalletState,
  ContractSignature,
} from '../types';
import {
  registerPasskey,
  signChallenge,
  formatSignatureForContract,
  type RegisterPasskeyOptions,
} from '../webauthn';
import { bytesToHex, hexToBytes, bytesToBase64Url } from '../utils';

// Contract ABIs (minimal for the functions we need)
const FACTORY_ABI = [
  {
    name: 'createWallet',
    type: 'function',
    inputs: [
      { name: 'credentialId', type: 'bytes32' },
      { name: 'pubKeyX', type: 'uint256' },
      { name: 'pubKeyY', type: 'uint256' },
      { name: 'recoveryAddress', type: 'address' },
    ],
    outputs: [{ name: 'wallet', type: 'address' }],
    stateMutability: 'payable',
  },
  {
    name: 'getWalletAddress',
    type: 'function',
    inputs: [{ name: 'credentialId', type: 'bytes32' }],
    outputs: [{ name: 'predicted', type: 'address' }],
    stateMutability: 'view',
  },
  {
    name: 'wallets',
    type: 'function',
    inputs: [{ name: 'credentialId', type: 'bytes32' }],
    outputs: [{ name: '', type: 'address' }],
    stateMutability: 'view',
  },
  {
    name: 'walletExists',
    type: 'function',
    inputs: [{ name: 'credentialId', type: 'bytes32' }],
    outputs: [{ name: 'exists', type: 'bool' }],
    stateMutability: 'view',
  },
] as const;

const WALLET_ABI = [
  {
    name: 'execute',
    type: 'function',
    inputs: [
      { name: 'target', type: 'address' },
      { name: 'value', type: 'uint256' },
      { name: 'data', type: 'bytes' },
      { name: 'credentialId', type: 'bytes32' },
      {
        name: 'signature',
        type: 'tuple',
        components: [
          { name: 'authenticatorData', type: 'bytes' },
          { name: 'clientDataJSON', type: 'string' },
          { name: 'r', type: 'uint256' },
          { name: 's', type: 'uint256' },
        ],
      },
    ],
    outputs: [{ name: 'result', type: 'bytes' }],
    stateMutability: 'nonpayable',
  },
  {
    name: 'executeBatch',
    type: 'function',
    inputs: [
      { name: 'targets', type: 'address[]' },
      { name: 'values', type: 'uint256[]' },
      { name: 'datas', type: 'bytes[]' },
      { name: 'credentialId', type: 'bytes32' },
      {
        name: 'signature',
        type: 'tuple',
        components: [
          { name: 'authenticatorData', type: 'bytes' },
          { name: 'clientDataJSON', type: 'string' },
          { name: 'r', type: 'uint256' },
          { name: 's', type: 'uint256' },
        ],
      },
    ],
    outputs: [{ name: 'results', type: 'bytes[]' }],
    stateMutability: 'nonpayable',
  },
  {
    name: 'nonce',
    type: 'function',
    inputs: [],
    outputs: [{ name: '', type: 'uint256' }],
    stateMutability: 'view',
  },
  {
    name: 'recoveryAddress',
    type: 'function',
    inputs: [],
    outputs: [{ name: '', type: 'address' }],
    stateMutability: 'view',
  },
  {
    name: 'getActivePasskeyCount',
    type: 'function',
    inputs: [],
    outputs: [{ name: 'count', type: 'uint256' }],
    stateMutability: 'view',
  },
  {
    name: 'getCredentialIds',
    type: 'function',
    inputs: [],
    outputs: [{ name: '', type: 'bytes32[]' }],
    stateMutability: 'view',
  },
  {
    name: 'getTransactionHash',
    type: 'function',
    inputs: [
      { name: 'target', type: 'address' },
      { name: 'value', type: 'uint256' },
      { name: 'data', type: 'bytes' },
      { name: '_nonce', type: 'uint256' },
    ],
    outputs: [{ name: '', type: 'bytes32' }],
    stateMutability: 'view',
  },
] as const;

/**
 * MantlePass SDK Client
 * 
 * @example
 * ```typescript
 * const client = new MantlePassClient({
 *   rpcUrl: 'https://rpc.sepolia.mantle.xyz',
 *   factoryAddress: '0x...',
 *   rpId: 'mantlepass.xyz',
 * });
 * 
 * // Create a wallet
 * const wallet = await client.createWallet({
 *   userName: 'user@example.com',
 * });
 * 
 * // Execute a transaction
 * const txHash = await client.execute(wallet, {
 *   target: '0x...',
 *   value: 1000000000000000000n, // 1 ETH
 * });
 * ```
 */
export class MantlePassClient {
  private publicClient: PublicClient;
  private config: Required<MantlePassConfig>;

  constructor(config: MantlePassConfig) {
    this.config = {
      chainId: config.chainId ?? 5003, // Default to Mantle Sepolia
      rpId: config.rpId ?? 'localhost',
      ...config,
    };

    const chain = this.config.chainId === 5000 ? mantle : mantleSepoliaTestnet;

    this.publicClient = createPublicClient({
      chain,
      transport: http(this.config.rpcUrl),
    });
  }

  /**
   * Create a new wallet with a passkey
   */
  async createWallet(options: {
    userName: string;
    userId?: string;
    recoveryAddress?: Address;
    initialFunding?: bigint;
  }): Promise<WalletInfo> {
    const { userName, userId = userName, recoveryAddress, initialFunding } = options;

    // Register passkey
    const credential = await registerPasskey({
      rpId: this.config.rpId,
      rpName: 'MantlePass',
      userId,
      userName,
    });

    // Compute credential ID hash
    const credentialIdHash = keccak256(bytesToHex(credential.rawId));

    // Get predicted wallet address
    const walletAddress = await this.getWalletAddress(credentialIdHash);

    return {
      address: walletAddress,
      credentialIdHash,
      credential,
    };
  }

  /**
   * Get the predicted wallet address for a credential ID hash
   */
  async getWalletAddress(credentialIdHash: Hex): Promise<Address> {
    const address = await this.publicClient.readContract({
      address: this.config.factoryAddress,
      abi: FACTORY_ABI,
      functionName: 'getWalletAddress',
      args: [credentialIdHash],
    });
    return address;
  }

  /**
   * Check if a wallet exists for a credential ID hash
   */
  async walletExists(credentialIdHash: Hex): Promise<boolean> {
    const exists = await this.publicClient.readContract({
      address: this.config.factoryAddress,
      abi: FACTORY_ABI,
      functionName: 'walletExists',
      args: [credentialIdHash],
    });
    return exists;
  }

  /**
   * Get wallet state
   */
  async getWalletState(walletAddress: Address): Promise<WalletState> {
    const [nonce, recoveryAddress, activePasskeyCount, credentialIds] = await Promise.all([
      this.publicClient.readContract({
        address: walletAddress,
        abi: WALLET_ABI,
        functionName: 'nonce',
      }),
      this.publicClient.readContract({
        address: walletAddress,
        abi: WALLET_ABI,
        functionName: 'recoveryAddress',
      }),
      this.publicClient.readContract({
        address: walletAddress,
        abi: WALLET_ABI,
        functionName: 'getActivePasskeyCount',
      }),
      this.publicClient.readContract({
        address: walletAddress,
        abi: WALLET_ABI,
        functionName: 'getCredentialIds',
      }),
    ]);

    return {
      address: walletAddress,
      nonce,
      recoveryAddress,
      activePasskeyCount: Number(activePasskeyCount),
      credentialIds: credentialIds as Hex[],
    };
  }

  /**
   * Get the transaction hash for signing
   */
  async getTransactionHash(
    walletAddress: Address,
    params: ExecuteParams,
    nonce: bigint
  ): Promise<Hex> {
    const hash = await this.publicClient.readContract({
      address: walletAddress,
      abi: WALLET_ABI,
      functionName: 'getTransactionHash',
      args: [
        params.target,
        params.value ?? 0n,
        params.data ?? '0x',
        nonce,
      ],
    });
    return hash;
  }

  /**
   * Sign a transaction with passkey
   */
  async signTransaction(
    walletAddress: Address,
    params: ExecuteParams,
    credentialId?: string
  ): Promise<{
    signature: ContractSignature;
    credentialIdHash: Hex;
  }> {
    // Get current nonce
    const nonce = await this.publicClient.readContract({
      address: walletAddress,
      abi: WALLET_ABI,
      functionName: 'nonce',
    });

    // Get transaction hash
    const txHash = await this.getTransactionHash(walletAddress, params, nonce);

    // Sign with passkey
    const challenge = hexToBytes(txHash);
    const assertion = await signChallenge(challenge, this.config.rpId, credentialId);

    // Format for contract
    const signature = formatSignatureForContract(assertion);

    // If credentialId was provided, hash it; otherwise we need to figure it out
    const credentialIdHash = credentialId
      ? keccak256(bytesToHex(hexToBytes(credentialId as Hex)))
      : '0x0000000000000000000000000000000000000000000000000000000000000000';

    return {
      signature,
      credentialIdHash,
    };
  }

  /**
   * Build the execute transaction data
   */
  buildExecuteData(
    params: ExecuteParams,
    credentialIdHash: Hex,
    signature: ContractSignature
  ): Hex {
    return encodeFunctionData({
      abi: WALLET_ABI,
      functionName: 'execute',
      args: [
        params.target,
        params.value ?? 0n,
        params.data ?? '0x',
        credentialIdHash,
        {
          authenticatorData: signature.authenticatorData,
          clientDataJSON: signature.clientDataJSON,
          r: signature.r,
          s: signature.s,
        },
      ],
    });
  }

  /**
   * Build the batch execute transaction data
   */
  buildBatchExecuteData(
    params: BatchExecuteParams,
    credentialIdHash: Hex,
    signature: ContractSignature
  ): Hex {
    return encodeFunctionData({
      abi: WALLET_ABI,
      functionName: 'executeBatch',
      args: [
        params.targets,
        params.values,
        params.datas,
        credentialIdHash,
        {
          authenticatorData: signature.authenticatorData,
          clientDataJSON: signature.clientDataJSON,
          r: signature.r,
          s: signature.s,
        },
      ],
    });
  }

  /**
   * Get the factory contract address
   */
  get factoryAddress(): Address {
    return this.config.factoryAddress;
  }

  /**
   * Get the RP ID for WebAuthn
   */
  get rpId(): string {
    return this.config.rpId;
  }
}
