"use client";

import { useState, useCallback, useEffect } from "react";
import {
  createPublicClient,
  createWalletClient,
  custom,
  http,
  parseEther,
  encodeFunctionData,
  keccak256,
  encodeAbiParameters,
  parseAbiParameters,
  type Address,
  type Hash,
  hexToBytes,
} from "viem";
import { mantleSepoliaTestnet } from "viem/chains";
import { privateKeyToAccount } from "viem/accounts";

// Contract addresses
const FACTORY_ADDRESS = "0x876DBabB4A37cCB97D5ca4285444f1BcE06220a6";
const RPC_URL = "https://rpc.sepolia.mantle.xyz";

// ABIs
const WALLET_ABI = [
  {
    name: "nonce",
    type: "function",
    inputs: [],
    outputs: [{ name: "", type: "uint256" }],
    stateMutability: "view",
  },
  {
    name: "getTransactionHash",
    type: "function",
    inputs: [
      { name: "target", type: "address" },
      { name: "value", type: "uint256" },
      { name: "data", type: "bytes" },
      { name: "_nonce", type: "uint256" },
    ],
    outputs: [{ name: "", type: "bytes32" }],
    stateMutability: "view",
  },
  {
    name: "execute",
    type: "function",
    inputs: [
      { name: "target", type: "address" },
      { name: "value", type: "uint256" },
      { name: "data", type: "bytes" },
      { name: "credentialId", type: "bytes32" },
      {
        name: "signature",
        type: "tuple",
        components: [
          { name: "authenticatorData", type: "bytes" },
          { name: "clientDataJSON", type: "string" },
          { name: "r", type: "uint256" },
          { name: "s", type: "uint256" },
        ],
      },
    ],
    outputs: [{ name: "result", type: "bytes" }],
    stateMutability: "nonpayable",
  },
] as const;

const FACTORY_ABI = [
  {
    name: "getWalletAddress",
    type: "function",
    inputs: [{ name: "credentialId", type: "bytes32" }],
    outputs: [{ name: "predicted", type: "address" }],
    stateMutability: "view",
  },
  {
    name: "createWallet",
    type: "function",
    inputs: [
      { name: "credentialId", type: "bytes32" },
      { name: "pubKeyX", type: "uint256" },
      { name: "pubKeyY", type: "uint256" },
      { name: "recoveryAddress", type: "address" },
    ],
    outputs: [{ name: "wallet", type: "address" }],
    stateMutability: "payable",
  },
] as const;

// Types
interface PasskeyCredential {
  id: string;
  rawId: Uint8Array;
  publicKeyX: bigint;
  publicKeyY: bigint;
}

interface WalletInfo {
  address: string;
  credentialIdHash: string;
  credential: PasskeyCredential;
}

// Utility functions
function bytesToBase64Url(bytes: Uint8Array): string {
  const binary = String.fromCharCode(...bytes);
  const base64 = btoa(binary);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const byte of bytes) {
    result = (result << 8n) | BigInt(byte);
  }
  return result;
}

function bytesToHex(bytes: Uint8Array): string {
  return (
    "0x" +
    Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("")
  );
}

// Extract P-256 public key from SPKI or COSE format
function extractP256PublicKey(publicKeyBytes: Uint8Array): {
  x: bigint;
  y: bigint;
} {
  if (publicKeyBytes.length === 65 && publicKeyBytes[0] === 0x04) {
    const x = bytesToBigInt(publicKeyBytes.slice(1, 33));
    const y = bytesToBigInt(publicKeyBytes.slice(33, 65));
    return { x, y };
  }

  if (publicKeyBytes[0] === 0x30) {
    for (let i = publicKeyBytes.length - 65; i >= 0; i--) {
      if (publicKeyBytes[i] === 0x04) {
        const x = bytesToBigInt(publicKeyBytes.slice(i + 1, i + 33));
        const y = bytesToBigInt(publicKeyBytes.slice(i + 33, i + 65));
        return { x, y };
      }
    }
  }

  let x: bigint = BigInt(0);
  let y: bigint = BigInt(0);

  for (let i = 0; i < publicKeyBytes.length - 32; i++) {
    if (publicKeyBytes[i] === 0x58 && publicKeyBytes[i + 1] === 0x20) {
      const coord = publicKeyBytes.slice(i + 2, i + 34);
      if (x === BigInt(0)) {
        x = bytesToBigInt(coord);
      } else {
        y = bytesToBigInt(coord);
        break;
      }
    }
  }

  if (x === BigInt(0) || y === BigInt(0)) {
    throw new Error("Failed to extract public key from format");
  }

  return { x, y };
}

export default function Home() {
  const [wallet, setWallet] = useState<WalletInfo | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [messageInput, setMessageInput] = useState("");
  const [copied, setCopied] = useState(false);
  const [recipient, setRecipient] = useState("");
  const [amount, setAmount] = useState("");

  const addLog = (msg: string) => {
    setLogs((prev) => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`]);
  };

  const isSupported =
    typeof window !== "undefined" && window.PublicKeyCredential !== undefined;

  // Helper to get the correct provider (prefer MetaMask over Phantom)
  const getEthereumProvider = () => {
    if (typeof window === "undefined") return null;
    const eth = (window as any).ethereum;
    if (!eth) return null;

    if (eth.providers) {
      const metamask = eth.providers.find(
        (p: any) => p.isMetaMask && !p.isPhantom
      );
      if (metamask) return metamask;
    }

    if (eth.isPhantom && !eth.isMetaMask) {
      console.warn(
        "Phantom detected as default. Please disable Phantom or use a profile with only MetaMask."
      );
    }

    return eth;
  };

  const switchChain = async () => {
    const provider = getEthereumProvider();
    if (provider) {
      try {
        await provider.request({
          method: "wallet_switchEthereumChain",
          params: [{ chainId: "0x138B" }], // 5003 in hex
        });
      } catch (switchError: any) {
        if (switchError.code === 4902) {
          await provider.request({
            method: "wallet_addEthereumChain",
            params: [
              {
                chainId: "0x138B",
                chainName: "Mantle Sepolia Testnet",
                nativeCurrency: { name: "MNT", symbol: "MNT", decimals: 18 },
                rpcUrls: ["https://rpc.sepolia.mantle.xyz"],
                blockExplorerUrls: ["https://explorer.sepolia.mantle.xyz/"],
              },
            ],
          });
        }
      }
    }
  };

  const createWallet = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    addLog("Starting wallet creation...");

    try {
      await switchChain();

      const context = crypto.getRandomValues(new Uint8Array(16));
      addLog("Requesting passkey creation (check your browser)...");

      const credential = (await navigator.credentials.create({
        publicKey: {
          rp: {
            id: window.location.hostname,
            name: "Mantissa Demo",
          },
          user: {
            id: context,
            name: "demo@mantlepass.xyz",
            displayName: "Demo User",
          },
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          pubKeyCredParams: [{ type: "public-key", alg: -7 }],
          authenticatorSelection: {
            authenticatorAttachment: "platform",
            residentKey: "required",
            userVerification: "required",
          },
          timeout: 60000,
          attestation: "none",
        },
      })) as PublicKeyCredential;

      if (!credential) throw new Error("Passkey creation cancelled");

      addLog("Passkey created! Extracting public key...");

      const response = credential.response as AuthenticatorAttestationResponse;
      const publicKeyBytes = response.getPublicKey();
      if (!publicKeyBytes) throw new Error("Failed to get public key");

      const { x, y } = extractP256PublicKey(new Uint8Array(publicKeyBytes));

      const credentialInfo: PasskeyCredential = {
        id: bytesToBase64Url(new Uint8Array(credential.rawId)),
        rawId: new Uint8Array(credential.rawId),
        publicKeyX: x,
        publicKeyY: y,
      };

      const hashBuffer = await crypto.subtle.digest(
        "SHA-256",
        credential.rawId
      );
      const credentialIdHash = bytesToHex(new Uint8Array(hashBuffer));

      // Calculate address without deployment
      addLog("Calculating Wallet Address...");

      const publicClient = createPublicClient({
        chain: mantleSepoliaTestnet,
        transport: http(RPC_URL),
      });

      const predictedAddress = await publicClient.readContract({
        address: FACTORY_ADDRESS as Address,
        abi: FACTORY_ABI,
        functionName: "getWalletAddress",
        args: [credentialIdHash as `0x${string}`],
      });

      const walletInfo: WalletInfo = {
        address: predictedAddress,
        credentialIdHash,
        credential: credentialInfo,
      };

      setWallet(walletInfo);
      addLog(`✅ Connected: ${predictedAddress}`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setError(msg);
      addLog(`❌ Error: ${msg}`);
    } finally {
      setIsLoading(false);
    }
  }, []);

  const signMessage = useCallback(async () => {
    if (!wallet) return;
    setIsLoading(true);
    setError(null);
    addLog("Signing a test message...");

    try {
      const message = messageInput || "Hello Mantissa!";
      const challenge = new Uint8Array(32);
      const encoder = new TextEncoder();
      const msgBytes = encoder.encode(message);
      for (let i = 0; i < 32; i++)
        challenge[i] = msgBytes[i % msgBytes.length] || 0;

      const assertion = (await navigator.credentials.get({
        publicKey: {
          challenge: challenge.buffer as ArrayBuffer,
          rpId: window.location.hostname,
          userVerification: "required",
        },
      })) as PublicKeyCredential;

      if (assertion) {
        addLog(`✅ Message Signed: "${message}"`);
      }
    } catch (e: any) {
      setError(e.message);
      addLog(`❌ Sign Error: ${e.message}`);
    } finally {
      setIsLoading(false);
    }
  }, [wallet, messageInput]);

  const handleSend = async () => {
    if (!wallet || !recipient || !amount) {
      setError("Please check wallet connection and inputs");
      return;
    }
    setIsLoading(true);
    setError(null);

    try {
      addLog(`Initiating Transfer of ${amount} MNT to ${recipient}...`);
      await switchChain();

      const client = getEthereumProvider();
      if (!client) throw new Error("No provider found");

      const publicClient = createPublicClient({
        chain: mantleSepoliaTestnet,
        transport: http(RPC_URL),
      });

      const walletClient = createWalletClient({
        chain: mantleSepoliaTestnet,
        transport: custom(client),
      });
      const [account] = await walletClient.requestAddresses();

      // 1. Check if wallet is deployed (Lazy Deployment)
      addLog("Checking wallet deployment status...");
      const code = await publicClient.getBytecode({
        address: wallet.address as Address,
      });

      if (!code || code === "0x") {
        addLog("⚠️ Wallet not deployed. Deploying now (lazy init)...");

        const { request } = await publicClient.simulateContract({
          address: FACTORY_ADDRESS as Address,
          abi: FACTORY_ABI,
          functionName: "createWallet",
          args: [
            wallet.credentialIdHash as `0x${string}`,
            wallet.credential.publicKeyX,
            wallet.credential.publicKeyY,
            account, // Recover address = sender
          ],
          account,
        });

        const hash = await walletClient.writeContract(request);
        addLog(`Deploy Tx Sent: ${hash.slice(0, 10)}...`);
        await publicClient.waitForTransactionReceipt({ hash });
        addLog("✅ Wallet Successfully Deployed!");
      }

      // 2. Prepare Transaction
      addLog("Preparing transaction...");

      const nonce = await publicClient.readContract({
        address: wallet.address as Address,
        abi: WALLET_ABI,
        functionName: "nonce",
      });

      const target = recipient as Address;
      const value = parseEther(amount);
      const data = "0x";
      const dataHash = keccak256(data);

      // Calculate hash to sign (same as solidity _hashTransaction)
      // keccak256(abi.encode(address(this), block.chainid, target, value, keccak256(data), nonce))
      const chainId = 5003; // Mantle Sepolia (or 5003 for Anvil fork if configured) - assuming 5003 based on switchChain

      const encodedHashData = encodeAbiParameters(
        parseAbiParameters(
          "address, uint256, address, uint256, bytes32, uint256"
        ),
        [
          wallet.address as Address,
          BigInt(chainId),
          target,
          value,
          dataHash,
          nonce,
        ]
      );

      const txHash = keccak256(encodedHashData);

      // 3. Sign with Passkey
      addLog("Requesting Passkey Signature...");
      const challenge = hexToBytes(txHash); // convert hex hash to bytes for WebAuthn challenge

      // Pad or truncate challenge to 32 bytes if needed? Keccak is 32 bytes.
      // WebAuthn challenge buffer.

      const assertion = (await navigator.credentials.get({
        publicKey: {
          challenge: challenge.buffer as ArrayBuffer,
          rpId: window.location.hostname,
          userVerification: "required",
        },
      })) as PublicKeyCredential;

      if (!assertion) throw new Error("User cancelled signing");

      // 4. Parse Signature
      const response = assertion.response as AuthenticatorAssertionResponse;
      const signatureData = {
        authenticatorData:
          "0x" +
          bytesToHex(new Uint8Array(response.authenticatorData)).slice(2),
        clientDataJSON: new TextDecoder().decode(response.clientDataJSON),
        r: BigInt(0), // Signature parsing needed here
        s: BigInt(0),
      };

      // Simple signature parsing for P-256 (ASN.1 DER to r,s)
      const sigBytes = new Uint8Array(response.signature);
      // DER sequence: 0x30 + len + 0x02 + lenR + R + 0x02 + lenS + S
      let pos = 2; // skip sequence header
      const rLen = sigBytes[pos + 1];
      const rStart = pos + 2;
      const rBytes = sigBytes.slice(rStart, rStart + rLen);
      signatureData.r = bytesToBigInt(rBytes);

      pos = rStart + rLen;
      const sLen = sigBytes[pos + 1];
      const sStart = pos + 2;
      const sBytes = sigBytes.slice(sStart, sStart + sLen);
      signatureData.s = bytesToBigInt(sBytes);

      addLog("✅ Signature generated. Executing on-chain...");

      // 5. Execute on Wallet
      const execHash = await walletClient.writeContract({
        address: wallet.address as Address,
        abi: WALLET_ABI,
        functionName: "execute",
        args: [
          target,
          value,
          data,
          wallet.credentialIdHash as `0x${string}`,
          {
            authenticatorData: signatureData.authenticatorData as `0x${string}`,
            clientDataJSON: signatureData.clientDataJSON,
            r: signatureData.r,
            s: signatureData.s,
          },
        ],
        account,
      });

      addLog(`🚀 Transaction Sent! Hash: ${execHash}`);
      await publicClient.waitForTransactionReceipt({ hash: execHash });
      addLog(`✅ Transaction Confirmed!`);
      setAmount("");
      setRecipient("");
    } catch (e: any) {
      console.error(e);
      setError(e.message || "Transaction failed");
      addLog(`❌ Error: ${e.message || "Transaction failed"}`);
    } finally {
      setIsLoading(false);
    }
  };

  const disconnect = () => {
    setWallet(null);
    setLogs([]);
    addLog("Disconnected");
  };

  const copyAddress = async () => {
    if (!wallet?.address) return;
    await navigator.clipboard.writeText(wallet.address);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const fundWallet = async () => {
    if (!wallet) return;
    setIsLoading(true);
    addLog("Funding accounts from Local Anvil Whale...");
    try {
      const client = createWalletClient({
        chain: mantleSepoliaTestnet,
        transport: http(RPC_URL),
      });

      // precise default anvil private key #0
      const whale = privateKeyToAccount(
        "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
      );

      // 1. Get EOA (MetaMask) Address to fund for gas
      const provider = getEthereumProvider();
      let eoaAddress: Address | undefined;
      if (provider) {
        const accounts = await provider.request({
          method: "eth_requestAccounts",
        });
        if (accounts && accounts.length > 0) {
          eoaAddress = accounts[0] as Address;
        }
      }

      // 2. Fund EOA (Gas Payer)
      if (eoaAddress) {
        const hashEOA = await client.sendTransaction({
          account: whale,
          to: eoaAddress,
          value: parseEther("5"),
        });
        addLog(`Funded Gas Payer (MetaMask): ${hashEOA}`);
      }

      // 3. Fund Smart Wallet (Asset Sender)
      const hashWallet = await client.sendTransaction({
        account: whale,
        to: wallet.address as Address,
        value: parseEther("10"),
      });

      addLog(`Funded Smart Wallet: ${hashWallet}`);
    } catch (e: any) {
      setError(e.message);
      addLog(`❌ Funding Failed: ${e.message}`);
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex flex-col items-center justify-center p-4 relative overflow-hidden">
      <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-[var(--accent)] opacity-[0.03] blur-[100px] rounded-full pointer-events-none" />
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-[var(--accent)] opacity-[0.03] blur-[100px] rounded-full pointer-events-none" />

      <div className="text-center mb-12 relative z-10">
        <h1 className="text-6xl md:text-8xl font-bold mb-2 tracking-tighter neon-text-glow font-sans">
          MANTISSA
        </h1>
        <h2 className="text-xl md:text-2xl font-mono text-[var(--accent)] tracking-[0.3em] uppercase mb-4 opacity-80">
          Seedless Smart Wallet
        </h2>
        <p className="text-[var(--text-secondary)] text-sm md:text-base font-mono max-w-md mx-auto leading-relaxed opacity-60">
          Biometric security meets Mantle L2. <br />
          No seed phrases. Just you.
        </p>
      </div>

      <div className="glass-card rounded-3xl p-1 w-full max-w-[520px] relative">
        <div className="bg-[rgba(2,13,8,0.4)] rounded-[20px] p-6 md:p-8 backdrop-blur-sm">
          {!isSupported ? (
            <div className="text-center py-12">
              <div className="text-red-500 mb-4 text-5xl">⚠️</div>
              <p className="text-xl mb-2 text-red-400 font-mono">
                WebAuthn Not Supported
              </p>
              <p className="text-sm text-[var(--text-secondary)]">
                Please use a modern browser
              </p>
            </div>
          ) : !wallet ? (
            <div className="flex flex-col gap-6">
              <div className="space-y-4">
                <div className="bg-[rgba(0,255,204,0.03)] border border-[rgba(0,255,204,0.1)] rounded-xl p-4 flex justify-between items-center">
                  <span className="text-[var(--text-secondary)] font-mono text-sm">
                    NETWORK
                  </span>
                  <span className="text-[var(--accent)] font-mono font-bold">
                    MANTLE L2
                  </span>
                </div>
                <div className="bg-[rgba(0,255,204,0.03)] border border-[rgba(0,255,204,0.1)] rounded-xl p-4 flex justify-between items-center">
                  <span className="text-[var(--text-secondary)] font-mono text-sm">
                    SECURITY
                  </span>
                  <div className="flex items-center gap-2">
                    <span className="w-2 h-2 rounded-full bg-[var(--accent)] neon-glow"></span>
                    <span className="text-[var(--accent)] font-mono font-bold">
                      P-256 SECURE
                    </span>
                  </div>
                </div>
              </div>

              <div className="h-px w-full bg-gradient-to-r from-transparent via-[rgba(0,255,204,0.2)] to-transparent my-2" />

              <button
                onClick={createWallet}
                disabled={isLoading}
                className="w-full py-5 rounded-xl font-bold text-lg tracking-widest transition-all duration-300
                  bg-[var(--accent)] text-black hover:opacity-90 hover:scale-[1.02] neon-glow disabled:opacity-50 disabled:cursor-not-allowed uppercase"
              >
                {isLoading ? (
                  <span className="flex items-center justify-center gap-3">
                    <svg className="animate-spin h-5 w-5" viewBox="0 0 24 24">
                      <circle
                        className="opacity-25"
                        cx="12"
                        cy="12"
                        r="10"
                        stroke="currentColor"
                        strokeWidth="4"
                        fill="none"
                      />
                      <path
                        className="opacity-75"
                        fill="currentColor"
                        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                      />
                    </svg>
                    CREATING...
                  </span>
                ) : (
                  "CREATE PASSKEY WALLET"
                )}
              </button>
            </div>
          ) : (
            <div className="flex flex-col gap-6">
              <div className="bg-[rgba(0,255,204,0.05)] border border-[var(--accent)] rounded-xl p-6 text-center relative overflow-hidden">
                <div className="absolute top-0 left-0 w-full h-1 bg-[var(--accent)] neon-glow" />

                <div className="w-16 h-16 mx-auto mb-4 rounded-full bg-[rgba(0,255,204,0.1)] border border-[var(--accent)] flex items-center justify-center neon-glow">
                  <svg
                    className="w-8 h-8 text-[var(--accent)]"
                    fill="none"
                    stroke="currentColor"
                    viewBox="0 0 24 24"
                  >
                    <path
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      strokeWidth={2}
                      d="M5 13l4 4L19 7"
                    />
                  </svg>
                </div>

                <p className="text-[var(--text-secondary)] text-sm font-mono mb-1">
                  CONNECTED WALLET
                </p>
                <div className="flex items-center justify-center gap-2">
                  <p className="text-xl md:text-2xl font-mono text-white tracking-wider break-all">
                    {wallet.address.slice(0, 6)}...{wallet.address.slice(-4)}
                  </p>
                  <button
                    onClick={copyAddress}
                    className="p-2 rounded-full hover:bg-[rgba(0,255,204,0.1)] transition-colors text-[var(--accent)]"
                    title="Copy Address"
                  >
                    {copied ? (
                      <svg
                        className="w-5 h-5"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M5 13l4 4L19 7"
                        />
                      </svg>
                    ) : (
                      <svg
                        className="w-5 h-5"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z"
                        />
                      </svg>
                    )}
                  </button>
                </div>
              </div>

              {/* Actions Grid */}
              <div className="space-y-4">
                <div>
                  <label className="text-[var(--text-secondary)] font-mono text-xs mb-1 block pl-1">
                    MESSAGE TO SIGN
                  </label>
                  <input
                    type="text"
                    placeholder="Hello Mantissa!"
                    value={messageInput}
                    onChange={(e) => setMessageInput(e.target.value)}
                    className="w-full bg-[rgba(0,0,0,0.3)] border border-[rgba(0,255,204,0.2)] rounded-xl p-4 text-[var(--foreground)] font-mono text-sm focus:outline-none focus:border-[var(--accent)] transition-colors"
                  />
                </div>
                <div className="grid grid-cols-2 gap-4">
                  <button
                    onClick={disconnect}
                    className="py-4 rounded-xl font-mono border border-[rgba(0,255,204,0.2)] text-[var(--text-secondary)] hover:text-[var(--accent)] hover:border-[var(--accent)] transition-colors"
                  >
                    DISCONNECT
                  </button>
                  <button
                    onClick={signMessage}
                    disabled={isLoading}
                    className="py-4 rounded-xl font-bold font-mono tracking-wide
                        bg-[rgba(0,255,204,0.1)] text-[var(--accent)] border border-[var(--accent)] hover:bg-[rgba(0,255,204,0.2)] neon-glow transition-all"
                  >
                    {isLoading ? "SIGNING..." : "SIGN MSG"}
                  </button>
                  <button
                    onClick={fundWallet}
                    disabled={isLoading}
                    className="col-span-2 py-3 rounded-xl font-mono text-xs border border-yellow-500/30 text-yellow-400 hover:bg-yellow-500/10 transition-colors"
                  >
                    💰 GET 10 TEST MNT (LOCAL ONLY)
                  </button>
                </div>
              </div>

              {/* Transfer UI */}
              <div className="bg-[rgba(0,255,204,0.02)] border border-[rgba(0,255,204,0.1)] rounded-xl p-4 space-y-4">
                <p className="text-[var(--text-secondary)] font-mono text-xs uppercase tracking-widest">
                  Send Assets
                </p>
                <div className="space-y-3">
                  <input
                    type="text"
                    placeholder="Recipient Address (0x...)"
                    value={recipient}
                    onChange={(e) => setRecipient(e.target.value)}
                    className="w-full bg-[rgba(0,0,0,0.3)] border border-[rgba(0,255,204,0.2)] rounded-xl p-3 text-[var(--foreground)] font-mono text-sm focus:outline-none focus:border-[var(--accent)] transition-colors"
                  />
                  <input
                    type="text"
                    placeholder="Amount (MNT)"
                    value={amount}
                    onChange={(e) => setAmount(e.target.value)}
                    className="w-full bg-[rgba(0,0,0,0.3)] border border-[rgba(0,255,204,0.2)] rounded-xl p-3 text-[var(--foreground)] font-mono text-sm focus:outline-none focus:border-[var(--accent)] transition-colors"
                  />
                  <button
                    onClick={handleSend}
                    disabled={isLoading}
                    className="w-full py-3 rounded-xl font-bold font-mono tracking-wide bg-[var(--accent)] text-black hover:opacity-90 hover:scale-[1.01] neon-glow transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {isLoading ? "SENDING..." : "SEND MNT"}
                  </button>
                </div>
              </div>
            </div>
          )}

          {error && (
            <div className="mt-6 bg-[rgba(255,50,50,0.1)] border border-red-500/50 rounded-xl p-4 animate-in fade-in slide-in-from-top-2">
              <p className="text-red-400 text-sm font-mono text-center break-words">
                {error}
              </p>
            </div>
          )}
        </div>
      </div>

      {logs.length > 0 && (
        <div className="mt-8 w-full max-w-[1000px] glass-card rounded-xl p-4 overflow-hidden">
          <div className="flex justify-between items-center mb-2 px-2">
            <span className="text-[var(--accent)] font-mono text-xs tracking-widest uppercase">
              System Logs
            </span>
            <div className="flex gap-1">
              <div className="w-2 h-2 rounded-full bg-red-500/50" />
              <div className="w-2 h-2 rounded-full bg-yellow-500/50" />
              <div className="w-2 h-2 rounded-full bg-green-500/50" />
            </div>
          </div>
          <div className="bg-[rgba(0,0,0,0.5)] rounded-lg p-3 font-mono text-sm h-48 overflow-y-auto space-y-1 custom-scrollbar">
            {logs.map((log, i) => (
              <div key={i} className="flex gap-2">
                <span className="text-[var(--text-secondary)] opacity-50">
                  {log.split("]")[0]}]
                </span>
                <span className="text-[var(--foreground)] break-all">
                  {log.split("]")[1]}
                </span>
              </div>
            ))}
            <div ref={(el) => el?.scrollIntoView({ behavior: "smooth" })} />
          </div>
        </div>
      )}

      <div className="mt-12 text-center">
        <div className="inline-flex items-center gap-6 text-[var(--text-secondary)] text-xs font-mono tracking-widest opacity-60">
          <span>FACTORY: {FACTORY_ADDRESS.slice(0, 6)}...</span>
          <span>•</span>
          <span>
            RPC: {RPC_URL.includes("localhost") ? "LOCALHOST" : "TESTNET"}
          </span>
        </div>
      </div>
    </div>
  );
}
