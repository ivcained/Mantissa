'use client';

import { useState, useCallback } from 'react';

// Contract addresses (update after deployment)
const FACTORY_ADDRESS = '0xae13506deae7f82ea5c1c646d0b6693b220a4bb8';
const RPC_URL = 'http://127.0.0.1:8545'; // Local Anvil fork

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
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (const byte of bytes) {
    result = (result << 8n) | BigInt(byte);
  }
  return result;
}

function bytesToHex(bytes: Uint8Array): string {
  return '0x' + Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

// Extract P-256 public key from SPKI or COSE format
function extractP256PublicKey(publicKeyBytes: Uint8Array): { x: bigint; y: bigint } {
  // Raw uncompressed point format (65 bytes, starts with 0x04)
  if (publicKeyBytes.length === 65 && publicKeyBytes[0] === 0x04) {
    const x = bytesToBigInt(publicKeyBytes.slice(1, 33));
    const y = bytesToBigInt(publicKeyBytes.slice(33, 65));
    return { x, y };
  }

  // SPKI format (starts with 0x30, ASN.1 SEQUENCE)
  // The uncompressed point (0x04 + 32 bytes X + 32 bytes Y) is at the end
  if (publicKeyBytes[0] === 0x30) {
    // Find the 0x04 marker followed by 64 bytes of key
    for (let i = publicKeyBytes.length - 65; i >= 0; i--) {
      if (publicKeyBytes[i] === 0x04) {
        const x = bytesToBigInt(publicKeyBytes.slice(i + 1, i + 33));
        const y = bytesToBigInt(publicKeyBytes.slice(i + 33, i + 65));
        return { x, y };
      }
    }
  }

  // COSE format - look for 0x58 0x20 (CBOR byte string of 32 bytes)
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
    throw new Error('Failed to extract public key from format');
  }

  return { x, y };
}

export default function Home() {
  const [wallet, setWallet] = useState<WalletInfo | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [logs, setLogs] = useState<string[]>([]);

  const addLog = (msg: string) => {
    setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${msg}`]);
  };

  const isSupported = typeof window !== 'undefined' &&
    window.PublicKeyCredential !== undefined;

  const createWallet = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    addLog('Starting wallet creation...');

    try {
      const userId = crypto.getRandomValues(new Uint8Array(16));

      addLog('Requesting passkey creation (check your browser)...');

      const credential = await navigator.credentials.create({
        publicKey: {
          rp: {
            id: window.location.hostname,
            name: 'Mantissa Demo',
          },
          user: {
            id: userId,
            name: 'demo@mantlepass.xyz',
            displayName: 'Demo User',
          },
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
          authenticatorSelection: {
            authenticatorAttachment: 'platform',
            residentKey: 'required',
            userVerification: 'required',
          },
          timeout: 60000,
          attestation: 'none',
        },
      }) as PublicKeyCredential;

      if (!credential) {
        throw new Error('Passkey creation cancelled');
      }

      addLog('Passkey created! Extracting public key...');

      const response = credential.response as AuthenticatorAttestationResponse;
      const publicKeyBytes = response.getPublicKey();

      if (!publicKeyBytes) {
        throw new Error('Failed to get public key');
      }

      const { x, y } = extractP256PublicKey(new Uint8Array(publicKeyBytes));

      const credentialInfo: PasskeyCredential = {
        id: bytesToBase64Url(new Uint8Array(credential.rawId)),
        rawId: new Uint8Array(credential.rawId),
        publicKeyX: x,
        publicKeyY: y,
      };

      const hashBuffer = await crypto.subtle.digest('SHA-256', credential.rawId);
      const credentialIdHash = bytesToHex(new Uint8Array(hashBuffer));
      const mockAddress = '0x' + credentialIdHash.slice(2, 42);

      const walletInfo: WalletInfo = {
        address: mockAddress,
        credentialIdHash,
        credential: credentialInfo,
      };

      setWallet(walletInfo);
      addLog(`✅ Wallet created!`);
      addLog(`Address: ${mockAddress}`);
      addLog(`Public Key X: ${x.toString(16).slice(0, 20)}...`);
      addLog(`Public Key Y: ${y.toString(16).slice(0, 20)}...`);

    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Unknown error';
      setError(msg);
      addLog(`❌ Error: ${msg}`);
    } finally {
      setIsLoading(false);
    }
  }, []);

  const signMessage = useCallback(async () => {
    if (!wallet) return;

    setIsLoading(true);
    addLog('Requesting signature (check your browser)...');

    try {
      const challenge = new TextEncoder().encode('Hello Mantissa!');

      const assertion = await navigator.credentials.get({
        publicKey: {
          challenge: challenge.buffer as ArrayBuffer,
          rpId: window.location.hostname,
          userVerification: 'required',
          timeout: 60000,
        },
      }) as PublicKeyCredential;

      if (!assertion) {
        throw new Error('Signing cancelled');
      }

      const response = assertion.response as AuthenticatorAssertionResponse;

      addLog('✅ Message signed!');
      addLog(`Authenticator Data: ${bytesToHex(new Uint8Array(response.authenticatorData)).slice(0, 40)}...`);
      addLog(`Signature: ${bytesToHex(new Uint8Array(response.signature)).slice(0, 40)}...`);

    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Unknown error';
      setError(msg);
      addLog(`❌ Error: ${msg}`);
    } finally {
      setIsLoading(false);
    }
  }, [wallet]);

  const disconnect = () => {
    setWallet(null);
    setLogs([]);
    addLog('Disconnected');
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 text-white">
      <div className="container mx-auto px-4 py-16 max-w-2xl">
        <div className="text-center mb-12">
          <h1 className="text-5xl font-bold mb-4 bg-gradient-to-r from-purple-400 to-pink-400 bg-clip-text text-transparent">
            Mantissa
          </h1>
          <p className="text-gray-400 text-lg">
            Passkey-native smart wallet for Mantle L2
          </p>
        </div>

        <div className="bg-white/5 backdrop-blur-lg rounded-2xl p-8 border border-white/10 mb-8">
          {!isSupported ? (
            <div className="text-center text-red-400">
              <p className="text-xl mb-2">⚠️ WebAuthn Not Supported</p>
              <p className="text-sm text-gray-400">
                Please use a modern browser with passkey support
              </p>
            </div>
          ) : !wallet ? (
            <div className="text-center">
              <div className="w-20 h-20 mx-auto mb-6 rounded-full bg-gradient-to-r from-purple-500 to-pink-500 flex items-center justify-center">
                <svg className="w-10 h-10" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
              </div>
              <h2 className="text-2xl font-semibold mb-4">Connect Your Wallet</h2>
              <p className="text-gray-400 mb-6">
                Create a seedless wallet using your device&apos;s biometrics
              </p>
              <button
                onClick={createWallet}
                disabled={isLoading}
                className="w-full py-4 px-6 bg-gradient-to-r from-purple-500 to-pink-500 rounded-xl font-semibold text-lg hover:opacity-90 transition-opacity disabled:opacity-50"
              >
                {isLoading ? 'Creating...' : '🔐 Create Passkey Wallet'}
              </button>
            </div>
          ) : (
            <div>
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-3">
                  <div className="w-12 h-12 rounded-full bg-gradient-to-r from-green-400 to-emerald-500 flex items-center justify-center">
                    <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
                    </svg>
                  </div>
                  <div>
                    <p className="text-sm text-gray-400">Connected</p>
                    <p className="font-mono text-sm">
                      {wallet.address.slice(0, 8)}...{wallet.address.slice(-6)}
                    </p>
                  </div>
                </div>
                <button
                  onClick={disconnect}
                  className="text-gray-400 hover:text-white transition-colors"
                >
                  Disconnect
                </button>
              </div>

              <button
                onClick={signMessage}
                disabled={isLoading}
                className="w-full py-3 px-6 bg-white/10 border border-white/20 rounded-xl font-medium hover:bg-white/20 transition-colors disabled:opacity-50"
              >
                {isLoading ? 'Signing...' : '✍️ Sign Message'}
              </button>
            </div>
          )}
        </div>

        {error && (
          <div className="bg-red-500/10 border border-red-500/20 rounded-xl p-4 mb-8">
            <p className="text-red-400">{error}</p>
          </div>
        )}

        {logs.length > 0 && (
          <div className="bg-black/30 rounded-xl p-4 font-mono text-sm">
            <p className="text-gray-500 mb-2">Console</p>
            <div className="space-y-1 max-h-48 overflow-y-auto">
              {logs.map((log, i) => (
                <p key={i} className="text-gray-300">{log}</p>
              ))}
            </div>
          </div>
        )}

        <div className="text-center mt-12 text-gray-500 text-sm">
          <p>Factory: <code className="text-purple-400">{FACTORY_ADDRESS}</code></p>
          <p>RPC: <code className="text-purple-400">{RPC_URL}</code></p>
        </div>
      </div>
    </div>
  );
}
