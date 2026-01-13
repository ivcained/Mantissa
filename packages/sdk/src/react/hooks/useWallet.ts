'use client';

import { useCallback, useState } from 'react';
import { useMantlePass } from '../MantlePassProvider';
import type { WalletInfo } from '../../types';
import {
  isWebAuthnSupported,
  isPlatformAuthenticatorAvailable,
} from '../../webauthn';

/**
 * Hook for wallet connection and state
 * 
 * @example
 * ```tsx
 * function ConnectButton() {
 *   const { connect, disconnect, isConnected, walletAddress, isLoading } = useWallet();
 * 
 *   if (isConnected) {
 *     return (
 *       <div>
 *         <p>Connected: {walletAddress}</p>
 *         <button onClick={disconnect}>Disconnect</button>
 *       </div>
 *     );
 *   }
 * 
 *   return (
 *     <button onClick={() => connect('user@example.com')} disabled={isLoading}>
 *       {isLoading ? 'Connecting...' : 'Connect with Passkey'}
 *     </button>
 *   );
 * }
 * ```
 */
export function useWallet() {
  const {
    wallet,
    walletState,
    isConnected,
    isLoading,
    error,
    connect: contextConnect,
    disconnect,
    refreshState,
  } = useMantlePass();

  const [isSupported, setIsSupported] = useState<boolean | null>(null);

  // Check WebAuthn support
  const checkSupport = useCallback(async () => {
    const supported =
      isWebAuthnSupported() && (await isPlatformAuthenticatorAvailable());
    setIsSupported(supported);
    return supported;
  }, []);

  // Connect with user-friendly wrapper
  const connect = useCallback(
    async (userName: string): Promise<WalletInfo> => {
      // Check support first
      const supported = await checkSupport();
      if (!supported) {
        throw new Error('Passkeys are not supported on this device');
      }

      return contextConnect(userName);
    },
    [contextConnect, checkSupport]
  );

  return {
    // State
    wallet,
    walletAddress: wallet?.address ?? null,
    walletState,
    isConnected,
    isLoading,
    error,
    isSupported,

    // Actions
    connect,
    disconnect,
    refreshState,
    checkSupport,
  };
}
