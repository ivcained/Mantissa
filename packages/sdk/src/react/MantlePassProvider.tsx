'use client';

import React, {
    createContext,
    useContext,
    useState,
    useCallback,
    useMemo,
    type ReactNode,
} from 'react';
import { MantlePassClient } from '../client';
import type {
    MantlePassConfig,
    WalletInfo,
    WalletState,
    ExecuteParams,
    ContractSignature,
} from '../types';
import type { Address, Hex } from 'viem';

/**
 * Context value for MantlePass
 */
interface MantlePassContextValue {
    /** The SDK client instance */
    client: MantlePassClient | null;
    /** Current wallet info (if connected) */
    wallet: WalletInfo | null;
    /** Current wallet state */
    walletState: WalletState | null;
    /** Whether a wallet is connected */
    isConnected: boolean;
    /** Whether an operation is loading */
    isLoading: boolean;
    /** Error message if any */
    error: string | null;
    /** Connect/create a wallet */
    connect: (userName: string) => Promise<WalletInfo>;
    /** Disconnect the wallet */
    disconnect: () => void;
    /** Sign a transaction */
    signTransaction: (params: ExecuteParams) => Promise<{
        signature: ContractSignature;
        credentialIdHash: Hex;
    }>;
    /** Refresh wallet state */
    refreshState: () => Promise<void>;
}

const MantlePassContext = createContext<MantlePassContextValue | null>(null);

/**
 * Props for MantlePassProvider
 */
interface MantlePassProviderProps extends MantlePassConfig {
    children: ReactNode;
}

/**
 * Provider component for MantlePass SDK
 * 
 * @example
 * ```tsx
 * import { MantlePassProvider } from '@mantlepass/sdk/react';
 * 
 * function App() {
 *   return (
 *     <MantlePassProvider
 *       rpcUrl="https://rpc.sepolia.mantle.xyz"
 *       factoryAddress="0x..."
 *       rpId="mantlepass.xyz"
 *     >
 *       <YourApp />
 *     </MantlePassProvider>
 *   );
 * }
 * ```
 */
export function MantlePassProvider({
    children,
    rpcUrl,
    factoryAddress,
    chainId,
    rpId,
}: MantlePassProviderProps) {
    const [wallet, setWallet] = useState<WalletInfo | null>(null);
    const [walletState, setWalletState] = useState<WalletState | null>(null);
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    // Create client instance
    const client = useMemo(
        () =>
            new MantlePassClient({
                rpcUrl,
                factoryAddress,
                chainId,
                rpId,
            }),
        [rpcUrl, factoryAddress, chainId, rpId]
    );

    // Connect/create wallet
    const connect = useCallback(
        async (userName: string): Promise<WalletInfo> => {
            setIsLoading(true);
            setError(null);

            try {
                const walletInfo = await client.createWallet({ userName });
                setWallet(walletInfo);

                // Try to fetch wallet state (may fail if wallet not deployed yet)
                try {
                    const state = await client.getWalletState(walletInfo.address);
                    setWalletState(state);
                } catch {
                    // Wallet might not be deployed yet
                }

                return walletInfo;
            } catch (err) {
                const message = err instanceof Error ? err.message : 'Failed to connect';
                setError(message);
                throw err;
            } finally {
                setIsLoading(false);
            }
        },
        [client]
    );

    // Disconnect
    const disconnect = useCallback(() => {
        setWallet(null);
        setWalletState(null);
        setError(null);
    }, []);

    // Sign transaction
    const signTransaction = useCallback(
        async (params: ExecuteParams) => {
            if (!wallet) {
                throw new Error('No wallet connected');
            }

            setIsLoading(true);
            setError(null);

            try {
                const result = await client.signTransaction(
                    wallet.address,
                    params,
                    wallet.credential.id
                );
                return result;
            } catch (err) {
                const message = err instanceof Error ? err.message : 'Failed to sign';
                setError(message);
                throw err;
            } finally {
                setIsLoading(false);
            }
        },
        [client, wallet]
    );

    // Refresh state
    const refreshState = useCallback(async () => {
        if (!wallet) return;

        try {
            const state = await client.getWalletState(wallet.address);
            setWalletState(state);
        } catch (err) {
            console.error('Failed to refresh wallet state:', err);
        }
    }, [client, wallet]);

    const value: MantlePassContextValue = useMemo(
        () => ({
            client,
            wallet,
            walletState,
            isConnected: wallet !== null,
            isLoading,
            error,
            connect,
            disconnect,
            signTransaction,
            refreshState,
        }),
        [
            client,
            wallet,
            walletState,
            isLoading,
            error,
            connect,
            disconnect,
            signTransaction,
            refreshState,
        ]
    );

    return (
        <MantlePassContext.Provider value={value}>
            {children}
        </MantlePassContext.Provider>
    );
}

/**
 * Hook to access MantlePass context
 */
export function useMantlePass(): MantlePassContextValue {
    const context = useContext(MantlePassContext);
    if (!context) {
        throw new Error('useMantlePass must be used within a MantlePassProvider');
    }
    return context;
}
