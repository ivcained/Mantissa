'use client';

import { useCallback, useState } from 'react';
import { useMantlePass } from '../MantlePassProvider';
import type { ExecuteParams, ContractSignature } from '../../types';
import type { Hex } from 'viem';

/**
 * Hook for transaction signing
 * 
 * @example
 * ```tsx
 * function SendButton() {
 *   const { signAndPrepare, isSigning, error } = useTransaction();
 * 
 *   const handleSend = async () => {
 *     const { signature, credentialIdHash, txData } = await signAndPrepare({
 *       target: '0x...',
 *       value: 1000000000000000000n, // 1 ETH
 *     });
 * 
 *     // Now submit txData to relayer or directly to chain
 *     console.log('Signed!', signature);
 *   };
 * 
 *   return (
 *     <button onClick={handleSend} disabled={isSigning}>
 *       {isSigning ? 'Signing...' : 'Send 1 ETH'}
 *     </button>
 *   );
 * }
 * ```
 */
export function useTransaction() {
  const { client, wallet, signTransaction } = useMantlePass();
  const [isSigning, setIsSigning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  /**
   * Sign a transaction and prepare the calldata
   */
  const signAndPrepare = useCallback(
    async (
      params: ExecuteParams
    ): Promise<{
      signature: ContractSignature;
      credentialIdHash: Hex;
      txData: Hex;
    }> => {
      if (!client || !wallet) {
        throw new Error('No wallet connected');
      }

      setIsSigning(true);
      setError(null);

      try {
        const { signature, credentialIdHash } = await signTransaction(params);

        // Build the transaction data
        const txData = client.buildExecuteData(
          params,
          credentialIdHash,
          signature
        );

        return {
          signature,
          credentialIdHash,
          txData,
        };
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Failed to sign';
        setError(message);
        throw err;
      } finally {
        setIsSigning(false);
      }
    },
    [client, wallet, signTransaction]
  );

  /**
   * Get the transaction hash for a given transaction
   */
  const getTransactionHash = useCallback(
    async (params: ExecuteParams, nonce: bigint): Promise<Hex> => {
      if (!client || !wallet) {
        throw new Error('No wallet connected');
      }

      return client.getTransactionHash(wallet.address, params, nonce);
    },
    [client, wallet]
  );

  return {
    signAndPrepare,
    getTransactionHash,
    isSigning,
    error,
  };
}
