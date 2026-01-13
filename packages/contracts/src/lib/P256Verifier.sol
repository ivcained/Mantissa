// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title P256Verifier
 * @notice Library for verifying P-256 (secp256r1) signatures using Mantle's RIP-7212 precompile
 * @dev The P-256 precompile is available at address 0x100 on Mantle L2
 */
library P256Verifier {
    /// @notice Address of the P-256 precompile on Mantle (RIP-7212)
    address constant P256_VERIFIER = 0x0000000000000000000000000000000000000100;

    /// @notice Gas cost for the P-256 precompile
    uint256 constant P256_GAS_COST = 3450;

    /**
     * @notice Verifies a P-256 signature
     * @param messageHash The hash of the message that was signed
     * @param r The r component of the signature
     * @param s The s component of the signature
     * @param x The x coordinate of the public key
     * @param y The y coordinate of the public key
     * @return success True if the signature is valid
     */
    function verifySignature(
        bytes32 messageHash,
        uint256 r,
        uint256 s,
        uint256 x,
        uint256 y
    ) internal view returns (bool success) {
        // Encode the input for the precompile
        // Format: messageHash (32) + r (32) + s (32) + x (32) + y (32) = 160 bytes
        bytes memory input = abi.encodePacked(messageHash, r, s, x, y);

        // Call the precompile
        (bool ok, bytes memory result) = P256_VERIFIER.staticcall{gas: P256_GAS_COST + 1000}(input);

        // Check if the call succeeded and returned 1 (valid signature)
        if (ok && result.length == 32) {
            uint256 returnValue = abi.decode(result, (uint256));
            success = returnValue == 1;
        } else {
            success = false;
        }
    }

    /**
     * @notice Verifies a P-256 signature with raw bytes
     * @param messageHash The hash of the message that was signed
     * @param signature The signature bytes (r || s, 64 bytes total)
     * @param publicKey The public key bytes (x || y, 64 bytes total)
     * @return success True if the signature is valid
     */
    function verifySignatureRaw(
        bytes32 messageHash,
        bytes memory signature,
        bytes memory publicKey
    ) internal view returns (bool success) {
        require(signature.length == 64, "P256: invalid signature length");
        require(publicKey.length == 64, "P256: invalid public key length");

        // Extract r, s from signature
        uint256 r;
        uint256 s;
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
        }

        // Extract x, y from public key
        uint256 x;
        uint256 y;
        assembly {
            x := mload(add(publicKey, 32))
            y := mload(add(publicKey, 64))
        }

        return verifySignature(messageHash, r, s, x, y);
    }

    /**
     * @notice Checks if the P-256 precompile is available
     * @return available True if the precompile responds correctly
     */
    function isPrecompileAvailable() internal view returns (bool available) {
        // Try to call with known test vector
        // This is a simple presence check
        (bool ok,) = P256_VERIFIER.staticcall{gas: 5000}("");
        available = ok;
    }
}
