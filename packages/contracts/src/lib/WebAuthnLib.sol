// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./P256Verifier.sol";

/**
 * @title WebAuthnLib
 * @notice Library for WebAuthn/FIDO2 signature verification
 * @dev Implements WebAuthn assertion verification per W3C spec
 */
library WebAuthnLib {
    /// @notice Flags in authenticator data
    uint8 constant FLAG_USER_PRESENT = 0x01;
    uint8 constant FLAG_USER_VERIFIED = 0x04;

    /**
     * @notice WebAuthn signature components
     * @param authenticatorData Raw authenticator data from WebAuthn assertion
     * @param clientDataJSON Raw client data JSON string
     * @param r Signature r component
     * @param s Signature s component
     */
    struct WebAuthnSignature {
        bytes authenticatorData;
        string clientDataJSON;
        uint256 r;
        uint256 s;
    }

    /**
     * @notice Passkey public key
     * @param x X coordinate of the P-256 public key
     * @param y Y coordinate of the P-256 public key
     */
    struct PasskeyPublicKey {
        uint256 x;
        uint256 y;
    }

    /**
     * @notice Verifies a WebAuthn assertion
     * @param signature The WebAuthn signature components
     * @param publicKey The passkey public key
     * @param challenge The expected challenge (usually a transaction hash)
     * @return success True if the signature is valid
     */
    function verifyAssertion(
        WebAuthnSignature memory signature,
        PasskeyPublicKey memory publicKey,
        bytes32 challenge
    ) internal view returns (bool success) {
        // Step 1: Verify authenticator data flags
        if (!_verifyAuthenticatorData(signature.authenticatorData)) {
            return false;
        }

        // Step 2: Verify the challenge in clientDataJSON
        if (!_verifyChallengeInClientData(signature.clientDataJSON, challenge)) {
            return false;
        }

        // Step 3: Compute the signing message
        // signingMessage = authenticatorData || SHA256(clientDataJSON)
        bytes32 clientDataHash = sha256(bytes(signature.clientDataJSON));
        bytes32 messageHash = sha256(abi.encodePacked(signature.authenticatorData, clientDataHash));

        // Step 4: Verify the P-256 signature
        success = P256Verifier.verifySignature(
            messageHash,
            signature.r,
            signature.s,
            publicKey.x,
            publicKey.y
        );
    }

    /**
     * @notice Verifies authenticator data flags
     * @param authenticatorData The raw authenticator data
     * @return valid True if flags indicate user presence
     */
    function _verifyAuthenticatorData(bytes memory authenticatorData) internal pure returns (bool valid) {
        // Authenticator data must be at least 37 bytes:
        // rpIdHash (32) + flags (1) + signCount (4)
        if (authenticatorData.length < 37) {
            return false;
        }

        // Check user present flag (bit 0)
        uint8 flags = uint8(authenticatorData[32]);
        valid = (flags & FLAG_USER_PRESENT) != 0;
    }

    /**
     * @notice Verifies that the challenge in clientDataJSON matches expected
     * @param clientDataJSON The client data JSON string
     * @param expectedChallenge The expected challenge bytes
     * @return valid True if challenge matches
     */
    function _verifyChallengeInClientData(
        string memory clientDataJSON,
        bytes32 expectedChallenge
    ) internal pure returns (bool valid) {
        // The challenge in clientDataJSON is base64url encoded
        // For MVP, we do a simplified check:
        // In production, properly parse JSON and decode base64url
        
        bytes memory jsonBytes = bytes(clientDataJSON);
        bytes memory challengeB64 = _base64UrlEncode(abi.encodePacked(expectedChallenge));
        
        // Search for the challenge in the JSON
        valid = _containsSubstring(jsonBytes, challengeB64);
    }

    /**
     * @notice Base64URL encode bytes (no padding)
     * @param data The data to encode
     * @return encoded The base64url encoded string
     */
    function _base64UrlEncode(bytes memory data) internal pure returns (bytes memory encoded) {
        // Base64 alphabet (URL-safe)
        bytes memory alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        
        uint256 encodedLen = 4 * ((data.length + 2) / 3);
        encoded = new bytes(encodedLen);
        
        uint256 i = 0;
        uint256 j = 0;
        
        while (i < data.length) {
            uint256 a = uint256(uint8(data[i++]));
            uint256 b = i < data.length ? uint256(uint8(data[i++])) : 0;
            uint256 c = i < data.length ? uint256(uint8(data[i++])) : 0;
            
            uint256 triple = (a << 16) | (b << 8) | c;
            
            encoded[j++] = alphabet[(triple >> 18) & 0x3F];
            encoded[j++] = alphabet[(triple >> 12) & 0x3F];
            encoded[j++] = alphabet[(triple >> 6) & 0x3F];
            encoded[j++] = alphabet[triple & 0x3F];
        }
        
        // Remove padding (base64url doesn't use padding)
        uint256 padding = data.length % 3 == 1 ? 2 : (data.length % 3 == 2 ? 1 : 0);
        assembly {
            mstore(encoded, sub(mload(encoded), padding))
        }
    }

    /**
     * @notice Check if haystack contains needle
     * @param haystack The string to search in
     * @param needle The string to search for
     * @return found True if needle is found in haystack
     */
    function _containsSubstring(bytes memory haystack, bytes memory needle) internal pure returns (bool found) {
        if (needle.length > haystack.length) {
            return false;
        }
        
        for (uint256 i = 0; i <= haystack.length - needle.length; i++) {
            bool match_ = true;
            for (uint256 j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    match_ = false;
                    break;
                }
            }
            if (match_) {
                return true;
            }
        }
        return false;
    }

    /**
     * @notice Extracts the RP ID hash from authenticator data
     * @param authenticatorData The raw authenticator data
     * @return rpIdHash The 32-byte RP ID hash
     */
    function extractRpIdHash(bytes memory authenticatorData) internal pure returns (bytes32 rpIdHash) {
        require(authenticatorData.length >= 32, "WebAuthn: invalid authenticator data");
        assembly {
            rpIdHash := mload(add(authenticatorData, 32))
        }
    }

    /**
     * @notice Extracts the sign count from authenticator data
     * @param authenticatorData The raw authenticator data
     * @return signCount The 4-byte sign count (big-endian)
     */
    function extractSignCount(bytes memory authenticatorData) internal pure returns (uint32 signCount) {
        require(authenticatorData.length >= 37, "WebAuthn: invalid authenticator data");
        signCount = uint32(uint8(authenticatorData[33])) << 24 |
                    uint32(uint8(authenticatorData[34])) << 16 |
                    uint32(uint8(authenticatorData[35])) << 8 |
                    uint32(uint8(authenticatorData[36]));
    }
}
