// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./lib/WebAuthnLib.sol";
import "./lib/P256Verifier.sol";

/**
 * @title MantlePassWallet
 * @notice Smart contract wallet with passkey (WebAuthn) authentication on Mantle L2
 * @dev Uses Mantle's P-256 precompile for gas-efficient signature verification
 */
contract MantlePassWallet {
    using WebAuthnLib for WebAuthnLib.WebAuthnSignature;

    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event Initialized(address indexed owner, bytes32 indexed credentialId);
    event PasskeyAdded(bytes32 indexed credentialId);
    event PasskeyRemoved(bytes32 indexed credentialId);
    event Executed(address indexed target, uint256 value, bytes data);
    event ExecutedBatch(address[] targets, uint256[] values, bytes[] datas);

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error AlreadyInitialized();
    error NotInitialized();
    error InvalidSignature();
    error PasskeyNotFound();
    error PasskeyAlreadyExists();
    error InvalidNonce();
    error CallFailed(uint256 index);
    error InvalidArrayLength();
    error NoPasskeys();
    error Unauthorized();
    error InvalidCredentialId();

    /*//////////////////////////////////////////////////////////////
                                 STRUCTS
    //////////////////////////////////////////////////////////////*/

    /// @notice Passkey credential with P-256 public key
    struct Passkey {
        uint256 x;          // P-256 public key x coordinate
        uint256 y;          // P-256 public key y coordinate
        bool active;        // Whether this passkey is active
        uint64 addedAt;     // Timestamp when passkey was added
    }

    /*//////////////////////////////////////////////////////////////
                                 STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Whether the wallet has been initialized
    bool public initialized;

    /// @notice Current nonce for replay protection
    uint256 public nonce;

    /// @notice Recovery address (can add new passkeys)
    address public recoveryAddress;

    /// @notice Mapping of credential ID hash to passkey
    mapping(bytes32 => Passkey) public passkeys;

    /// @notice Array of all credential IDs (for enumeration)
    bytes32[] public credentialIds;

    /// @notice RP ID hash for WebAuthn verification
    bytes32 public rpIdHash;

    /*//////////////////////////////////////////////////////////////
                              INITIALIZER
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Initialize the wallet with the first passkey
     * @param credentialId The WebAuthn credential ID (hashed)
     * @param pubKeyX X coordinate of the P-256 public key
     * @param pubKeyY Y coordinate of the P-256 public key
     * @param _recoveryAddress Address that can add passkeys (for recovery)
     * @param _rpIdHash The RP ID hash for WebAuthn verification
     */
    function initialize(
        bytes32 credentialId,
        uint256 pubKeyX,
        uint256 pubKeyY,
        address _recoveryAddress,
        bytes32 _rpIdHash
    ) external {
        if (initialized) revert AlreadyInitialized();
        if (credentialId == bytes32(0)) revert InvalidCredentialId();
        
        initialized = true;
        recoveryAddress = _recoveryAddress;
        rpIdHash = _rpIdHash;

        passkeys[credentialId] = Passkey({
            x: pubKeyX,
            y: pubKeyY,
            active: true,
            addedAt: uint64(block.timestamp)
        });
        credentialIds.push(credentialId);

        emit Initialized(_recoveryAddress, credentialId);
        emit PasskeyAdded(credentialId);
    }

    /*//////////////////////////////////////////////////////////////
                            CORE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Execute a transaction with passkey authentication
     * @param target The target contract address
     * @param value The ETH value to send
     * @param data The calldata
     * @param credentialId The credential ID of the signing passkey
     * @param signature The WebAuthn signature
     */
    function execute(
        address target,
        uint256 value,
        bytes calldata data,
        bytes32 credentialId,
        WebAuthnLib.WebAuthnSignature calldata signature
    ) external returns (bytes memory result) {
        if (!initialized) revert NotInitialized();

        // Verify the signature
        _verifySignature(
            credentialId,
            signature,
            _hashTransaction(target, value, data, nonce)
        );

        // Increment nonce
        unchecked {
            nonce++;
        }

        // Execute the call
        (bool success, bytes memory returnData) = target.call{value: value}(data);
        if (!success) {
            // Bubble up revert reason
            assembly {
                revert(add(returnData, 32), mload(returnData))
            }
        }

        emit Executed(target, value, data);
        return returnData;
    }

    /**
     * @notice Execute multiple transactions in a batch
     * @param targets The target contract addresses
     * @param values The ETH values to send
     * @param datas The calldatas
     * @param credentialId The credential ID of the signing passkey
     * @param signature The WebAuthn signature
     */
    function executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas,
        bytes32 credentialId,
        WebAuthnLib.WebAuthnSignature calldata signature
    ) external returns (bytes[] memory results) {
        if (!initialized) revert NotInitialized();
        if (targets.length != values.length || values.length != datas.length) {
            revert InvalidArrayLength();
        }

        // Verify the signature
        _verifySignature(
            credentialId,
            signature,
            _hashBatchTransaction(targets, values, datas, nonce)
        );

        // Increment nonce
        unchecked {
            nonce++;
        }

        // Execute all calls
        results = new bytes[](targets.length);
        for (uint256 i = 0; i < targets.length; i++) {
            (bool success, bytes memory returnData) = targets[i].call{value: values[i]}(datas[i]);
            if (!success) {
                revert CallFailed(i);
            }
            results[i] = returnData;
        }

        emit ExecutedBatch(targets, values, datas);
    }

    /*//////////////////////////////////////////////////////////////
                          PASSKEY MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Add a new passkey (requires existing passkey signature or recovery address)
     * @param newCredentialId The new credential ID
     * @param pubKeyX X coordinate of the new P-256 public key
     * @param pubKeyY Y coordinate of the new P-256 public key
     * @param credentialId The credential ID of the authorizing passkey
     * @param signature The WebAuthn signature (empty if using recovery)
     */
    function addPasskey(
        bytes32 newCredentialId,
        uint256 pubKeyX,
        uint256 pubKeyY,
        bytes32 credentialId,
        WebAuthnLib.WebAuthnSignature calldata signature
    ) external {
        if (!initialized) revert NotInitialized();
        if (passkeys[newCredentialId].active) revert PasskeyAlreadyExists();
        if (newCredentialId == bytes32(0)) revert InvalidCredentialId();

        // Either verify with existing passkey or recovery address
        if (msg.sender == recoveryAddress) {
            // Recovery address can add passkeys directly
        } else {
            // Verify with existing passkey
            _verifySignature(
                credentialId,
                signature,
                keccak256(abi.encode("ADD_PASSKEY", newCredentialId, pubKeyX, pubKeyY, nonce))
            );
            unchecked {
                nonce++;
            }
        }

        passkeys[newCredentialId] = Passkey({
            x: pubKeyX,
            y: pubKeyY,
            active: true,
            addedAt: uint64(block.timestamp)
        });
        credentialIds.push(newCredentialId);

        emit PasskeyAdded(newCredentialId);
    }

    /**
     * @notice Remove a passkey
     * @param targetCredentialId The credential ID to remove
     * @param credentialId The credential ID of the authorizing passkey
     * @param signature The WebAuthn signature
     */
    function removePasskey(
        bytes32 targetCredentialId,
        bytes32 credentialId,
        WebAuthnLib.WebAuthnSignature calldata signature
    ) external {
        if (!initialized) revert NotInitialized();
        if (!passkeys[targetCredentialId].active) revert PasskeyNotFound();
        
        // Must have at least one passkey remaining
        uint256 activeCount = 0;
        for (uint256 i = 0; i < credentialIds.length; i++) {
            if (passkeys[credentialIds[i]].active) {
                activeCount++;
            }
        }
        if (activeCount <= 1) revert NoPasskeys();

        // Verify with existing passkey (can't use recovery to remove)
        _verifySignature(
            credentialId,
            signature,
            keccak256(abi.encode("REMOVE_PASSKEY", targetCredentialId, nonce))
        );
        unchecked {
            nonce++;
        }

        passkeys[targetCredentialId].active = false;
        emit PasskeyRemoved(targetCredentialId);
    }

    /**
     * @notice Update the recovery address
     * @param newRecoveryAddress The new recovery address
     * @param credentialId The credential ID of the authorizing passkey
     * @param signature The WebAuthn signature
     */
    function setRecoveryAddress(
        address newRecoveryAddress,
        bytes32 credentialId,
        WebAuthnLib.WebAuthnSignature calldata signature
    ) external {
        if (!initialized) revert NotInitialized();

        _verifySignature(
            credentialId,
            signature,
            keccak256(abi.encode("SET_RECOVERY", newRecoveryAddress, nonce))
        );
        unchecked {
            nonce++;
        }

        recoveryAddress = newRecoveryAddress;
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get all credential IDs
     * @return The array of credential IDs
     */
    function getCredentialIds() external view returns (bytes32[] memory) {
        return credentialIds;
    }

    /**
     * @notice Get the number of active passkeys
     * @return count The number of active passkeys
     */
    function getActivePasskeyCount() external view returns (uint256 count) {
        for (uint256 i = 0; i < credentialIds.length; i++) {
            if (passkeys[credentialIds[i]].active) {
                count++;
            }
        }
    }

    /**
     * @notice Check if a passkey is active
     * @param credentialId The credential ID to check
     * @return active True if the passkey is active
     */
    function isPasskeyActive(bytes32 credentialId) external view returns (bool active) {
        return passkeys[credentialId].active;
    }

    /**
     * @notice Get the hash of a transaction for signing
     * @param target The target address
     * @param value The ETH value
     * @param data The calldata
     * @param _nonce The nonce to use
     * @return The transaction hash
     */
    function getTransactionHash(
        address target,
        uint256 value,
        bytes calldata data,
        uint256 _nonce
    ) external view returns (bytes32) {
        return _hashTransaction(target, value, data, _nonce);
    }

    /*//////////////////////////////////////////////////////////////
                          INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Verify a WebAuthn signature
     */
    function _verifySignature(
        bytes32 credentialId,
        WebAuthnLib.WebAuthnSignature calldata signature,
        bytes32 challenge
    ) internal view {
        Passkey storage passkey = passkeys[credentialId];
        if (!passkey.active) revert PasskeyNotFound();

        bool valid = WebAuthnLib.verifyAssertion(
            signature,
            WebAuthnLib.PasskeyPublicKey({x: passkey.x, y: passkey.y}),
            challenge
        );

        if (!valid) revert InvalidSignature();
    }

    /**
     * @notice Hash a single transaction
     */
    function _hashTransaction(
        address target,
        uint256 value,
        bytes calldata data,
        uint256 _nonce
    ) internal view returns (bytes32) {
        return keccak256(abi.encode(
            address(this),
            block.chainid,
            target,
            value,
            keccak256(data),
            _nonce
        ));
    }

    /**
     * @notice Hash a batch transaction
     */
    function _hashBatchTransaction(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas,
        uint256 _nonce
    ) internal view returns (bytes32) {
        bytes32[] memory dataHashes = new bytes32[](datas.length);
        for (uint256 i = 0; i < datas.length; i++) {
            dataHashes[i] = keccak256(datas[i]);
        }
        return keccak256(abi.encode(
            address(this),
            block.chainid,
            targets,
            values,
            dataHashes,
            _nonce
        ));
    }

    /*//////////////////////////////////////////////////////////////
                              RECEIVE ETH
    //////////////////////////////////////////////////////////////*/

    receive() external payable {}
    fallback() external payable {}
}
