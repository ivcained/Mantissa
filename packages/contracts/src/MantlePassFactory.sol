// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./MantlePassWallet.sol";

/**
 * @title MantlePassFactory
 * @notice Factory for deploying MantlePassWallet contracts with deterministic addresses
 * @dev Uses CREATE2 for address prediction before deployment
 */
contract MantlePassFactory {
    /*//////////////////////////////////////////////////////////////
                                 EVENTS
    //////////////////////////////////////////////////////////////*/

    event WalletCreated(
        address indexed wallet,
        bytes32 indexed credentialId,
        address indexed recoveryAddress
    );

    /*//////////////////////////////////////////////////////////////
                                 ERRORS
    //////////////////////////////////////////////////////////////*/

    error WalletAlreadyExists();
    error DeploymentFailed();
    error InvalidCredentialId();

    /*//////////////////////////////////////////////////////////////
                                 STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Mapping of credential ID to wallet address
    mapping(bytes32 => address) public wallets;

    /// @notice The RP ID hash for this factory's wallets
    bytes32 public immutable rpIdHash;

    /*//////////////////////////////////////////////////////////////
                              CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    /**
     * @param _rpIdHash The RP ID hash for WebAuthn verification
     */
    constructor(bytes32 _rpIdHash) {
        rpIdHash = _rpIdHash;
    }

    /*//////////////////////////////////////////////////////////////
                            CORE FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Create a new wallet with the given passkey
     * @param credentialId The WebAuthn credential ID (hashed)
     * @param pubKeyX X coordinate of the P-256 public key
     * @param pubKeyY Y coordinate of the P-256 public key
     * @param recoveryAddress Address that can add passkeys for recovery
     * @return wallet The address of the created wallet
     */
    function createWallet(
        bytes32 credentialId,
        uint256 pubKeyX,
        uint256 pubKeyY,
        address recoveryAddress
    ) external payable returns (address wallet) {
        if (credentialId == bytes32(0)) revert InvalidCredentialId();
        if (wallets[credentialId] != address(0)) revert WalletAlreadyExists();

        // Deploy wallet using CREATE2
        bytes32 salt = _computeSalt(credentialId);
        bytes memory bytecode = type(MantlePassWallet).creationCode;

        assembly {
            wallet := create2(0, add(bytecode, 32), mload(bytecode), salt)
        }

        if (wallet == address(0)) revert DeploymentFailed();

        // Initialize the wallet
        MantlePassWallet(payable(wallet)).initialize(
            credentialId,
            pubKeyX,
            pubKeyY,
            recoveryAddress,
            rpIdHash
        );

        // Store the mapping
        wallets[credentialId] = wallet;

        // Forward any ETH sent
        if (msg.value > 0) {
            (bool success,) = wallet.call{value: msg.value}("");
            require(success, "ETH transfer failed");
        }

        emit WalletCreated(wallet, credentialId, recoveryAddress);
    }

    /**
     * @notice Predict the wallet address for a credential ID
     * @param credentialId The WebAuthn credential ID (hashed)
     * @return predicted The predicted wallet address
     */
    function getWalletAddress(bytes32 credentialId) external view returns (address predicted) {
        bytes32 salt = _computeSalt(credentialId);
        bytes32 bytecodeHash = keccak256(type(MantlePassWallet).creationCode);

        predicted = address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff),
            address(this),
            salt,
            bytecodeHash
        )))));
    }

    /**
     * @notice Check if a wallet exists for a credential ID
     * @param credentialId The credential ID to check
     * @return exists True if a wallet exists
     */
    function walletExists(bytes32 credentialId) external view returns (bool exists) {
        return wallets[credentialId] != address(0);
    }

    /*//////////////////////////////////////////////////////////////
                          INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Compute the CREATE2 salt for a credential ID
     */
    function _computeSalt(bytes32 credentialId) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("MantlePass_v1", credentialId));
    }
}
