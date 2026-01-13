// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/MantlePassWallet.sol";
import "../src/MantlePassFactory.sol";
import "../src/lib/WebAuthnLib.sol";

/**
 * @title MantlePassWalletTest
 * @notice Tests for MantlePassWallet and MantlePassFactory
 */
contract MantlePassWalletTest is Test {
    MantlePassFactory public factory;
    MantlePassWallet public wallet;

    // Test passkey credentials (mock values for testing)
    bytes32 constant CREDENTIAL_ID = keccak256("test-credential-id-1");
    bytes32 constant CREDENTIAL_ID_2 = keccak256("test-credential-id-2");
    
    // Mock P-256 public key (these would be real values from WebAuthn)
    uint256 constant PUB_KEY_X = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef;
    uint256 constant PUB_KEY_Y = 0xfedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321;
    
    // RP ID hash (sha256 of the relying party ID, e.g., "mantlepass.xyz")
    bytes32 constant RP_ID_HASH = keccak256("mantlepass.xyz");

    address recoveryAddress = address(0x1234);
    address user = address(0x5678);
    address recipient = address(0x9abc);

    function setUp() public {
        // Deploy factory
        factory = new MantlePassFactory(RP_ID_HASH);
        
        // Create a wallet through the factory
        address walletAddr = factory.createWallet(
            CREDENTIAL_ID,
            PUB_KEY_X,
            PUB_KEY_Y,
            recoveryAddress
        );
        wallet = MantlePassWallet(payable(walletAddr));
        
        // Fund the wallet
        vm.deal(address(wallet), 10 ether);
    }

    /*//////////////////////////////////////////////////////////////
                            FACTORY TESTS
    //////////////////////////////////////////////////////////////*/

    function test_FactoryDeployment() public view {
        assertEq(factory.rpIdHash(), RP_ID_HASH);
    }

    function test_WalletCreation() public view {
        assertTrue(factory.walletExists(CREDENTIAL_ID));
        assertEq(factory.wallets(CREDENTIAL_ID), address(wallet));
    }

    function test_PredictWalletAddress() public {
        bytes32 newCredential = keccak256("new-credential");
        
        // Get predicted address
        address predicted = factory.getWalletAddress(newCredential);
        
        // Create the wallet
        address actual = factory.createWallet(
            newCredential,
            PUB_KEY_X,
            PUB_KEY_Y,
            recoveryAddress
        );
        
        assertEq(predicted, actual);
    }

    function test_CannotCreateDuplicateWallet() public {
        vm.expectRevert(MantlePassFactory.WalletAlreadyExists.selector);
        factory.createWallet(
            CREDENTIAL_ID, // Already exists
            PUB_KEY_X,
            PUB_KEY_Y,
            recoveryAddress
        );
    }

    function test_CreateWalletWithFunding() public {
        bytes32 newCredential = keccak256("funded-credential");
        
        address newWallet = factory.createWallet{value: 1 ether}(
            newCredential,
            PUB_KEY_X,
            PUB_KEY_Y,
            recoveryAddress
        );
        
        assertEq(address(newWallet).balance, 1 ether);
    }

    /*//////////////////////////////////////////////////////////////
                            WALLET TESTS
    //////////////////////////////////////////////////////////////*/

    function test_WalletInitialized() public view {
        assertTrue(wallet.initialized());
        assertEq(wallet.recoveryAddress(), recoveryAddress);
        assertEq(wallet.rpIdHash(), RP_ID_HASH);
        assertEq(wallet.nonce(), 0);
    }

    function test_PasskeyStored() public view {
        assertTrue(wallet.isPasskeyActive(CREDENTIAL_ID));
        
        (uint256 x, uint256 y, bool active,) = wallet.passkeys(CREDENTIAL_ID);
        assertEq(x, PUB_KEY_X);
        assertEq(y, PUB_KEY_Y);
        assertTrue(active);
    }

    function test_CannotReinitialize() public {
        vm.expectRevert(MantlePassWallet.AlreadyInitialized.selector);
        wallet.initialize(
            CREDENTIAL_ID,
            PUB_KEY_X,
            PUB_KEY_Y,
            recoveryAddress,
            RP_ID_HASH
        );
    }

    function test_GetCredentialIds() public view {
        bytes32[] memory ids = wallet.getCredentialIds();
        assertEq(ids.length, 1);
        assertEq(ids[0], CREDENTIAL_ID);
    }

    function test_GetActivePasskeyCount() public view {
        assertEq(wallet.getActivePasskeyCount(), 1);
    }

    function test_ReceiveEth() public {
        uint256 balanceBefore = address(wallet).balance;
        
        vm.deal(user, 2 ether);
        vm.prank(user);
        (bool success,) = address(wallet).call{value: 1 ether}("");
        assertTrue(success);
        
        assertEq(address(wallet).balance, balanceBefore + 1 ether);
    }

    function test_GetTransactionHash() public view {
        bytes32 hash1 = wallet.getTransactionHash(
            recipient,
            1 ether,
            "",
            0
        );
        
        bytes32 hash2 = wallet.getTransactionHash(
            recipient,
            1 ether,
            "",
            1
        );
        
        // Different nonces should produce different hashes
        assertTrue(hash1 != hash2);
    }

    /*//////////////////////////////////////////////////////////////
                      RECOVERY ADDRESS TESTS
    //////////////////////////////////////////////////////////////*/

    function test_RecoveryCanAddPasskey() public {
        // Create mock signature (empty for recovery)
        WebAuthnLib.WebAuthnSignature memory emptySig;
        
        vm.prank(recoveryAddress);
        wallet.addPasskey(
            CREDENTIAL_ID_2,
            PUB_KEY_X,
            PUB_KEY_Y,
            bytes32(0), // credentialId not needed for recovery
            emptySig
        );
        
        assertTrue(wallet.isPasskeyActive(CREDENTIAL_ID_2));
        assertEq(wallet.getActivePasskeyCount(), 2);
    }

    function test_CannotAddDuplicatePasskey() public {
        WebAuthnLib.WebAuthnSignature memory emptySig;
        
        vm.prank(recoveryAddress);
        vm.expectRevert(MantlePassWallet.PasskeyAlreadyExists.selector);
        wallet.addPasskey(
            CREDENTIAL_ID, // Already exists
            PUB_KEY_X,
            PUB_KEY_Y,
            bytes32(0),
            emptySig
        );
    }

    /*//////////////////////////////////////////////////////////////
                          SIGNATURE TESTS
    //////////////////////////////////////////////////////////////*/

    // Note: Full signature verification tests require actual WebAuthn signatures
    // In a real scenario, these would be generated by the SDK
    // For now, we test the revert cases
    
    function test_ExecuteRevertsWithInactivePasskey() public {
        bytes32 unknownCredential = keccak256("unknown");
        WebAuthnLib.WebAuthnSignature memory sig = WebAuthnLib.WebAuthnSignature({
            authenticatorData: "",
            clientDataJSON: "",
            r: 0,
            s: 0
        });
        
        vm.expectRevert(MantlePassWallet.PasskeyNotFound.selector);
        wallet.execute(
            recipient,
            1 ether,
            "",
            unknownCredential,
            sig
        );
    }

    function test_ExecuteBatchRevertsWithArrayMismatch() public {
        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](1); // Mismatched length
        bytes[] memory datas = new bytes[](2);
        
        WebAuthnLib.WebAuthnSignature memory sig;
        
        vm.expectRevert(MantlePassWallet.InvalidArrayLength.selector);
        wallet.executeBatch(
            targets,
            values,
            datas,
            CREDENTIAL_ID,
            sig
        );
    }
}
