// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/MantlePassFactory.sol";

/**
 * @title DeployMantlePass
 * @notice Deployment script for MantlePass contracts
 */
contract DeployMantlePass is Script {
    function run() external {
        // Load private key from environment
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        
        // RP ID hash - should be sha256 of your domain
        // For testing: keccak256("mantlepass.xyz")
        bytes32 rpIdHash = keccak256("mantlepass.xyz");
        
        vm.startBroadcast(deployerPrivateKey);

        // Deploy the factory
        MantlePassFactory factory = new MantlePassFactory(rpIdHash);
        
        console.log("MantlePassFactory deployed at:", address(factory));
        console.log("RP ID Hash:", vm.toString(rpIdHash));

        vm.stopBroadcast();
    }
}
