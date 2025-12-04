// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/interfaces/IKuru.sol";

/**
 * @title SetupScript
 * @notice Setup and interaction script for Kuru testing
 */
contract SetupScript is Script {
    address constant ROUTER = 0x1f5A250c4A506DA4cE584173c6ed1890B1bf7187;
    address constant MARGIN_ACCOUNT = 0xdDDaBd30785bA8b45e434a1f134BDf304d6125d9;
    
    function run() public view {
        console.log("=== Kuru Contract Info ===");
        console.log("Router:", ROUTER);
        console.log("MarginAccount:", MARGIN_ACCOUNT);
        
        // Check if contracts exist
        console.log("");
        console.log("Checking contract code...");
        
        uint256 routerCode;
        uint256 marginCode;
        
        assembly {
            routerCode := extcodesize(0x1f5A250c4A506DA4cE584173c6ed1890B1bf7187)
            marginCode := extcodesize(0xdDDaBd30785bA8b45e434a1f134BDf304d6125d9)
        }
        
        console.log("Router code size:", routerCode);
        console.log("MarginAccount code size:", marginCode);
    }
}

/**
 * @title ExploitAttempt
 * @notice Script to attempt exploits (for testing only)
 */
contract ExploitAttempt is Script {
    IMarginAccount constant marginAccount = IMarginAccount(0xdDDaBd30785bA8b45e434a1f134BDf304d6125d9);
    
    function run() public {
        vm.startBroadcast();
        
        console.log("=== Attempting Access Control Bypass ===");
        console.log("Sender:", msg.sender);
        
        // Try to credit ourselves
        address token = address(0x1);
        uint256 amount = 1 ether;
        
        console.log("Attempting creditUser...");
        
        // This will likely revert - that's what we're testing
        try marginAccount.creditUser(msg.sender, token, amount, false) {
            console.log("!!! CRITICAL: creditUser SUCCEEDED !!!");
        } catch Error(string memory reason) {
            console.log("Reverted:", reason);
        } catch {
            console.log("Reverted (access control working)");
        }
        
        vm.stopBroadcast();
    }
}
