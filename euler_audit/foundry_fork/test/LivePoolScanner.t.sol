// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

/**
 * @title LivePoolScanner
 * @notice Scan live EulerSwap pools for custom hooks
 */

interface IEulerSwapRegistry {
    function getPoolCount() external view returns (uint256);
    function getPoolAddress(uint256 index) external view returns (address);
    function pools(bytes32 id) external view returns (address);
}

interface IEulerSwap {
    struct DynamicParams {
        uint64 fee0;
        uint64 fee1;
        uint64 priceX;
        uint64 priceY;
        uint64 concentrationX;
        uint64 concentrationY;
        uint112 equilibriumReserve0;
        uint112 equilibriumReserve1;
        uint112 minReserve0;
        uint112 minReserve1;
        uint64 expiration;
        uint8 swapHookedOperations;
        address swapHook;
    }
    
    struct StaticParams {
        address supplyVault0;
        address supplyVault1;
        address eulerAccount;
        address feeRecipient;
    }
    
    function getDynamicParams() external view returns (DynamicParams memory);
    function getStaticParams() external view returns (StaticParams memory);
    function getReserves() external view returns (uint112, uint112, uint32);
    function isInstalled() external view returns (bool);
    function getAssets() external view returns (address, address);
}

interface IEulerSwapFactory {
    function getDeployedPoolsLength() external view returns (uint256);
    function getDeployedPoolAddress(uint256 index) external view returns (address);
}

interface IERC20 {
    function symbol() external view returns (string memory);
}

contract LivePoolScanner is Test {
    // Mainnet addresses
    address constant EULER_SWAP_FACTORY = 0x21b135c1e5B13F2A48Fd68A979c3f0a85F578E81;
    address constant EULER_SWAP_REGISTRY = 0x8bd9E83A851a4f64d15A18d2b88aa4FDcafDb77d;
    
    function setUp() public {}
    
    /**
     * @notice Scan all registered EulerSwap pools for custom hooks
     */
    function test_ScanForCustomHooks() public view {
        console.log("=== SCANNING EULERSWAP POOLS FOR CUSTOM HOOKS ===");
        console.log("");
        
        // Try to get pool count from factory
        uint256 poolCount;
        
        try IEulerSwapFactory(EULER_SWAP_FACTORY).getDeployedPoolsLength() returns (uint256 count) {
            poolCount = count;
            console.log("Pools deployed:", poolCount);
        } catch {
            console.log("Could not query factory");
            return;
        }
        
        uint256 hookedPoolCount = 0;
        uint256 scannedCount = 0;
        
        // Scan up to 50 pools
        uint256 limit = poolCount > 50 ? 50 : poolCount;
        
        for (uint256 i = 0; i < limit; i++) {
            try IEulerSwapFactory(EULER_SWAP_FACTORY).getDeployedPoolAddress(i) returns (address poolAddr) {
                if (poolAddr == address(0)) continue;
                scannedCount++;
                
                try IEulerSwap(poolAddr).getDynamicParams() returns (IEulerSwap.DynamicParams memory dParams) {
                    // Check if pool has custom hook
                    if (dParams.swapHook != address(0) || dParams.swapHookedOperations != 0) {
                        hookedPoolCount++;
                        
                        console.log("---");
                        console.log("!!! HOOKED POOL FOUND !!!");
                        console.log("Pool address:", poolAddr);
                        console.log("Hook address:", dParams.swapHook);
                        console.log("Hook operations:", uint256(dParams.swapHookedOperations));
                        console.log("Fee0:", dParams.fee0);
                        console.log("Fee1:", dParams.fee1);
                        
                        // Get assets
                        try IEulerSwap(poolAddr).getAssets() returns (address asset0, address asset1) {
                            try IERC20(asset0).symbol() returns (string memory s0) {
                                console.log("Asset0:", s0);
                            } catch {}
                            try IERC20(asset1).symbol() returns (string memory s1) {
                                console.log("Asset1:", s1);
                            } catch {}
                        } catch {}
                        
                        // Check if installed
                        try IEulerSwap(poolAddr).isInstalled() returns (bool installed) {
                            console.log("Installed:", installed);
                        } catch {}
                    }
                } catch {}
            } catch {}
        }
        
        console.log("");
        console.log("=== SCAN RESULTS ===");
        console.log("Pools scanned:", scannedCount);
        console.log("Pools with custom hooks:", hookedPoolCount);
        
        if (hookedPoolCount > 0) {
            console.log("");
            console.log("!!! WARNING: Custom hooks found !!!");
            console.log("Users should verify hook behavior before swapping");
        }
    }
    
    /**
     * @notice Analyze all pools for risk indicators
     */
    function test_PoolRiskAnalysis() public view {
        console.log("=== POOL RISK ANALYSIS ===");
        console.log("");
        
        uint256 poolCount;
        
        try IEulerSwapFactory(EULER_SWAP_FACTORY).getDeployedPoolsLength() returns (uint256 count) {
            poolCount = count;
        } catch {
            console.log("Could not query factory");
            return;
        }
        
        uint256 limit = poolCount > 30 ? 30 : poolCount;
        
        for (uint256 i = 0; i < limit; i++) {
            try IEulerSwapFactory(EULER_SWAP_FACTORY).getDeployedPoolAddress(i) returns (address poolAddr) {
                if (poolAddr == address(0)) continue;
                
                // Get dynamic params
                try IEulerSwap(poolAddr).getDynamicParams() returns (IEulerSwap.DynamicParams memory dParams) {
                    // Calculate risk score
                    uint256 riskScore = 0;
                    
                    if (dParams.swapHook != address(0)) riskScore += 50;  // Custom hook
                    if (dParams.swapHookedOperations > 0) riskScore += 25;  // Hook ops enabled
                    if (dParams.fee0 > 0.1e18) riskScore += 10;  // High fee
                    if (dParams.fee1 > 0.1e18) riskScore += 10;  // High fee
                    if (dParams.expiration != 0 && dParams.expiration < block.timestamp + 1 days) {
                        riskScore += 5;  // Expiring soon
                    }
                    
                    if (riskScore > 0) {
                        console.log("---");
                        console.log("Pool:", poolAddr);
                        console.log("Risk Score:", riskScore);
                        
                        if (dParams.swapHook != address(0)) {
                            console.log("  - Has custom hook!");
                        }
                        if (dParams.fee0 > 0.1e18 || dParams.fee1 > 0.1e18) {
                            console.log("  - High fees detected");
                        }
                    }
                } catch {}
            } catch {}
        }
    }
    
    /**
     * @notice Summary of hook types
     */
    function test_HookTypeSummary() public pure {
        console.log("=== HOOK TYPE REFERENCE ===");
        console.log("");
        console.log("swapHookedOperations is a bitmask:");
        console.log("  Bit 0 (1): EULER_SWAP_HOOK_BEFORE_SWAP");
        console.log("  Bit 1 (2): EULER_SWAP_HOOK_GET_FEE");
        console.log("  Bit 2 (4): EULER_SWAP_HOOK_AFTER_SWAP");
        console.log("");
        console.log("Common combinations:");
        console.log("  0: No hooks");
        console.log("  1: beforeSwap only");
        console.log("  2: getFee only");
        console.log("  4: afterSwap only");
        console.log("  7: All hooks");
        console.log("");
        console.log("RISK LEVELS:");
        console.log("  beforeSwap: Can reject swaps");
        console.log("  getFee: Can set dynamic fees");
        console.log("  afterSwap: Can reconfigure + reenter!");
    }
}
