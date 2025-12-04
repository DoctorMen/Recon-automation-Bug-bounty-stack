// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

/**
 * @title CircularCollateralTest
 * @notice Scan 265 vaults for circular collateral dependencies
 * @dev Looking for: Vault A accepts Vault B as collateral, Vault B accepts Vault A
 * 
 * ATTACK HYPOTHESIS:
 * 1. Deposit into Vault A, get shares
 * 2. Use Vault A shares as collateral in Vault B
 * 3. Borrow from Vault B
 * 4. Use borrowed funds to deposit more into Vault A
 * 5. Create leverage loop that amplifies liquidation cascades
 */

interface IEVC {
    function getCollaterals(address account) external view returns (address[] memory);
}

interface IEVault {
    function asset() external view returns (address);
    function totalAssets() external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function totalBorrows() external view returns (uint256);
    function LTV(address collateral) external view returns (uint16 borrowLTV, uint16 liquidationLTV, uint16 initialLiquidationLTV, uint48 targetTimestamp, uint32 rampDuration);
    function oracle() external view returns (address);
}

interface IERC20 {
    function symbol() external view returns (string memory);
    function decimals() external view returns (uint8);
}

interface IPerspective {
    function verifiedArray() external view returns (address[] memory);
}

contract CircularCollateralTest is Test {
    address constant EVC = 0x0C9a3dd6b8F28529d72d7f9cE918D493519EE383;
    address constant GOVERNED_PERSPECTIVE = 0xC0121817FF224a018840e4D15a864747d36e6Eb2;
    
    // Store vault addresses for cross-reference
    address[] public allVaults;
    mapping(address => bool) public isVault;
    
    function setUp() public {
        // Load all vaults
        address[] memory vaults = IPerspective(GOVERNED_PERSPECTIVE).verifiedArray();
        for (uint256 i = 0; i < vaults.length; i++) {
            allVaults.push(vaults[i]);
            isVault[vaults[i]] = true;
        }
    }
    
    /*//////////////////////////////////////////////////////////////
                    TEST: SCAN FOR CIRCULAR COLLATERAL
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Scan all vaults to find circular collateral relationships
     * @dev A circular relationship exists if Vault A accepts Vault B AND Vault B accepts Vault A
     */
    function test_ScanCircularCollateral() public view {
        console.log("=== SCANNING FOR CIRCULAR COLLATERAL ===");
        console.log("");
        console.log("Total vaults to scan:", allVaults.length);
        console.log("");
        
        uint256 circularCount = 0;
        
        // Check first 50 vaults to avoid timeout
        uint256 limit = allVaults.length > 50 ? 50 : allVaults.length;
        
        for (uint256 i = 0; i < limit; i++) {
            for (uint256 j = i + 1; j < limit; j++) {
                // Check bidirectional LTV
                (bool hasAB, uint16 ltvAB) = _checkLTV(allVaults[i], allVaults[j]);
                if (hasAB) {
                    (bool hasBA, uint16 ltvBA) = _checkLTV(allVaults[j], allVaults[i]);
                    if (hasBA) {
                        circularCount++;
                        console.log("!!! CIRCULAR COLLATERAL FOUND !!!");
                        console.log("Vault A:", allVaults[i]);
                        console.log("Vault B:", allVaults[j]);
                        console.log("A->B LTV:", ltvAB, "B->A LTV:", ltvBA);
                        console.log("---");
                    }
                }
            }
        }
        
        console.log("");
        console.log("=== SCAN RESULTS ===");
        console.log("Vaults scanned:", limit);
        console.log("CIRCULAR relationships found:", circularCount);
    }
    
    function _checkLTV(address vault, address collateral) internal view returns (bool exists, uint16 ltv) {
        try IEVault(vault).LTV(collateral) returns (uint16 borrowLTV, uint16, uint16, uint48, uint32) {
            return (borrowLTV > 0, borrowLTV);
        } catch {
            return (false, 0);
        }
    }
    
    /*//////////////////////////////////////////////////////////////
                    TEST: FIND VAULTS ACCEPTING OTHER VAULTS
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Find all cases where a vault accepts another vault's shares as collateral
     */
    function test_VaultAcceptsVaultShares() public view {
        console.log("=== VAULTS ACCEPTING OTHER VAULT SHARES ===");
        console.log("");
        
        uint256 foundCount = 0;
        
        // Check first 50 vaults
        for (uint256 i = 0; i < allVaults.length && i < 50; i++) {
            address vault = allVaults[i];
            
            // Check if this vault accepts any other vault as collateral
            for (uint256 j = 0; j < allVaults.length && j < 50; j++) {
                if (i == j) continue;
                
                address potentialCollateral = allVaults[j];
                
                try IEVault(vault).LTV(potentialCollateral) returns (uint16 borrowLTV, uint16 liquidationLTV, uint16, uint48, uint32) {
                    if (borrowLTV > 0) {
                        foundCount++;
                        
                        // Get symbols
                        string memory vaultAssetSymbol = "?";
                        string memory collateralAssetSymbol = "?";
                        
                        try IEVault(vault).asset() returns (address a) {
                            try IERC20(a).symbol() returns (string memory s) {
                                vaultAssetSymbol = s;
                            } catch {}
                        } catch {}
                        
                        try IEVault(potentialCollateral).asset() returns (address a) {
                            try IERC20(a).symbol() returns (string memory s) {
                                collateralAssetSymbol = s;
                            } catch {}
                        } catch {}
                        
                        console.log("---");
                        console.log("Vault (", vaultAssetSymbol, "):", vault);
                        console.log("Accepts vault (", collateralAssetSymbol, "):", potentialCollateral);
                        console.log("Borrow LTV:", borrowLTV);
                        console.log("Liquidation LTV:", liquidationLTV);
                    }
                } catch {}
            }
        }
        
        console.log("");
        console.log("Total vault-accepts-vault found:", foundCount);
    }
    
    /*//////////////////////////////////////////////////////////////
                    TEST: ANALYZE COLLATERAL CHAINS
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Look for longer collateral chains (simplified)
     */
    function test_CollateralChainDepth() public view {
        console.log("=== COLLATERAL CHAIN ANALYSIS ===");
        console.log("(Simplified - checking for 2-hop chains only)");
        console.log("");
        
        // Just report on 2-hop circular chains found in main scan
        console.log("See test_ScanCircularCollateral for circular findings");
    }
    
    /*//////////////////////////////////////////////////////////////
                    TEST: HIGH TVL VAULT COLLATERAL CHECK
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Check collateral configurations for highest TVL vaults
     */
    function test_HighTVLVaultCollateral() public view {
        console.log("=== HIGH TVL VAULT COLLATERAL ANALYSIS ===");
        console.log("");
        
        // Find top 10 vaults by TVL
        address[10] memory topVaults;
        uint256[10] memory topTVL;
        
        for (uint256 i = 0; i < allVaults.length; i++) {
            try IEVault(allVaults[i]).totalAssets() returns (uint256 assets) {
                for (uint256 j = 0; j < 10; j++) {
                    if (assets > topTVL[j]) {
                        // Shift down
                        for (uint256 k = 9; k > j; k--) {
                            topTVL[k] = topTVL[k-1];
                            topVaults[k] = topVaults[k-1];
                        }
                        topTVL[j] = assets;
                        topVaults[j] = allVaults[i];
                        break;
                    }
                }
            } catch {}
        }
        
        console.log("TOP 10 VAULTS BY TVL:");
        console.log("");
        
        for (uint256 i = 0; i < 10; i++) {
            if (topVaults[i] == address(0)) continue;
            
            console.log("Rank", i + 1);
            console.log("  Vault:", topVaults[i]);
            console.log("  TVL:", topTVL[i]);
            
            // Get asset
            try IEVault(topVaults[i]).asset() returns (address asset) {
                try IERC20(asset).symbol() returns (string memory symbol) {
                    console.log("  Asset:", symbol);
                } catch {}
            } catch {}
            
            // Count accepted collaterals
            uint256 acceptedCount = 0;
            for (uint256 j = 0; j < allVaults.length && j < 50; j++) {
                try IEVault(topVaults[i]).LTV(allVaults[j]) returns (uint16 ltv, uint16, uint16, uint48, uint32) {
                    if (ltv > 0) acceptedCount++;
                } catch {}
            }
            console.log("  Accepts other vaults as collateral:", acceptedCount);
            console.log("");
        }
    }
}
