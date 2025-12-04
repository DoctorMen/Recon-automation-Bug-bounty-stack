// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

/**
 * @title LostAssetsDeepDive
 * @notice Deep analysis of Euler Earn lostAssets accounting
 * 
 * DISCOVERED: 2 Euler Earn vaults have non-zero lostAssets:
 *   - 0x3B4802...AF: 6 lost assets
 *   - 0xb072b2...3a: 3 lost assets
 * 
 * MECHANISM:
 * 1. lostAssets tracks assets that "disappeared" from strategies
 * 2. When realTotalAssets < lastTotalAssets - lostAssets, lostAssets increases
 * 3. newTotalAssets = realTotalAssets + newLostAssets (ghost assets)
 * 4. This prevents share price from decreasing
 * 
 * ATTACK VECTORS:
 * 1. Manipulate strategy to decrease realTotalAssets
 * 2. Cause lostAssets to accumulate incorrectly
 * 3. Exploit the "ghost assets" accounting
 */

interface IEulerEarn {
    function deposit(uint256 assets, address receiver) external returns (uint256);
    function withdraw(uint256 assets, address receiver, address owner) external returns (uint256);
    function totalAssets() external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function asset() external view returns (address);
    function supplyQueue(uint256 index) external view returns (address);
    function supplyQueueLength() external view returns (uint256);
    function withdrawQueue(uint256 index) external view returns (address);
    function withdrawQueueLength() external view returns (uint256);
    function lastTotalAssets() external view returns (uint256);
    function lostAssets() external view returns (uint256);
    function fee() external view returns (uint96);
    function balanceOf(address) external view returns (uint256);
    function convertToAssets(uint256 shares) external view returns (uint256);
    function convertToShares(uint256 assets) external view returns (uint256);
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function symbol() external view returns (string memory);
    function decimals() external view returns (uint8);
}

interface IEVault {
    function totalAssets() external view returns (uint256);
    function balanceOf(address) external view returns (uint256);
}

interface IPerspective {
    function verifiedArray() external view returns (address[] memory);
}

contract LostAssetsDeepDive is Test {
    address constant EULER_EARN_PERSPECTIVE = 0x492e9FE1289d43F8bB6275237BF16c9248C74D44;
    
    // Vaults with known lostAssets
    address constant EARN_VAULT_1 = 0x3B4802FDb0E5d74aA37d58FD77d63e93d4f9A4AF;
    address constant EARN_VAULT_2 = 0xb072b2779F1EF1A6A9D2d5fAa1766F341B92aB3a;
    
    function setUp() public {}
    
    /*//////////////////////////////////////////////////////////////
                    TEST: LOST ASSETS ACCOUNTING DEEP DIVE
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Analyze the lostAssets mechanism in detail
     */
    function test_LostAssetsAccounting() public view {
        console.log("=== LOST ASSETS ACCOUNTING ANALYSIS ===");
        console.log("");
        
        console.log("HOW lostAssets WORKS:");
        console.log("--------------------");
        console.log("1. Euler Earn tracks 'lastTotalAssets' - expected assets");
        console.log("2. 'realTotalAssets' = sum of assets in all strategies");
        console.log("3. If realTotalAssets < lastTotalAssets - lostAssets:");
        console.log("     -> lostAssets += (lastTotalAssets - realTotalAssets)");
        console.log("4. totalAssets = realTotalAssets + lostAssets");
        console.log("");
        
        console.log("WHY lostAssets CAN OCCUR:");
        console.log("-------------------------");
        console.log("- Strategy vault loses assets (bad debt, exploit)");
        console.log("- Rounding differences in deposit/withdraw");
        console.log("- Fee-on-transfer token edge cases");
        console.log("- Strategy vault share price manipulation");
        console.log("");
    }
    
    /**
     * @notice Analyze vaults with non-zero lostAssets
     */
    function test_AnalyzeVaultsWithLostAssets() public view {
        console.log("=== VAULTS WITH NON-ZERO LOST ASSETS ===");
        console.log("");
        
        // Vault 1: 0x3B4802...
        console.log("VAULT 1: 0x3B4802FDb0E5d74aA37d58FD77d63e93d4f9A4AF");
        _analyzeEarnVault(EARN_VAULT_1);
        
        console.log("");
        console.log("---");
        console.log("");
        
        // Vault 2: 0xb072b2...
        console.log("VAULT 2: 0xb072b2779F1EF1A6A9D2d5fAa1766F341B92aB3a");
        _analyzeEarnVault(EARN_VAULT_2);
    }
    
    function _analyzeEarnVault(address earnVault) internal view {
        IEulerEarn earn = IEulerEarn(earnVault);
        
        // Basic metrics
        uint256 totalAssets = earn.totalAssets();
        uint256 totalSupply = earn.totalSupply();
        uint256 lastTotalAssets = earn.lastTotalAssets();
        uint256 lostAssets = earn.lostAssets();
        
        console.log("Total Assets:", totalAssets);
        console.log("Total Supply:", totalSupply);
        console.log("Last Total Assets:", lastTotalAssets);
        console.log("Lost Assets:", lostAssets);
        
        // Calculate real assets (without ghost assets)
        uint256 realAssets = totalAssets - lostAssets;
        console.log("Real Assets (total - lost):", realAssets);
        
        // Share price analysis
        if (totalSupply > 0) {
            uint256 sharePrice = (totalAssets * 1e18) / totalSupply;
            uint256 realSharePrice = (realAssets * 1e18) / totalSupply;
            console.log("Share Price (with ghost):", sharePrice);
            console.log("Share Price (real):", realSharePrice);
            
            uint256 priceDiff = sharePrice - realSharePrice;
            console.log("Ghost value per share:", priceDiff);
        }
        
        // Underlying asset
        try earn.asset() returns (address asset) {
            try IERC20(asset).symbol() returns (string memory symbol) {
                console.log("Underlying asset:", symbol);
            } catch {}
        } catch {}
        
        // Strategy analysis
        console.log("");
        console.log("Strategy breakdown:");
        
        try earn.withdrawQueueLength() returns (uint256 len) {
            for (uint256 i = 0; i < len; i++) {
                try earn.withdrawQueue(i) returns (address strategy) {
                    console.log("  Strategy", i, ":", strategy);
                    
                    // Check strategy's view of the earn vault's holdings
                    try IEVault(strategy).balanceOf(earnVault) returns (uint256 shares) {
                        console.log("    Earn vault shares:", shares);
                    } catch {}
                    
                    try IEVault(strategy).totalAssets() returns (uint256 stratAssets) {
                        console.log("    Strategy total assets:", stratAssets);
                    } catch {}
                } catch {}
            }
        } catch {}
    }
    
    /*//////////////////////////////////////////////////////////////
                    TEST: POTENTIAL ATTACK VECTORS
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Analyze potential exploitation of lostAssets
     */
    function test_LostAssetsExploitVectors() public pure {
        console.log("=== LOST ASSETS EXPLOITATION VECTORS ===");
        console.log("");
        
        console.log("VECTOR 1: GHOST ASSET INFLATION");
        console.log("--------------------------------");
        console.log("1. Attacker deposits into Euler Earn");
        console.log("2. Attacker manipulates strategy to lose assets");
        console.log("3. lostAssets increases, but totalAssets stays same");
        console.log("4. Other depositors' shares are diluted by ghost assets");
        console.log("5. Attacker withdraws more than their fair share");
        console.log("");
        
        console.log("VECTOR 2: RATE MANIPULATION VIA STRATEGY");
        console.log("-----------------------------------------");
        console.log("1. Flash loan to deposit large amount into strategy");
        console.log("2. Earn vault's expectedSupplyAssets increases");
        console.log("3. Withdraw flash loan, strategy assets decrease");
        console.log("4. lostAssets increases incorrectly");
        console.log("5. Ghost assets inflate share price");
        console.log("");
        
        console.log("VECTOR 3: ROUNDING ACCUMULATION");
        console.log("--------------------------------");
        console.log("1. Many small deposits/withdrawals");
        console.log("2. Each causes tiny rounding difference");
        console.log("3. lostAssets slowly accumulates dust");
        console.log("4. Over time, significant ghost assets build up");
        console.log("");
        
        console.log("VECTOR 4: STRATEGY SHARE PRICE MANIPULATION");
        console.log("--------------------------------------------");
        console.log("1. Donate to strategy vault (increases share price)");
        console.log("2. realTotalAssets increases without deposit");
        console.log("3. Earn vault's lastTotalAssets out of sync");
        console.log("4. Next withdraw triggers lostAssets increase");
        console.log("");
        
        console.log("KNOWN ACKNOWLEDGED ISSUES:");
        console.log("--------------------------");
        console.log("From EulerEarn.sol line 922:");
        console.log("  'It is acknowledged that feeAssets may be rounded");
        console.log("   down to 0 if totalInterest * fee < WAD'");
        console.log("");
        console.log("From EulerEarn.sol lines 705-707 and 727-730:");
        console.log("  'lastTotalAssets +/- assets may be a little above");
        console.log("   totalAssets(). This can lead to a small accrual");
        console.log("   of lostAssets at the next interaction.'");
    }
    
    /*//////////////////////////////////////////////////////////////
                    TEST: SCAN ALL EULER EARN FOR LOST ASSETS
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Scan all Euler Earn vaults for lostAssets
     */
    function test_ScanAllEulerEarnForLostAssets() public view {
        console.log("=== SCANNING ALL EULER EARN VAULTS ===");
        console.log("");
        
        address[] memory earnVaults;
        try IPerspective(EULER_EARN_PERSPECTIVE).verifiedArray() returns (address[] memory vaults) {
            earnVaults = vaults;
        } catch {
            console.log("Could not query perspective");
            return;
        }
        
        uint256 totalLostAssets = 0;
        uint256 vaultsWithLostAssets = 0;
        
        for (uint256 i = 0; i < earnVaults.length; i++) {
            IEulerEarn earn = IEulerEarn(earnVaults[i]);
            
            try earn.lostAssets() returns (uint256 lost) {
                if (lost > 0) {
                    vaultsWithLostAssets++;
                    totalLostAssets += lost;
                    
                    console.log("---");
                    console.log("Vault:", earnVaults[i]);
                    console.log("Lost Assets:", lost);
                    
                    try earn.totalAssets() returns (uint256 total) {
                        if (total > 0) {
                            uint256 lostPct = (lost * 10000) / total;
                            console.log("Lost % (bps):", lostPct);
                        }
                    } catch {}
                    
                    try earn.asset() returns (address asset) {
                        try IERC20(asset).symbol() returns (string memory symbol) {
                            console.log("Asset:", symbol);
                        } catch {}
                    } catch {}
                }
            } catch {}
        }
        
        console.log("");
        console.log("=== SUMMARY ===");
        console.log("Total Euler Earn vaults:", earnVaults.length);
        console.log("Vaults with lost assets:", vaultsWithLostAssets);
        console.log("Total lost assets (raw):", totalLostAssets);
    }
    
    /*//////////////////////////////////////////////////////////////
                    TEST: BUG BOUNTY RELEVANCE
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Assess bug bounty relevance of lostAssets findings
     */
    function test_BugBountyAssessment() public pure {
        console.log("=== BUG BOUNTY ASSESSMENT ===");
        console.log("");
        
        console.log("FINDING: Non-zero lostAssets in production vaults");
        console.log("");
        
        console.log("SEVERITY ASSESSMENT:");
        console.log("--------------------");
        console.log("- Lost assets values are small (3-6 wei)");
        console.log("- Likely from expected rounding (documented)");
        console.log("- No significant value at risk");
        console.log("- Verdict: INFORMATIONAL (known behavior)");
        console.log("");
        
        console.log("POTENTIAL ESCALATION:");
        console.log("---------------------");
        console.log("Could be MEDIUM/HIGH if we can show:");
        console.log("1. Attacker can inflate lostAssets significantly");
        console.log("2. Ghost assets affect share price calculations");
        console.log("3. Extraction possible via careful timing");
        console.log("");
        
        console.log("NEXT STEPS FOR HUNTER:");
        console.log("----------------------");
        console.log("1. Try to cause large lostAssets via strategy manipulation");
        console.log("2. Test if ghost assets can be extracted");
        console.log("3. Check if rounding can be accumulated faster");
        console.log("4. Review audit reports for related findings");
    }
}
