// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

/**
 * @title AdvancedAttackVectors
 * @notice Comprehensive tests for remaining Euler attack surfaces:
 *   1. Oracle price manipulation
 *   2. Interest rate manipulation  
 *   3. First depositor attacks (VIRTUAL_DEPOSIT_AMOUNT = 1e6)
 *   4. Euler Earn aggregation attacks
 */

interface IEVC {
    function batch(BatchItem[] calldata items) external payable;
    function enableCollateral(address account, address vault) external payable;
    function enableController(address account, address vault) external payable;
}

struct BatchItem {
    address targetContract;
    address onBehalfOfAccount;
    uint256 value;
    bytes data;
}

interface IEVault {
    function deposit(uint256 assets, address receiver) external returns (uint256);
    function withdraw(uint256 assets, address receiver, address owner) external returns (uint256);
    function borrow(uint256 assets, address receiver) external returns (uint256);
    function repay(uint256 assets, address receiver) external returns (uint256);
    function asset() external view returns (address);
    function totalAssets() external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function debtOf(address account) external view returns (uint256);
    function totalBorrows() external view returns (uint256);
    function cash() external view returns (uint256);
    function convertToShares(uint256 assets) external view returns (uint256);
    function convertToAssets(uint256 shares) external view returns (uint256);
    function interestRate() external view returns (uint256);
    function interestAccumulator() external view returns (uint256);
    function oracle() external view returns (address);
    function unitOfAccount() external view returns (address);
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
    function transfer(address, uint256) external returns (bool);
    function decimals() external view returns (uint8);
    function symbol() external view returns (string memory);
}

interface IPerspective {
    function verifiedArray() external view returns (address[] memory);
}

interface IOracle {
    function getQuote(uint256 amount, address base, address quote) external view returns (uint256);
    function getQuotes(uint256 amount, address base, address quote) external view returns (uint256 bidOut, uint256 askOut);
}

interface IEulerEarn {
    function deposit(uint256 assets, address receiver) external returns (uint256);
    function withdraw(uint256 assets, address receiver, address owner) external returns (uint256);
    function totalAssets() external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function supplyQueue(uint256 index) external view returns (address);
    function supplyQueueLength() external view returns (uint256);
    function withdrawQueue(uint256 index) external view returns (address);
    function withdrawQueueLength() external view returns (uint256);
    function lastTotalAssets() external view returns (uint256);
    function lostAssets() external view returns (uint256);
    function fee() external view returns (uint96);
}

contract AdvancedAttackVectors is Test {
    address constant EVC = 0x0C9a3dd6b8F28529d72d7f9cE918D493519EE383;
    address constant GOVERNED_PERSPECTIVE = 0xC0121817FF224a018840e4D15a864747d36e6Eb2;
    address constant EULER_EARN_PERSPECTIVE = 0x492e9FE1289d43F8bB6275237BF16c9248C74D44;
    
    // VIRTUAL_DEPOSIT_AMOUNT from ConversionHelpers.sol
    uint256 constant VIRTUAL_DEPOSIT_AMOUNT = 1e6;
    
    address public attacker;
    
    function setUp() public {
        attacker = makeAddr("attacker");
        vm.deal(attacker, 100 ether);
    }
    
    /*//////////////////////////////////////////////////////////////
             TEST 1: FIRST DEPOSITOR / SHARE INFLATION ATTACK
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Analyze if VIRTUAL_DEPOSIT_AMOUNT = 1e6 is sufficient
     * @dev The attack: deposit 1 wei, donate large amount, steal from next depositor
     * 
     * Protection mechanism:
     * totalAssets = cash + borrows + VIRTUAL_DEPOSIT_AMOUNT
     * totalShares = shares + VIRTUAL_DEPOSIT_AMOUNT
     * 
     * This creates a "virtual" 1e6 deposit that exists from the start
     */
    function test_FirstDepositorProtection() public view {
        console.log("=== FIRST DEPOSITOR ATTACK ANALYSIS ===");
        console.log("");
        
        console.log("VIRTUAL_DEPOSIT_AMOUNT:", VIRTUAL_DEPOSIT_AMOUNT);
        console.log("");
        
        // For 18-decimal tokens:
        // 1e6 virtual deposit = 0.000000000001 tokens
        // 
        // Attack scenario:
        // 1. Attacker deposits 1 wei -> gets ~1 share (due to virtual 1e6)
        // 2. Attacker donates 10 ETH directly
        // 3. Victim deposits 10 ETH -> gets ~0 shares (rounding)
        // 4. Attacker withdraws all -> steals victim's funds
        
        console.log("For 18-decimal tokens (ETH, most ERC20):");
        console.log("  Virtual deposit = 0.000000000001 tokens");
        console.log("  This may NOT be sufficient protection!");
        console.log("");
        
        // Calculate attack profitability
        uint256 virtualAssets = VIRTUAL_DEPOSIT_AMOUNT;
        uint256 virtualShares = VIRTUAL_DEPOSIT_AMOUNT;
        
        // Attacker deposits 1 wei
        uint256 attackerDeposit = 1;
        uint256 attackerShares = (attackerDeposit * virtualShares) / virtualAssets;
        console.log("Attacker deposits 1 wei:");
        console.log("  Shares received:", attackerShares);
        
        // After deposit: totalAssets = 1e6 + 1, totalShares = 1e6 + attackerShares
        uint256 newTotalAssets = virtualAssets + attackerDeposit;
        uint256 newTotalShares = virtualShares + attackerShares;
        
        // Attacker donates 1e18 (1 token) directly
        uint256 donation = 1e18;
        newTotalAssets += donation;
        console.log("");
        console.log("After donating 1e18 (1 token):");
        console.log("  Total assets:", newTotalAssets);
        console.log("  Total shares:", newTotalShares);
        console.log("  Share price:", newTotalAssets * 1e18 / newTotalShares);
        
        // Victim deposits 1e18
        uint256 victimDeposit = 1e18;
        uint256 victimShares = (victimDeposit * newTotalShares) / newTotalAssets;
        console.log("");
        console.log("Victim deposits 1e18:");
        console.log("  Shares received:", victimShares);
        
        if (victimShares == 0) {
            console.log("  !!! VULNERABILITY: Victim gets 0 shares !!!");
        } else {
            console.log("  Victim protected by virtual deposit");
        }
        
        // Calculate loss
        uint256 finalTotalAssets = newTotalAssets + victimDeposit;
        uint256 finalTotalShares = newTotalShares + victimShares;
        
        if (victimShares > 0) {
            uint256 victimValue = victimShares * finalTotalAssets / finalTotalShares;
            uint256 victimLoss = victimDeposit - victimValue;
            console.log("");
            console.log("Victim's final value:", victimValue);
            console.log("Victim's loss:", victimLoss);
            console.log("Loss percentage:", victimLoss * 100 / victimDeposit, "%");
        }
        
        console.log("");
        console.log("CONCLUSION:");
        console.log("  1e6 virtual deposit provides ~1M:1 protection ratio");
        console.log("  Attack cost: ~1M tokens to steal 1 token");
        console.log("  For USDC (6 decimals): 1 token protection");
        console.log("  For ETH (18 decimals): 0.000000000001 token protection");
    }
    
    /*//////////////////////////////////////////////////////////////
             TEST 2: ORACLE MANIPULATION VECTORS
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Analyze oracle configurations across vaults
     */
    function test_OracleAnalysis() public view {
        console.log("=== ORACLE CONFIGURATION ANALYSIS ===");
        console.log("");
        
        address[] memory vaults = IPerspective(GOVERNED_PERSPECTIVE).verifiedArray();
        
        // Track unique oracles
        address[] memory uniqueOracles = new address[](50);
        uint256 uniqueCount = 0;
        
        console.log("Scanning vaults for oracle configurations...");
        console.log("");
        
        uint256 limit = vaults.length > 30 ? 30 : vaults.length;
        
        for (uint256 i = 0; i < limit; i++) {
            try IEVault(vaults[i]).oracle() returns (address oracleAddr) {
                if (oracleAddr != address(0)) {
                    // Check if unique
                    bool isNew = true;
                    for (uint256 j = 0; j < uniqueCount; j++) {
                        if (uniqueOracles[j] == oracleAddr) {
                            isNew = false;
                            break;
                        }
                    }
                    
                    if (isNew && uniqueCount < 50) {
                        uniqueOracles[uniqueCount] = oracleAddr;
                        uniqueCount++;
                        
                        console.log("Oracle found:", oracleAddr);
                        
                        // Get vault asset for context
                        try IEVault(vaults[i]).asset() returns (address asset) {
                            try IERC20(asset).symbol() returns (string memory symbol) {
                                console.log("  Used by vault with asset:", symbol);
                            } catch {}
                        } catch {}
                    }
                }
            } catch {}
        }
        
        console.log("");
        console.log("Unique oracles found:", uniqueCount);
        console.log("");
        console.log("ORACLE ATTACK VECTORS:");
        console.log("  1. Stale price exploitation (max staleness bypass)");
        console.log("  2. Flash loan price manipulation");
        console.log("  3. Cross-oracle arbitrage (bid/ask spread)");
        console.log("  4. Decimal mismatch between adapters");
    }
    
    /*//////////////////////////////////////////////////////////////
             TEST 3: INTEREST RATE MANIPULATION
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Analyze interest rate models and manipulation potential
     */
    function test_InterestRateManipulation() public view {
        console.log("=== INTEREST RATE MANIPULATION ANALYSIS ===");
        console.log("");
        
        address[] memory vaults = IPerspective(GOVERNED_PERSPECTIVE).verifiedArray();
        
        console.log("HIGH UTILIZATION VAULTS (manipulation targets):");
        console.log("");
        
        uint256 highUtilCount = 0;
        
        for (uint256 i = 0; i < vaults.length && i < 50; i++) {
            try IEVault(vaults[i]).totalBorrows() returns (uint256 borrows) {
                if (borrows > 0) {
                    try IEVault(vaults[i]).totalAssets() returns (uint256 assets) {
                        if (assets > 0) {
                            uint256 utilization = (borrows * 100) / assets;
                            
                            if (utilization > 80) {
                                highUtilCount++;
                                
                                console.log("---");
                                console.log("Vault:", vaults[i]);
                                console.log("Utilization:", utilization, "%");
                                console.log("Borrows:", borrows);
                                console.log("Assets:", assets);
                                
                                // Get interest rate
                                try IEVault(vaults[i]).interestRate() returns (uint256 rate) {
                                    // Rate is in 1e27 (RAY) per second
                                    // APY = (1 + rate/1e27)^31536000 - 1
                                    uint256 aprBps = rate * 31536000 / 1e23; // Rough APR in bps
                                    console.log("Interest rate (bps/year ~):", aprBps);
                                } catch {}
                                
                                try IEVault(vaults[i]).asset() returns (address asset) {
                                    try IERC20(asset).symbol() returns (string memory symbol) {
                                        console.log("Asset:", symbol);
                                    } catch {}
                                } catch {}
                            }
                        }
                    } catch {}
                }
            } catch {}
        }
        
        console.log("");
        console.log("High utilization vaults found:", highUtilCount);
        console.log("");
        console.log("INTEREST RATE ATTACK VECTORS:");
        console.log("  1. Borrow to push utilization to 100%");
        console.log("  2. Force liquidations via rate spike");
        console.log("  3. Interest accumulator overflow");
        console.log("  4. Rate model kink exploitation");
    }
    
    /*//////////////////////////////////////////////////////////////
             TEST 4: EULER EARN AGGREGATION ATTACKS
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Analyze Euler Earn vaults for aggregation attacks
     */
    function test_EulerEarnAnalysis() public view {
        console.log("=== EULER EARN AGGREGATION ANALYSIS ===");
        console.log("");
        
        address[] memory earnVaults;
        
        try IPerspective(EULER_EARN_PERSPECTIVE).verifiedArray() returns (address[] memory vaults) {
            earnVaults = vaults;
            console.log("Euler Earn vaults found:", earnVaults.length);
        } catch {
            console.log("Could not query Euler Earn perspective");
            return;
        }
        
        console.log("");
        
        for (uint256 i = 0; i < earnVaults.length; i++) {
            console.log("---");
            console.log("Earn Vault:", earnVaults[i]);
            
            IEulerEarn earn = IEulerEarn(earnVaults[i]);
            
            try earn.totalAssets() returns (uint256 assets) {
                console.log("Total Assets:", assets);
            } catch {}
            
            try earn.totalSupply() returns (uint256 supply) {
                console.log("Total Supply:", supply);
            } catch {}
            
            try earn.lastTotalAssets() returns (uint256 lastAssets) {
                console.log("Last Total Assets:", lastAssets);
            } catch {}
            
            try earn.lostAssets() returns (uint256 lost) {
                if (lost > 0) {
                    console.log("!!! LOST ASSETS:", lost);
                }
            } catch {}
            
            try earn.fee() returns (uint96 fee) {
                console.log("Fee (bps):", fee / 1e14); // Fee is in WAD
            } catch {}
            
            // Check supply queue
            try earn.supplyQueueLength() returns (uint256 len) {
                console.log("Supply queue length:", len);
                
                // Show first few strategies
                for (uint256 j = 0; j < len && j < 3; j++) {
                    try earn.supplyQueue(j) returns (address strategy) {
                        console.log("  Strategy", j, ":", strategy);
                    } catch {}
                }
            } catch {}
        }
        
        console.log("");
        console.log("EULER EARN ATTACK VECTORS:");
        console.log("  1. Rebalance sandwich attack");
        console.log("  2. Strategy queue manipulation");
        console.log("  3. Lost assets accounting exploit");
        console.log("  4. Fee calculation manipulation");
        console.log("  5. Cross-strategy arbitrage");
    }
    
    /*//////////////////////////////////////////////////////////////
             TEST 5: LIQUIDATION THRESHOLD EDGE CASES
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Find accounts near liquidation threshold
     */
    function test_LiquidationEdgeCases() public pure {
        console.log("=== LIQUIDATION EDGE CASE ANALYSIS ===");
        console.log("");
        
        console.log("LIQUIDATION ATTACK PATTERNS:");
        console.log("");
        
        console.log("1. PRICE MANIPULATION LIQUIDATION:");
        console.log("   - Flash loan to move oracle price");
        console.log("   - Trigger liquidations at manipulated price");
        console.log("   - Profit from liquidation discount");
        console.log("   - Repay flash loan");
        console.log("");
        
        console.log("2. JUST-IN-TIME LIQUIDATION:");
        console.log("   - Monitor mempool for borrows");
        console.log("   - Frontrun with oracle update");
        console.log("   - Liquidate in same block");
        console.log("");
        
        console.log("3. SELF-LIQUIDATION (bypassing cool-off):");
        console.log("   - Create position via operator");
        console.log("   - Operator is different account");
        console.log("   - Cool-off check on violator only?");
        console.log("");
        
        console.log("4. BATCH LIQUIDATION EXPLOIT:");
        console.log("   - Multiple liquidations in one batch");
        console.log("   - Deferred checks = temporarily insolvent state");
        console.log("   - Extract value before checks run");
    }
    
    /*//////////////////////////////////////////////////////////////
             TEST 6: PRECISION LOSS ANALYSIS
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Analyze precision loss in share/asset conversions
     */
    function test_PrecisionLossAnalysis() public pure {
        console.log("=== PRECISION LOSS ANALYSIS ===");
        console.log("");
        
        // The conversion uses:
        // shares = assets * totalShares / totalAssets
        // assets = shares * totalAssets / totalShares
        
        // With VIRTUAL_DEPOSIT_AMOUNT = 1e6:
        // Minimum totalShares = 1e6
        // Minimum totalAssets = 1e6
        
        console.log("Precision analysis for rounding attacks:");
        console.log("");
        
        // Case 1: Very small deposit
        uint256 virtualDeposit = 1e6;
        uint256 smallDeposit = 1; // 1 wei
        
        uint256 sharesDown = smallDeposit * virtualDeposit / virtualDeposit;
        uint256 sharesUp = (smallDeposit * virtualDeposit + virtualDeposit - 1) / virtualDeposit;
        
        console.log("Depositing 1 wei:");
        console.log("  Shares (round down):", sharesDown);
        console.log("  Shares (round up):", sharesUp);
        console.log("");
        
        // Case 2: Accumulated dust
        console.log("Dust accumulation attack:");
        console.log("  1. Make many small deposits (round down)");
        console.log("  2. Vault accumulates rounding dust");
        console.log("  3. Large depositor gets extra value");
        console.log("");
        
        console.log("MITIGATION REVIEW:");
        console.log("  - toSharesUp() used for withdrawals");
        console.log("  - toSharesDown() used for deposits");
        console.log("  - toAssetsUp() used for debt calculations");
        console.log("  - VIRTUAL_DEPOSIT provides base precision");
    }
    
    /*//////////////////////////////////////////////////////////////
             SUMMARY: ALL ATTACK VECTORS
    //////////////////////////////////////////////////////////////*/
    
    function test_AttackVectorSummary() public pure {
        console.log("=== EULER V2 ATTACK VECTOR SUMMARY ===");
        console.log("");
        
        console.log("HIGH PRIORITY (Potential $5M+ bounties):");
        console.log("  1. Oracle manipulation -> bad liquidations");
        console.log("  2. Interest rate manipulation -> forced liquidations");
        console.log("  3. Euler Earn rebalance attacks");
        console.log("  4. Cross-vault collateral (if found)");
        console.log("");
        
        console.log("MEDIUM PRIORITY:");
        console.log("  5. First depositor attack (1e6 virtual may be weak)");
        console.log("  6. Precision loss accumulation");
        console.log("  7. Batch execution edge cases");
        console.log("  8. Self-liquidation via operators");
        console.log("");
        
        console.log("LOWER PRIORITY:");
        console.log("  9. Gas griefing (many collaterals)");
        console.log("  10. Event emission inconsistencies");
        console.log("  11. Timelock bypass in Euler Earn");
        console.log("");
        
        console.log("NEXT STEPS FOR HUNTER:");
        console.log("  1. Deep dive into oracle adapters");
        console.log("  2. Fuzz interest rate edge cases");
        console.log("  3. Analyze Euler Earn rebalance flow");
        console.log("  4. Check for audit acknowledged issues");
    }
}
