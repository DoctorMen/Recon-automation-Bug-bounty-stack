// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

/**
 * @title DebtSocializationTest
 * @notice Deep dive on debt socialization attack vectors
 * @dev MIN_SOCIALIZATION_LIABILITY_VALUE = 1e6 (very small!)
 * 
 * ATTACK HYPOTHESIS:
 * 1. Create many small debt positions (just above 1e6)
 * 2. Manipulate collateral to zero
 * 3. Trigger debt socialization repeatedly
 * 4. Drain vault value through share price dilution
 */

interface IEVC {
    function batch(BatchItem[] calldata items) external payable;
    function enableCollateral(address account, address vault) external payable;
    function enableController(address account, address vault) external payable;
    function getCollaterals(address account) external view returns (address[] memory);
    function getControllers(address account) external view returns (address[] memory);
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
    function liquidate(address violator, address collateral, uint256 repayAssets, uint256 minYieldBalance) external;
    function checkLiquidation(address liquidator, address violator, address collateral) external view returns (uint256 maxRepay, uint256 maxYield);
    function asset() external view returns (address);
    function totalAssets() external view returns (uint256);
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function debtOf(address account) external view returns (uint256);
    function totalBorrows() external view returns (uint256);
    function cash() external view returns (uint256);
    function convertToShares(uint256 assets) external view returns (uint256);
    function convertToAssets(uint256 shares) external view returns (uint256);
    function maxDeposit(address) external view returns (uint256);
    function LTV(address collateral) external view returns (uint16 borrowLTV, uint16 liquidationLTV, uint16 initialLiquidationLTV, uint48 targetTimestamp, uint32 rampDuration);
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
}

contract DebtSocializationTest is Test {
    // Constants
    address constant EVC = 0x0C9a3dd6b8F28529d72d7f9cE918D493519EE383;
    address constant GOVERNED_PERSPECTIVE = 0xC0121817FF224a018840e4D15a864747d36e6Eb2;
    
    // MIN_SOCIALIZATION_LIABILITY_VALUE from Liquidation.sol
    uint256 constant MIN_SOCIALIZATION_LIABILITY_VALUE = 1e6;
    
    IEVC public evc;
    
    function setUp() public {
        evc = IEVC(EVC);
    }
    
    /*//////////////////////////////////////////////////////////////
                    TEST: DEBT SOCIALIZATION THRESHOLD
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Analyze the debt socialization threshold
     * @dev The threshold is only 1e6 - absurdly small for most tokens
     */
    function test_DebtSocializationThreshold() public view {
        console.log("=== DEBT SOCIALIZATION THRESHOLD ANALYSIS ===");
        console.log("");
        
        // MIN_SOCIALIZATION_LIABILITY_VALUE = 1e6
        // For different token decimals, this means:
        
        console.log("MIN_SOCIALIZATION_LIABILITY_VALUE:", MIN_SOCIALIZATION_LIABILITY_VALUE);
        console.log("");
        
        // 18 decimals (ETH, most ERC20): 1e6 / 1e18 = 0.000000000001 tokens
        console.log("For 18 decimal tokens: 0.000000000001 tokens");
        
        // 6 decimals (USDC, USDT): 1e6 / 1e6 = 1 token ($1)
        console.log("For 6 decimal tokens: 1 token ($1)");
        
        // 8 decimals (WBTC): 1e6 / 1e8 = 0.01 tokens ($500 at $50k BTC)
        console.log("For 8 decimal tokens: 0.01 tokens");
        
        console.log("");
        console.log("INSIGHT: Threshold is in UNIT_OF_ACCOUNT value, not raw tokens");
        console.log("Unit of account is typically USD (1e18 precision)");
        console.log("So 1e6 = $0.000000000001 in USD terms!");
        console.log("");
        console.log("CRITICAL: This threshold is essentially ZERO!");
    }
    
    /*//////////////////////////////////////////////////////////////
                    TEST: FIND VAULTS WITH ACTIVE BORROWS
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Find vaults that have active borrows (potential debt socialization targets)
     */
    function test_FindVaultsWithBorrows() public view {
        console.log("=== SCANNING VAULTS FOR ACTIVE BORROWS ===");
        console.log("");
        
        address[] memory vaults = IPerspective(GOVERNED_PERSPECTIVE).verifiedArray();
        console.log("Total governed vaults:", vaults.length);
        console.log("");
        
        uint256 vaultsWithBorrows = 0;
        
        // Check first 50 vaults for borrows
        uint256 checkLimit = vaults.length > 50 ? 50 : vaults.length;
        
        for (uint256 i = 0; i < checkLimit; i++) {
            try IEVault(vaults[i]).totalBorrows() returns (uint256 borrows) {
                if (borrows > 0) {
                    vaultsWithBorrows++;
                    
                    // Get vault details
                    address asset = IEVault(vaults[i]).asset();
                    string memory symbol;
                    try IERC20(asset).symbol() returns (string memory s) {
                        symbol = s;
                    } catch {
                        symbol = "UNKNOWN";
                    }
                    
                    uint256 totalAssets = IEVault(vaults[i]).totalAssets();
                    
                    console.log("---");
                    console.log("Vault:", vaults[i]);
                    console.log("Asset:", symbol);
                    console.log("Total Borrows:", borrows);
                    console.log("Total Assets:", totalAssets);
                    
                    // Calculate utilization
                    if (totalAssets > 0) {
                        uint256 utilization = (borrows * 100) / totalAssets;
                        console.log("Utilization:", utilization, "%");
                    }
                }
            } catch {}
        }
        
        console.log("");
        console.log("=== SUMMARY ===");
        console.log("Vaults scanned:", checkLimit);
        console.log("Vaults with active borrows:", vaultsWithBorrows);
    }
    
    /*//////////////////////////////////////////////////////////////
                    TEST: ANALYZE HIGH-BORROW VAULTS
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Deep analysis of vaults with highest borrow amounts
     */
    function test_AnalyzeHighBorrowVaults() public view {
        console.log("=== HIGH BORROW VAULT ANALYSIS ===");
        console.log("");
        
        address[] memory vaults = IPerspective(GOVERNED_PERSPECTIVE).verifiedArray();
        
        // Track top 5 vaults by borrows
        address[5] memory topVaults;
        uint256[5] memory topBorrows;
        
        for (uint256 i = 0; i < vaults.length; i++) {
            try IEVault(vaults[i]).totalBorrows() returns (uint256 borrows) {
                if (borrows > 0) {
                    // Insert into sorted array
                    for (uint256 j = 0; j < 5; j++) {
                        if (borrows > topBorrows[j]) {
                            // Shift down
                            for (uint256 k = 4; k > j; k--) {
                                topBorrows[k] = topBorrows[k-1];
                                topVaults[k] = topVaults[k-1];
                            }
                            topBorrows[j] = borrows;
                            topVaults[j] = vaults[i];
                            break;
                        }
                    }
                }
            } catch {}
        }
        
        console.log("TOP 5 VAULTS BY BORROW AMOUNT:");
        console.log("");
        
        for (uint256 i = 0; i < 5; i++) {
            if (topVaults[i] != address(0)) {
                console.log("Rank", i + 1);
                console.log("  Vault:", topVaults[i]);
                console.log("  Borrows:", topBorrows[i]);
                
                // Get more details
                try IEVault(topVaults[i]).asset() returns (address asset) {
                    try IERC20(asset).symbol() returns (string memory symbol) {
                        console.log("  Asset:", symbol);
                    } catch {}
                    try IERC20(asset).decimals() returns (uint8 decimals) {
                        console.log("  Decimals:", decimals);
                    } catch {}
                } catch {}
                
                try IEVault(topVaults[i]).totalAssets() returns (uint256 assets) {
                    console.log("  Total Assets:", assets);
                } catch {}
                
                try IEVault(topVaults[i]).totalSupply() returns (uint256 supply) {
                    console.log("  Total Supply:", supply);
                } catch {}
                
                console.log("");
            }
        }
    }
    
    /*//////////////////////////////////////////////////////////////
                    TEST: DEBT SOCIALIZATION CONDITIONS
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Check what's needed for debt socialization to occur
     */
    function test_DebtSocializationConditions() public pure {
        console.log("=== DEBT SOCIALIZATION CONDITIONS ===");
        console.log("");
        
        console.log("For debt socialization to occur, ALL of these must be true:");
        console.log("");
        console.log("1. liabilityValue >= MIN_SOCIALIZATION_LIABILITY_VALUE (1e6)");
        console.log("   - In unit of account (usually USD)");
        console.log("   - 1e6 with 18 decimals = $0.000000000001");
        console.log("   - Essentially ANY debt qualifies!");
        console.log("");
        console.log("2. CFG_DONT_SOCIALIZE_DEBT flag NOT set");
        console.log("   - This is a per-vault configuration");
        console.log("   - Most vaults have socialization enabled");
        console.log("");
        console.log("3. liability > repay (remaining debt after liquidation)");
        console.log("   - Only the unpaid portion gets socialized");
        console.log("   - If liquidator pays all debt, no socialization");
        console.log("");
        console.log("4. violator has NO remaining collateral");
        console.log("   - checkNoCollateral() must return true");
        console.log("   - All recognized collaterals must have 0 balance");
        console.log("");
        console.log("ATTACK VECTOR:");
        console.log("- Create position with worthless/depreciating collateral");
        console.log("- Let collateral value drop to zero");
        console.log("- Debt gets socialized to all depositors");
        console.log("- Repeat to drain vault");
    }
    
    /*//////////////////////////////////////////////////////////////
                    TEST: SHARE PRICE IMPACT CALCULATION
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Calculate theoretical impact of debt socialization on share price
     */
    function test_SharePriceImpact() public view {
        console.log("=== SHARE PRICE IMPACT FROM DEBT SOCIALIZATION ===");
        console.log("");
        
        // Example calculation:
        // Vault has 1M assets, 1M shares (1:1 ratio)
        // $10,000 debt gets socialized
        // New ratio: 990,000 assets / 1,000,000 shares = 0.99
        // 1% loss for all depositors
        
        uint256 exampleAssets = 1_000_000e18;
        uint256 exampleShares = 1_000_000e18;
        uint256 socializedDebt = 10_000e18;
        
        uint256 newAssets = exampleAssets - socializedDebt;
        uint256 sharePrice = (newAssets * 1e18) / exampleShares;
        
        console.log("Example Scenario:");
        console.log("  Initial Assets: 1,000,000");
        console.log("  Initial Shares: 1,000,000");
        console.log("  Initial Share Price: 1.0");
        console.log("");
        console.log("After $10,000 debt socialization:");
        console.log("  New Assets: 990,000");
        console.log("  Share Price:", sharePrice);
        console.log("  Loss: 1%");
        console.log("");
        console.log("CRITICAL: Repeated socialization compounds losses!");
        console.log("10 rounds of $10k = ~10% loss for depositors");
    }
}
