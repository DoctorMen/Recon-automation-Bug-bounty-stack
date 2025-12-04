// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

/**
 * @title EulerAdvancedTest
 * @notice Advanced tests for cross-contract interactions and edge cases
 * @dev Focus: Liquidation, debt socialization, oracle manipulation vectors
 */

interface IEVC {
    function batch(BatchItem[] calldata items) external payable;
    function call(address targetContract, address onBehalfOfAccount, uint256 value, bytes calldata data) external payable returns (bytes memory);
    function enableCollateral(address account, address vault) external payable;
    function enableController(address account, address vault) external payable;
    function disableController(address account) external payable;
    function getControllers(address account) external view returns (address[] memory);
    function getCollaterals(address account) external view returns (address[] memory);
    function controlCollateral(address targetCollateral, address onBehalfOfAccount, uint256 value, bytes calldata data) external payable returns (bytes memory);
    function forgiveAccountStatusCheck(address account) external payable;
    function requireAccountStatusCheck(address account) external payable;
    function isAccountStatusCheckDeferred(address account) external view returns (bool);
    function getLastAccountStatusCheckTimestamp(address account) external view returns (uint256);
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
    function LTV(address collateral) external view returns (uint16 borrowLTV, uint16 liquidationLTV, uint16 initialLiquidationLTV, uint48 targetTimestamp, uint32 rampDuration);
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

contract EulerAdvancedTest is Test {
    // Ethereum Mainnet addresses
    address constant EVC = 0x0C9a3dd6b8F28529d72d7f9cE918D493519EE383;
    
    // Perspectives
    address constant GOVERNED_PERSPECTIVE = 0xC0121817FF224a018840e4D15a864747d36e6Eb2;
    address constant EULER_EARN_PERSPECTIVE = 0x492e9FE1289d43F8bB6275237BF16c9248C74D44;
    
    // USL Vaults - BOOSTED ($7.5M!)
    address constant USD0PP_VAULT = 0xF037eeEBA7729c39114B9711c75FbccCa4A343C8;
    address constant USD0_VAULT = 0xd001f0a15D272542687b2677BA627f48A4333b5d;
    
    // Common tokens
    address constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    address constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;
    
    IEVC public evc;
    
    address public attacker;
    address public victim;
    
    function setUp() public {
        attacker = makeAddr("attacker");
        victim = makeAddr("victim");
        
        vm.deal(attacker, 100 ether);
        vm.deal(victim, 100 ether);
        
        evc = IEVC(EVC);
    }
    
    /*//////////////////////////////////////////////////////////////
                    TEST: VAULT ENUMERATION
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Enumerate all verified vaults from perspectives
     * @dev Important: Only vaults from verifiedArray() are in scope
     */
    function test_EnumerateVerifiedVaults() public view {
        console.log("=== ENUMERATING VERIFIED VAULTS ===");
        console.log("");
        
        // Query Governed Perspective
        try IPerspective(GOVERNED_PERSPECTIVE).verifiedArray() returns (address[] memory vaults) {
            console.log("Governed Perspective vaults:", vaults.length);
            for (uint i = 0; i < vaults.length && i < 10; i++) {
                console.log("  Vault", i, ":", vaults[i]);
            }
            if (vaults.length > 10) {
                console.log("  ... and", vaults.length - 10, "more");
            }
        } catch {
            console.log("Could not query Governed Perspective");
        }
        
        console.log("");
        
        // Query Euler Earn Perspective
        try IPerspective(EULER_EARN_PERSPECTIVE).verifiedArray() returns (address[] memory vaults) {
            console.log("Euler Earn Perspective vaults:", vaults.length);
            for (uint i = 0; i < vaults.length && i < 5; i++) {
                console.log("  Vault", i, ":", vaults[i]);
            }
        } catch {
            console.log("Could not query Euler Earn Perspective");
        }
    }
    
    /*//////////////////////////////////////////////////////////////
                    TEST: LIQUIDATION MECHANICS
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Test liquidation check on USL vaults
     */
    function test_USL_LiquidationCheck() public view {
        console.log("=== USL VAULT LIQUIDATION CHECK ===");
        console.log("");
        
        IEVault usd0ppVault = IEVault(USD0PP_VAULT);
        
        // Check if we can query liquidation status
        // This helps understand the liquidation mechanics
        try usd0ppVault.checkLiquidation(attacker, victim, USD0PP_VAULT) returns (uint256 maxRepay, uint256 maxYield) {
            console.log("USD0++ Vault - Liquidation check for victim:");
            console.log("  Max repay:", maxRepay);
            console.log("  Max yield:", maxYield);
        } catch {
            console.log("Victim has no liquidatable position (expected)");
        }
        
        // Check total borrows
        try usd0ppVault.totalBorrows() returns (uint256 borrows) {
            console.log("Total borrows:", borrows);
        } catch {}
        
        // Check cash
        try usd0ppVault.cash() returns (uint256 vaultCash) {
            console.log("Vault cash:", vaultCash);
        } catch {}
    }
    
    /*//////////////////////////////////////////////////////////////
                    TEST: DEBT SOCIALIZATION EDGE CASES
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Analyze debt socialization parameters
     * @dev Debt socialization happens when:
     *   1. liabilityValue >= MIN_SOCIALIZATION_LIABILITY_VALUE (1e6)
     *   2. CFG_DONT_SOCIALIZE_DEBT flag is NOT set
     *   3. liability > repay (remaining debt after liquidation)
     *   4. violator has no remaining collateral
     */
    function test_DebtSocializationAnalysis() public view {
        console.log("=== DEBT SOCIALIZATION ANALYSIS ===");
        console.log("");
        
        // MIN_SOCIALIZATION_LIABILITY_VALUE = 1e6
        // This is very small - only $1 worth of debt in USDC terms
        // Could there be precision attacks?
        
        console.log("MIN_SOCIALIZATION_LIABILITY_VALUE: 1e6 (1 USDC)");
        console.log("");
        
        IEVault usd0ppVault = IEVault(USD0PP_VAULT);
        
        // Check vault state
        uint256 totalAssets = usd0ppVault.totalAssets();
        uint256 totalSupply = usd0ppVault.totalSupply();
        uint256 totalBorrows;
        
        try usd0ppVault.totalBorrows() returns (uint256 b) {
            totalBorrows = b;
        } catch {}
        
        console.log("USD0++ Vault State:");
        console.log("  Total assets:", totalAssets);
        console.log("  Total supply:", totalSupply);
        console.log("  Total borrows:", totalBorrows);
        
        if (totalSupply > 0 && totalBorrows > 0) {
            // If there's bad debt, it would affect the share price
            uint256 effectiveAssets = totalAssets > totalBorrows ? totalAssets - totalBorrows : 0;
            console.log("  Effective assets (after debt):", effectiveAssets);
        }
    }
    
    /*//////////////////////////////////////////////////////////////
                    TEST: ORACLE PRICE MANIPULATION VECTORS
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Test for oracle price manipulation vectors
     * @dev The oracle uses bid/ask spread for health checks
     */
    function test_OraclePriceAnalysis() public view {
        console.log("=== ORACLE PRICE ANALYSIS ===");
        console.log("");
        
        // The Euler oracle system uses:
        // - Mid-point prices for liquidation thresholds
        // - Bid/ask prices for account status checks
        
        // This design prevents:
        // - Sandwich attacks around liquidation thresholds
        // - MEV exploitation of small price movements
        
        console.log("Oracle price types:");
        console.log("  - Mid-point: Used for liquidation");
        console.log("  - Bid/Ask: Used for account health");
        console.log("");
        console.log("Attack vectors to consider:");
        console.log("  1. Flash loan + large trade to move mid-point");
        console.log("  2. Multi-block manipulation");
        console.log("  3. Stale price exploitation");
    }
    
    /*//////////////////////////////////////////////////////////////
                    TEST: CROSS-VAULT COLLATERAL CHAINS
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Analyze cross-vault collateral relationships
     * @dev One vault can use another vault's shares as collateral
     */
    function test_CrossVaultCollateral() public view {
        console.log("=== CROSS-VAULT COLLATERAL ANALYSIS ===");
        console.log("");
        
        IEVault usd0ppVault = IEVault(USD0PP_VAULT);
        IEVault usd0Vault = IEVault(USD0_VAULT);
        
        // Check if vault shares can be used as collateral
        // This creates potential circular dependencies
        
        address usd0ppAsset = usd0ppVault.asset();
        address usd0Asset = usd0Vault.asset();
        
        console.log("USD0++ vault underlying:", usd0ppAsset);
        console.log("USD0 vault underlying:", usd0Asset);
        
        // Check LTV settings if available
        try usd0ppVault.LTV(usd0Asset) returns (uint16 borrowLTV, uint16 liquidationLTV, uint16 initialLTV, uint48 target, uint32 ramp) {
            console.log("");
            console.log("USD0++ can use USD0 as collateral:");
            console.log("  Borrow LTV:", borrowLTV);
            console.log("  Liquidation LTV:", liquidationLTV);
        } catch {
            console.log("No LTV config for USD0 in USD0++ vault");
        }
    }
    
    /*//////////////////////////////////////////////////////////////
                    TEST: LIQUIDATION COOL-OFF TIMING
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Test liquidation cool-off timing mechanism
     * @dev A cool-off time must elapse after successful status check
     */
    function test_LiquidationCoolOff() public view {
        console.log("=== LIQUIDATION COOL-OFF TIMING ===");
        console.log("");
        
        // The cool-off prevents self-liquidation attacks where:
        // 1. Attacker creates position just below liquidation threshold
        // 2. Attacker triggers price movement
        // 3. Attacker liquidates themselves for profit
        
        // Check last status check timestamp for various accounts
        uint256 attackerTimestamp = evc.getLastAccountStatusCheckTimestamp(attacker);
        uint256 victimTimestamp = evc.getLastAccountStatusCheckTimestamp(victim);
        
        console.log("Last account status check timestamps:");
        console.log("  Attacker:", attackerTimestamp);
        console.log("  Victim:", victimTimestamp);
        console.log("  Current block:", block.timestamp);
        
        // The cool-off time is stored in vaultStorage.liquidationCoolOffTime
        // We can't read it directly but it's typically a few minutes
    }
    
    /*//////////////////////////////////////////////////////////////
                    TEST: EVC BATCH ATOMICITY
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Test EVC batch execution atomicity
     * @dev Batch operations defer status checks until the end
     */
    function test_BatchAtomicity() public {
        console.log("=== EVC BATCH ATOMICITY TEST ===");
        console.log("");
        
        vm.startPrank(attacker);
        
        // The key insight:
        // During batch execution, checks are DEFERRED
        // This allows temporarily unhealthy states
        // All checks run at the END of the batch
        
        // Potential attack vectors:
        // 1. Flash loan within batch
        // 2. Multiple vault interactions
        // 3. Collateral manipulation
        
        // Check if attacker's account has deferred checks
        bool isDeferred = evc.isAccountStatusCheckDeferred(attacker);
        console.log("Attacker checks deferred (before batch):", isDeferred);
        
        vm.stopPrank();
        
        console.log("");
        console.log("During batch execution:");
        console.log("  - Status checks are DEFERRED");
        console.log("  - Temporarily unhealthy states allowed");
        console.log("  - All checks run at END of batch");
        console.log("  - Reverts if ANY check fails");
    }
    
    /*//////////////////////////////////////////////////////////////
                    TEST: FLASH LOAN INTEGRATION
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice Analyze flash loan integration
     * @dev EVault supports flash loans via the flashLoan function
     */
    function test_FlashLoanAnalysis() public view {
        console.log("=== FLASH LOAN ANALYSIS ===");
        console.log("");
        
        // Flash loan pattern in EVault:
        // 1. Check original balance
        // 2. Transfer requested amount to borrower
        // 3. Call onFlashLoan callback
        // 4. Check balance >= original (must repay)
        
        // Potential vulnerabilities:
        // 1. Reentrancy during callback (mitigated by nonReentrant)
        // 2. Fee-on-transfer token issues
        // 3. Rebasing token issues
        
        IEVault usd0ppVault = IEVault(USD0PP_VAULT);
        uint256 vaultCash;
        
        try usd0ppVault.cash() returns (uint256 c) {
            vaultCash = c;
        } catch {}
        
        console.log("Flash loan available cash:", vaultCash);
        console.log("");
        console.log("Flash loan security:");
        console.log("  - nonReentrant modifier");
        console.log("  - Balance check after callback");
        console.log("  - No explicit fee (same balance required)");
    }
    
    /*//////////////////////////////////////////////////////////////
                    HELPER: FIND HIGH-VALUE VAULTS
    //////////////////////////////////////////////////////////////*/
    
    function test_HighValueVaults() public view {
        console.log("=== HIGH VALUE VAULT ANALYSIS ===");
        console.log("");
        
        // These are the USL vaults with boosted rewards
        IEVault usd0ppVault = IEVault(USD0PP_VAULT);
        IEVault usd0Vault = IEVault(USD0_VAULT);
        
        uint256 usd0ppAssets = usd0ppVault.totalAssets();
        uint256 usd0Assets = usd0Vault.totalAssets();
        
        console.log("USL Vault TVL (in underlying tokens):");
        console.log("  USD0++ Vault:", usd0ppAssets);
        console.log("  USD0 Vault:", usd0Assets);
        console.log("");
        
        // These vaults are the highest priority targets
        // Finding a bug here = $7.5M potential reward
        console.log("Finding bugs in these vaults = $7.5M potential!");
    }
}
