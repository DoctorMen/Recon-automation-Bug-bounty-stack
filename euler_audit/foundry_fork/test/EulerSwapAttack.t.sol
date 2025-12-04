// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

/**
 * @title EulerSwapAttack
 * @notice UNFAIR ADVANTAGE: Novel attack vectors in EulerSwap JIT mechanism
 * 
 * KEY FINDINGS:
 * 1. Reentrancy guard UNLOCKED during afterSwap hook (SwapLib.sol:101)
 * 2. JIT borrows from EVK vaults - interest rate manipulation possible
 * 3. Hook can reconfigure() during swap
 * 4. Share price manipulation in underlying vaults
 */

interface IEulerSwap {
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
    function getReserves() external view returns (uint112, uint112, uint32);
    function computeQuote(address tokenIn, address tokenOut, uint256 amount, bool exactIn) external view returns (uint256);
    function getLimits(address tokenIn, address tokenOut) external view returns (uint256 inLimit, uint256 outLimit);
    function getAssets() external view returns (address asset0, address asset1);
    function isInstalled() external view returns (bool);
}

interface IEulerSwapRegistry {
    function pools(bytes32 id) external view returns (address);
    function getPoolId(address asset0, address asset1, address supplyVault0, address supplyVault1, address eulerAccount, address feeRecipient) external pure returns (bytes32);
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function symbol() external view returns (string memory);
}

contract EulerSwapAttack is Test {
    // Known EulerSwap addresses
    address constant EULER_SWAP = 0xb013be1D0D380C13B58e889f412895970A2Cf228;
    address constant EULER_SWAP_REGISTRY = 0x8bd9E83A851a4f64d15A18d2b88aa4FDcafDb77d;
    
    function setUp() public {}
    
    /*//////////////////////////////////////////////////////////////
                    ATTACK 1: REENTRANCY DURING HOOK
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice The afterSwap hook runs with reentrancy UNLOCKED
     * 
     * From SwapLib.sol:101:
     *   s.status = 1; // Unlock the reentrancy guard during afterSwap
     * 
     * This allows:
     * 1. Hook can call swap() again (re-entrant swap)
     * 2. Hook can call reconfigure() to change parameters
     * 3. Both simultaneously!
     */
    function test_ReentrancyDuringHook() public pure {
        console.log("=== REENTRANCY DURING AFTERSWAP HOOK ===");
        console.log("");
        
        console.log("VULNERABILITY:");
        console.log("  SwapLib.sol line 101:");
        console.log("  s.status = 1; // Unlock reentrancy during afterSwap");
        console.log("");
        
        console.log("ATTACK SCENARIO:");
        console.log("  1. Malicious pool owner sets custom swapHook");
        console.log("  2. User swaps on the pool");
        console.log("  3. After curve verification, reserves updated");
        console.log("  4. afterSwap hook called (status = 1 = UNLOCKED)");
        console.log("  5. Hook can:");
        console.log("     a) Call swap() again (reentrancy)");
        console.log("     b) Call reconfigure() to change params");
        console.log("     c) Manipulate state for next swap");
        console.log("");
        
        console.log("SEVERITY ASSESSMENT:");
        console.log("  - Pool owner controls the hook");
        console.log("  - Users who swap on malicious pools at risk");
        console.log("  - Not a bug IF users are warned about custom hooks");
        console.log("  - MEDIUM if users can't detect malicious hooks");
    }
    
    /*//////////////////////////////////////////////////////////////
                    ATTACK 2: JIT INTEREST RATE MANIPULATION
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice EulerSwap borrows from EVK vaults for JIT liquidity
     * 
     * From FundsLib.sol:61-64:
     *   if (amount > 0) {
     *       IEVC(evc).enableController(eulerAccount, borrowVault);
     *       IEVC(evc).call(borrowVault, eulerAccount, 0, 
     *           abi.encodeCall(IBorrowing.borrow, (amount, to)));
     *   }
     * 
     * Attack: Manipulate borrow vault's interest rate before swap
     */
    function test_JITInterestRateManipulation() public pure {
        console.log("=== JIT INTEREST RATE MANIPULATION ===");
        console.log("");
        
        console.log("HOW JIT WORKS:");
        console.log("  1. Swap needs liquidity");
        console.log("  2. First withdraws from supplyVault");
        console.log("  3. If not enough, BORROWS from borrowVault");
        console.log("  4. On return, repays debt then deposits");
        console.log("");
        
        console.log("ATTACK VECTOR:");
        console.log("  1. Monitor mempool for large EulerSwap trades");
        console.log("  2. Front-run: Borrow heavily from borrowVault");
        console.log("  3. This spikes interest rate / utilization");
        console.log("  4. Victim's swap either:");
        console.log("     a) Fails (insufficient collateral)");
        console.log("     b) Pays higher interest");
        console.log("  5. Back-run: Repay and profit from rate spike");
        console.log("");
        
        console.log("IMPACT:");
        console.log("  - DoS on EulerSwap pools");
        console.log("  - Higher costs for swappers");
        console.log("  - MEV extraction opportunity");
    }
    
    /*//////////////////////////////////////////////////////////////
                    ATTACK 3: SHARE PRICE MANIPULATION
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice convertToAssets used without protection
     * 
     * From FundsLib.sol:51-52:
     *   uint256 shares = IEVault(supplyVault).balanceOf(eulerAccount);
     *   balance = shares == 0 ? 0 : IEVault(supplyVault).convertToAssets(shares);
     */
    function test_SharePriceManipulation() public pure {
        console.log("=== SHARE PRICE MANIPULATION ===");
        console.log("");
        
        console.log("OBSERVATION:");
        console.log("  FundsLib uses convertToAssets() directly");
        console.log("  This reads current share price from vault");
        console.log("");
        
        console.log("ATTACK VECTOR:");
        console.log("  1. Donate to supplyVault (inflate share price)");
        console.log("  2. EulerSwap thinks it has more assets");
        console.log("  3. Swap based on inflated balance");
        console.log("  4. Extract value via price discrepancy");
        console.log("");
        
        console.log("MITIGATION CHECK:");
        console.log("  - EVK has VIRTUAL_DEPOSIT protection");
        console.log("  - May still be exploitable at scale");
    }
    
    /*//////////////////////////////////////////////////////////////
                    ATTACK 4: HOOK AUTHORIZATION BYPASS
    //////////////////////////////////////////////////////////////*/
    
    /**
     * @notice SwapHook itself can reconfigure the pool
     * 
     * From EulerSwapManagement.sol:160:
     *   sender == sParams.eulerAccount || 
     *   s.managers[sender] || 
     *   sender == oldDParams.swapHook  // <-- Hook can reconfigure!
     */
    function test_HookAuthorizationAnalysis() public pure {
        console.log("=== HOOK AUTHORIZATION ANALYSIS ===");
        console.log("");
        
        console.log("FINDING:");
        console.log("  The swapHook itself has reconfigure() permission!");
        console.log("  EulerSwapManagement.sol line 160:");
        console.log("  sender == oldDParams.swapHook");
        console.log("");
        
        console.log("IMPLICATION:");
        console.log("  During afterSwap (reentrancy unlocked):");
        console.log("  1. Hook can reconfigure fees");
        console.log("  2. Hook can change its own address");
        console.log("  3. Hook can modify curve parameters");
        console.log("  4. All AFTER curve verification passed!");
        console.log("");
        
        console.log("SEVERITY:");
        console.log("  - Intentional design for flexibility");
        console.log("  - But users may not realize hook power");
        console.log("  - Need clear documentation/warnings");
    }
    
    /*//////////////////////////////////////////////////////////////
                    ATTACK 5: CURVE PARAMETER RACE
    //////////////////////////////////////////////////////////////*/
    
    function test_CurveParameterRace() public pure {
        console.log("=== CURVE PARAMETER RACE CONDITION ===");
        console.log("");
        
        console.log("POTENTIAL ATTACK:");
        console.log("  1. User submits swap transaction");
        console.log("  2. Pool manager sees it in mempool");
        console.log("  3. Manager front-runs with reconfigure()");
        console.log("  4. Changes curve params (fees, limits)");
        console.log("  5. User's swap executes with worse params");
        console.log("");
        
        console.log("MITIGATION:");
        console.log("  - User should set slippage protection");
        console.log("  - computeQuote() returns expected amount");
        console.log("  - But params can change between quote and swap");
    }
    
    /*//////////////////////////////////////////////////////////////
                    SUMMARY: UNFAIR ADVANTAGE FINDINGS
    //////////////////////////////////////////////////////////////*/
    
    function test_UnfairAdvantageSummary() public pure {
        console.log("=== UNFAIR ADVANTAGE SUMMARY ===");
        console.log("");
        
        console.log("NOVEL ATTACK SURFACES IDENTIFIED:");
        console.log("");
        
        console.log("1. REENTRANCY DURING HOOK (SwapLib.sol:101)");
        console.log("   Status: Intentional but risky");
        console.log("   Bounty: MEDIUM if user protection missing");
        console.log("");
        
        console.log("2. JIT BORROW RATE MANIPULATION");
        console.log("   Status: Economic attack");
        console.log("   Bounty: MEDIUM-HIGH if profitable");
        console.log("");
        
        console.log("3. HOOK HAS RECONFIGURE POWER");
        console.log("   Status: By design");
        console.log("   Bounty: LOW unless user warning missing");
        console.log("");
        
        console.log("4. CROSS-PROTOCOL INTERACTION");
        console.log("   Status: EulerSwap + EVK interaction");
        console.log("   Bounty: HIGH if state inconsistency found");
        console.log("");
        
        console.log("RECOMMENDED NEXT STEPS:");
        console.log("  1. Build PoC for JIT rate manipulation");
        console.log("  2. Test reentrancy with custom hook");
        console.log("  3. Check live pools for vulnerable configs");
        console.log("  4. Review hook audit coverage");
    }
}
