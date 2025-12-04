# EulerSwap Potential Vulnerability Finding

## Summary

**Component:** EulerSwap JIT Liquidity Mechanism  
**Severity:** Medium  
**Category:** Reentrancy / State Manipulation  

---

## Finding 1: Reentrancy Guard Unlocked During afterSwap Hook

### Location
`SwapLib.sol:101`

```solidity
function invokeAfterSwapHook(SwapContext memory ctx, CtxLib.State storage s, uint256 fee0, uint256 fee1) internal {
    if ((ctx.dParams.swapHookedOperations & EULER_SWAP_HOOK_AFTER_SWAP) == 0) return;

    s.status = 1; // <-- UNLOCKED during hook call

    (bool success, bytes memory data) = ctx.dParams.swapHook.call(
        abi.encodeCall(IEulerSwapHookTarget.afterSwap, (...))
    );
    require(success, HookError(EULER_SWAP_HOOK_AFTER_SWAP, data));

    s.status = 2; // <-- Locked again after
}
```

### Issue

The reentrancy guard is intentionally unlocked (`status = 1`) during the `afterSwap` hook execution. This allows the hook to:

1. **Call `swap()` again** - Re-entrant swap execution
2. **Call `reconfigure()`** - Modify pool parameters mid-transaction
3. **Both simultaneously**

### Execution Flow

```
1. User calls swap()
2. Curve invariant verified ✓
3. Reserves updated ✓
4. afterSwap hook called (status = UNLOCKED)
   └─ Hook can: swap(), reconfigure(), manipulate state
5. Status locked again
```

### Impact

- **Malicious pool owners** can create pools that extract value from swappers
- **Users cannot easily detect** if a pool has a malicious hook
- **State can be manipulated** after curve verification passed

### Severity Assessment

- If this is **documented and expected**: Low/Informational
- If users have **no warning mechanism**: Medium
- If **funds can be extracted**: High

---

## Finding 2: JIT Borrow Rate Manipulation

### Mechanism

EulerSwap uses "Just-In-Time" liquidity from EVK vaults:

```solidity
// FundsLib.sol:61-64
if (amount > 0) {
    IEVC(evc).enableController(eulerAccount, borrowVault);
    IEVC(evc).call(borrowVault, eulerAccount, 0, 
        abi.encodeCall(IBorrowing.borrow, (amount, to)));
}
```

### Attack Vector

1. Monitor mempool for large EulerSwap trades
2. Front-run: Borrow heavily from the same `borrowVault`
3. This spikes utilization → higher interest rate
4. Victim's swap either:
   - **Fails** (insufficient collateral on eulerAccount)
   - **Pays more** (higher borrow cost)
5. Back-run: Repay and collect interest

### Impact

- DoS on EulerSwap pools
- MEV extraction opportunity
- Higher costs for legitimate swappers

---

## Finding 3: Hook Authorization Extends to Reconfigure

### Location
`EulerSwapManagement.sol:160`

```solidity
sender == sParams.eulerAccount || 
s.managers[sender] || 
sender == oldDParams.swapHook  // <-- Hook can reconfigure!
```

### Issue

The `swapHook` itself has permission to call `reconfigure()`. Combined with Finding 1 (reentrancy unlocked during hook), this means:

- Hook can change fees **after** user's swap is validated
- Hook can change curve parameters
- Hook can install a new hook

---

## Recommended Actions

### For Euler Team

1. **Add hook transparency** - Emit events when custom hooks are installed
2. **Consider limiting hook powers** - Restrict what hooks can do during afterSwap
3. **Document the risk** - Warn users about trading on pools with custom hooks

### For Bug Bounty

1. Build PoC demonstrating value extraction via malicious hook
2. Quantify potential user losses
3. Submit as Medium severity (Design issue with user risk)

---

## Files Analyzed

- `EulerSwap.sol` (164 lines)
- `SwapLib.sol` (235 lines)
- `FundsLib.sol` (113 lines)
- `CurveLib.sol` (174 lines)
- `EulerSwapManagement.sol`

## Test Coverage

Created: `euler_audit/foundry_fork/test/EulerSwapAttack.t.sol`
- 6 tests passing
- Documents all attack vectors

---

## Classification

| Aspect | Assessment |
|--------|------------|
| Exploitability | Medium (requires malicious pool) |
| Impact | Medium (user funds at risk) |
| Likelihood | Low (users must trade on bad pools) |
| Overall | **Medium** |

This may be **intentional design** for flexibility, but the user protection mechanisms should be verified.

---

## Audit Report Cross-Reference

### Tested in Codebase

The behavior IS tested in `EulerSwapHooks.t.sol`:

```solidity
// Line 373-381
function test_afterSwapReconfigure() public {
    setHook(EULER_SWAP_HOOK_AFTER_SWAP, 0, 0);
    as_reconfigure_fee0 = 0.077e18;
    
    doSwap(true, assetTST, assetTST2, 1e18, 0.9974e18);
    
    EulerSwap.DynamicParams memory p = eulerSwap.getDynamicParams();
    assertEq(p.fee0, 0.077e18);  // Hook successfully changed fee!
}
```

### Comment in Code (SwapLib.sol:101)

```solidity
s.status = 1; // Unlock the reentrancy guard during afterSwap, allowing hook to reconfigure()
```

### Conclusion

**Status: INTENTIONAL DESIGN - NOT A BUG**

The reentrancy unlocking during `afterSwap` is:
1. Documented in code comments
2. Tested in test suite
3. Required for hook flexibility

### Bounty Potential

| Scenario | Bounty |
|----------|--------|
| If documented/warned | INFORMATIONAL |
| If no UI warning | LOW-MEDIUM |
| If hook can steal funds | HIGH |

### Remaining Value

The JIT borrow rate manipulation attack remains unexplored and may have bounty potential as an economic attack that doesn't require a malicious pool owner.
