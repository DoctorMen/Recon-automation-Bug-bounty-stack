# Euler V2 - Deep Attack Vector Analysis

## EVC (Ethereum Vault Connector) - Core Primitive

### 1. Account ID System Attacks
**The 256 sub-accounts per address (XOR with 0-255)**

```solidity
// Each address has 256 accounts via XOR
function haveCommonOwnerInternal(address account, address otherAccount) internal pure returns (bool result) {
    assembly {
        result := lt(xor(account, otherAccount), 0x100)
    }
}
```

**Attack Vectors:**
- Can we create confusion between sub-accounts?
- Can operator authorization leak between accounts?
- Is there address collision risk with 8-bit reduction?

### 2. Operator Bitfield Manipulation
**Operators use a 256-bit field for authorization**

```solidity
uint256 bitMask = 1 << (uint160(owner) ^ uint160(account));
uint256 newOperatorBitField = authorized ? oldOperatorBitField | bitMask : oldOperatorBitField & ~bitMask;
```

**Attack Vectors:**
- Can bitMask overflow/wrap?
- Can we authorize for unintended accounts?
- What happens at boundary conditions?

### 3. Controller Isolation Bypass
**Only one controller allowed per account**

```solidity
if (numOfControllers != 1) {
    revert EVC_ControllerViolation();
}
```

**Attack Vectors:**
- Race condition to enable multiple controllers?
- Can batch execution bypass this?
- What about during deferred checks?

### 4. Deferred Checks Exploitation
**Checks are deferred during batch/call operations**

```solidity
if (executionContext.areChecksDeferred()) {
    accountStatusChecks.insert(account);
} else {
    requireAccountStatusCheckInternalNonReentrantChecks(account);
}
```

**Attack Vectors:**
- Can we escape the check restoration?
- Reentrancy during deferred state?
- What if restoreExecutionContext fails?

### 5. Permit Signature Attacks
**EIP-712 permit with nonces**

```solidity
if (currentNonce == type(uint256).max || currentNonce != nonce) {
    revert EVC_InvalidNonce();
}
```

**Attack Vectors:**
- Nonce overflow at type(uint256).max?
- Signature replay across chains?
- Can permitDisabledMode be bypassed?

### 6. controlCollateral Reentrancy
**Controller can call arbitrary contracts**

```solidity
function controlCollateral(
    address targetCollateral,
    address onBehalfOfAccount,
    uint256 value,
    bytes calldata data
) ... onlyController(onBehalfOfAccount) {
    if (!accountCollaterals[onBehalfOfAccount].contains(targetCollateral)) {
        revert EVC_NotAuthorized();
    }
    // Calls targetCollateral with arbitrary data
}
```

**Attack Vectors:**
- Malicious collateral contract callback?
- Reentrancy to modify state during call?
- Can we remove collateral during call?

---

## EVK (Euler Vault Kit) - Credit Vaults

### 7. Share Inflation (First Depositor Attack)
**Already tested on Kuru - need to verify for EVK**

Check:
- MIN_SHARES / dead shares mechanism
- First deposit calculations
- Donation attack vectors

### 8. Liquidation Logic
**Bad debt socialization and liquidation flow**

Attack Vectors:
- Can we create unliquidatable positions?
- Bad debt distribution bugs?
- Liquidation bonus manipulation?
- Partial liquidation edge cases?

### 9. Interest Rate Manipulation
**IRMLinearKink model**

Attack Vectors:
- Can we manipulate utilization ratio?
- Interest rate jumps at kink points?
- Overflow in rate calculations?

### 10. Cross-Vault Collateral Attacks
**Vaults can use other vaults as collateral**

Attack Vectors:
- Circular collateral dependencies?
- Price manipulation across vaults?
- Collateral chain liquidation cascades?

---

## Price Oracle Attacks

### 11. Oracle Adapter Inconsistencies
**Multiple oracle sources: Chainlink, Chronicle, Pyth, RedStone**

Attack Vectors:
- Decimal handling between adapters?
- Stale price windows?
- Price deviation between sources?
- EulerRouter fallback logic bugs?

### 12. ERC4626 Share Pricing
**convertToAssets manipulation**

Attack Vectors:
- Donation attacks on underlying vaults?
- Share price manipulation?
- Rounding in conversion?

---

## EulerSwap - AMM with JIT Liquidity

### 13. JIT Liquidity Abuse
**Just-in-time borrowing for swaps**

Attack Vectors:
- Borrow without proper repayment?
- Flash loan + JIT combination?
- Interest accrual manipulation?

### 14. Hook Interaction Bugs
**Uniswap v4 hook compatibility**

Attack Vectors:
- Malicious hook callbacks?
- State manipulation via hooks?
- Reentrancy through hooks?

---

## USL Vaults (BOOSTED $7.5M!)

### 15. USD0/USD0++ Specific Attacks
**Usual protocol integration**

Attack Vectors:
- Depeg scenario handling?
- USD0++ redemption edge cases?
- Cross-protocol state inconsistencies?
- Usual protocol specific bugs?

---

## Priority Order for Investigation

1. **USL Vaults** - $7.5M potential, Usual integration risks
2. **EVC Controller/Operator** - Core primitive, $5M potential
3. **Liquidation Logic** - Common DeFi bug class
4. **Cross-Vault Collateral** - Complex interactions
5. **Oracle Adapters** - Price manipulation vectors
6. **EulerSwap JIT** - Novel mechanism, less audited

---

## Testing Approach

```bash
# Fork test setup
forge test --fork-url https://eth.llamarpc.com --match-contract EulerTest -vvvv

# Fuzz critical functions
forge test --match-test testFuzz_ --fuzz-runs 10000

# Static analysis
slither euler-vault-kit/src/ --exclude-dependencies
```

---

## Previous Audits to Review

- Check euler-vault-kit/audits/ for known issues
- Look for "acknowledged" issues that may still be exploitable
- Cross-reference with DeFi exploit database
