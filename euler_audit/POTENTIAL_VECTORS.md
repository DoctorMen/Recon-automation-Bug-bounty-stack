# Euler V2 - Potential Attack Vectors (Deep Analysis)

## Code Review Summary

After reviewing:
- EVC: 1235 lines (EthereumVaultConnector.sol)
- Liquidation: 252 lines
- Borrowing: 170 lines
- LiquidityUtils: 126 lines
- EVCClient: 145 lines

---

## HIGH PRIORITY VECTORS

### 1. Debt Socialization Manipulation

**Location:** `Liquidation.sol:220-234`

```solidity
if (
    liqCache.liabilityValue >= MIN_SOCIALIZATION_LIABILITY_VALUE  // Only 1e6!
    && vaultCache.configFlags.isNotSet(CFG_DONT_SOCIALIZE_DEBT)
    && liqCache.liability > liqCache.repay
    && checkNoCollateral(liqCache.violator, liqCache.collaterals)
) {
    // Debt is socialized (deleted without repayment)
}
```

**Potential Issue:**
- `MIN_SOCIALIZATION_LIABILITY_VALUE = 1e6` is very small (~$1 for USDC)
- If an attacker can create many small bad debt positions...
- Could they systematically drain vault value through socialization?

**Test Required:**
- Create position with liability just above 1e6
- Manipulate collateral to zero
- Trigger debt socialization
- Measure impact on share price

---

### 2. Liquidation Cool-Off Bypass

**Location:** `Liquidation.sol:241-245`

```solidity
function isInLiquidationCoolOff(address account) private view returns (bool) {
    unchecked {
        return block.timestamp < getLastAccountStatusCheckTimestamp(account) + vaultStorage.liquidationCoolOffTime;
    }
}
```

**Potential Issue:**
- Uses `unchecked` for timestamp arithmetic
- If `liquidationCoolOffTime` is very large, could it overflow?
- What if `getLastAccountStatusCheckTimestamp` returns 0 for fresh accounts?

**Test Required:**
- Check cooloff time configuration
- Test with fresh accounts (timestamp = 0)
- Test boundary conditions

---

### 3. EVC Batch + Deferred Checks

**Location:** EVC batch execution defers all status checks

**Potential Attack Flow:**
1. Start batch operation
2. Borrow maximum from vault A
3. Use borrowed funds as "collateral" elsewhere
4. Before batch ends, return funds
5. All checks pass at end

**Status:** EVC appears to handle this correctly by running all checks at batch end

---

### 4. Cross-Vault Collateral Chains

**Hypothesis:** If Vault A accepts Vault B shares as collateral, and Vault B accepts Vault A shares...

**Reality Check:** Our tests show NO cross-vault LTV configured for USL vaults

**Still Worth Exploring:** Check other 265 governed vaults for circular dependencies

---

### 5. Flash Loan + Liquidation Combo

**Location:** `Borrowing.sol:144-158` (flashLoan)

**Potential Attack:**
1. Flash loan from vault
2. Use funds to manipulate oracle price
3. Trigger liquidation at manipulated price
4. Profit from discount
5. Repay flash loan

**Mitigations Found:**
- Bid/ask spread for account health (vs mid-point for liquidation)
- Liquidation cool-off period
- nonReentrant modifier

---

### 6. Share Price Manipulation (First Depositor)

**Status:** Need to verify dead share mechanism in EVault

**Key Question:** Does EVK implement MIN_SHARES like Kuru's MIN_LIQUIDITY?

---

### 7. Oracle Adapter Inconsistencies

**Location:** euler-price-oracle repository

**Potential Issues:**
- Decimal handling across adapters (Chainlink, Pyth, etc.)
- Stale price windows
- Price deviation between sources

**Note:** Oracle issues are partially out of scope per bounty rules

---

## MEDIUM PRIORITY VECTORS

### 8. Rounding Errors in Share/Asset Conversion

**Locations:**
- `toSharesUp()` vs `toSharesDown()`
- `toAssetsUp()` vs `toAssetsDown()`

**Potential Issue:**
- Small precision losses could compound
- Dust accumulation could be extracted

---

### 9. Controller Isolation Edge Cases

**Location:** EVC only allows 1 controller per account

**Question:** Can race conditions allow briefly having 2 controllers?

---

### 10. Permit Nonce at MAX_UINT256

**Location:** `EthereumVaultConnector.sol:515`

```solidity
if (currentNonce == type(uint256).max || currentNonce != nonce) {
    revert EVC_InvalidNonce();
}
```

**Observation:** Nonce can never equal MAX_UINT256, but what happens when it reaches MAX-1?

---

## LOW PRIORITY / INFORMATIONAL

### 11. Gas Griefing via Many Collaterals

If an account has 100+ collaterals, liquidity checks become expensive

### 12. Event Emission Gaps

`DebtSocialized` event emitted, but accounting may confuse off-chain trackers

---

## NEXT STEPS

1. [ ] Deep dive into 265 governed vaults for circular collateral
2. [ ] Analyze Euler Earn aggregation logic
3. [ ] Review EulerSwap JIT mechanism
4. [ ] Fuzz share/asset conversion functions
5. [ ] Test debt socialization with small positions
6. [ ] Check for any acknowledged audit issues still present

---

## AUDIT REPORTS TO REVIEW

- Check `euler-vault-kit/audits/` for previous findings
- Cross-reference with "acknowledged" issues that may still exist
