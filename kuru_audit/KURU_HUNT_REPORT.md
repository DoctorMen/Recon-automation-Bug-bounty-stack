# KURU DEX NEURAL-ENHANCED VULNERABILITY ASSESSMENT
## Target: Kuru Labs Bug Bounty | Max Reward: $50,000

**Assessment Date:** 2025-12-02  
**Neural Brain Status:** ACTIVE  
**Authorization:** CONFIRMED via Cantina  

---

## EXECUTIVE SUMMARY

Kuru is a CLOB-AMM hybrid DEX on Monad with complex interactions between:
- **OrderBook** - Central limit order book with flip orders
- **KuruAMMVault** - Automated market maker with virtual rebalancing
- **MarginAccount** - Cross-market balance management
- **Router** - Multi-hop swap orchestration

---

## HIGH-PRIORITY ATTACK VECTORS (Neural Score: 0.85+)

### 1. SHARE INFLATION ATTACK (KuruAMMVault) ⚡ CRITICAL POTENTIAL

**Target Function:** `deposit()` / First deposit mechanism

**Vulnerability Pattern:**
```solidity
// First deposit: Shares = sqrt(baseDeposit * quoteDeposit) - MIN_LIQUIDITY
// Subsequent: Proportional to virtually rebalanced reserves
```

**Attack Hypothesis:**
- First depositor can manipulate initial share price
- If MIN_LIQUIDITY is small, attacker can:
  1. Deposit minimal amounts to get first shares
  2. Donate tokens directly to vault (not through deposit)
  3. Subsequent depositors get fewer shares per token
  
**Investigation Steps:**
1. Check MIN_LIQUIDITY value in Vault.sol
2. Test if direct token transfers affect share calculations
3. Verify rounding behavior in `previewDeposit()`

**Estimated Severity:** CRITICAL ($50,000)

---

### 2. VIRTUAL REBALANCING MANIPULATION ⚡ HIGH POTENTIAL

**Target Mechanism:**
```
x_rebalanced = (x'*p + y') / 2p
y_rebalanced = (x'*p + y') / 2
```

**Vulnerability Pattern:**
- Price `p` is used in rebalancing calculations
- If attacker can manipulate `p` before deposit/withdrawal:
  - Front-run with large trade to move price
  - Deposit when rebalanced values favor attacker
  - Back-run to restore price

**Attack Hypothesis:**
- Sandwich attack on vault operations
- Flash loan to manipulate vault price temporarily
- Extract value during rebalancing window

**Investigation Steps:**
1. Check if `totalAssets()` uses spot price or TWAP
2. Verify timing of price updates vs rebalancing
3. Test with flash loan simulation

**Estimated Severity:** HIGH ($25,000)

---

### 3. MULTI-HOP SWAP REENTRANCY (Router) ⚡ HIGH POTENTIAL

**Target Function:** `anyToAnySwap()`

**Vulnerability Pattern:**
```solidity
function anyToAnySwap(
    address[] calldata _marketAddresses,
    bool[] calldata _isBuy,
    bool[] calldata _nativeSend,
    address _debitToken,
    address _creditToken,
    uint256 _amount,
    uint256 _minAmountOut
) external payable returns (uint256 _amountOut)
```

**Attack Hypothesis:**
- Complex array handling across multiple markets
- Native token handling (`_nativeSend`) mixed with ERC20
- Potential for:
  - Reentrancy between hops
  - Array length mismatches
  - Native/ERC20 confusion

**Investigation Steps:**
1. Check CEI pattern in swap execution
2. Verify array length validation
3. Test with malicious token callbacks
4. Verify `_minAmountOut` checked at correct point

**Estimated Severity:** HIGH ($25,000)

---

### 4. MARGINACCOUNT ACCESS CONTROL ⚡ MEDIUM-HIGH

**Target Functions:**
```solidity
function creditUser(address _user, address _token, uint256 _amount, bool _useMargin) external
function debitUser(address _user, address _token, uint256 _amount) external
function creditUsersEncoded(bytes calldata _encodedData) external
```

**Vulnerability Pattern:**
- Who can call `creditUser`/`debitUser`?
- `creditUsersEncoded` parses raw bytes - potential for:
  - Malformed data handling
  - Integer overflow in decoding
  - Unauthorized credit creation

**Investigation Steps:**
1. Verify caller restrictions (onlyMarket modifier?)
2. Test encoded data edge cases
3. Check for credit without corresponding debit

**Estimated Severity:** MEDIUM-HIGH ($10,000-$25,000)

---

### 5. FLIP ORDER EDGE CASES (OrderBook) ⚡ MEDIUM

**Target Functions:**
```solidity
function addFlipBuyOrder(uint32 _price, uint32 _flippedPrice, uint96 _size, bool _provisionOrRevert) external
function addFlipSellOrder(uint32 _price, uint32 _flippedPrice, uint96 _size, bool _provisionOrRevert) external
```

**Out-of-Scope Note:** "Market DOS by bypassing minimum order size through flip orders" - KNOWN

**Alternative Attack Vectors:**
- Flip order + partial fill interactions
- Flipped price manipulation
- State corruption between flip and original order

**Investigation Steps:**
1. Check `_flippedPrice` validation vs market bounds
2. Test flip order cancellation edge cases
3. Verify partial fill handling for flipped orders

**Estimated Severity:** MEDIUM ($5,000-$10,000)

---

### 6. PRECISION/ROUNDING ATTACKS ⚡ MEDIUM

**Target Areas:**
- `sizePrecision` and `pricePrecision` in OrderBook
- Fixed-point math in share calculations
- Fee calculations (`takerFeeBps`, `makerFeeBps`)

**Vulnerability Pattern:**
- Dust amounts that round to zero fees
- Precision loss in multi-hop swaps
- Share calculation rounding manipulation

**Investigation Steps:**
1. Test minimum viable trade sizes
2. Check fee rounding direction
3. Verify precision consistency across contracts

**Estimated Severity:** MEDIUM ($5,000)

---

## KNOWN ISSUES (OUT OF SCOPE)

Per bug bounty rules, these are NOT eligible:
1. ❌ Vault DOS with low liquidity
2. ❌ Issues from badly set market parameters
3. ❌ Market DOS via flip order minimum bypass
4. ❌ Price oracle issues in KuruForwarder

---

## RECOMMENDED TESTING SEQUENCE

1. **Vault Share Inflation** - Highest impact potential
2. **Virtual Rebalancing Sandwich** - Complex but high reward
3. **Multi-hop Reentrancy** - Classic DeFi vulnerability
4. **MarginAccount Access** - Less complex, medium reward
5. **Flip Order Edges** - Novel mechanism worth exploring

---

## NEXT STEPS

1. [ ] Obtain Vault.sol and LiquidityShares.sol source code
2. [ ] Set up local Foundry test environment
3. [ ] Create PoC for share inflation attack
4. [ ] Test sandwich attack on virtual rebalancing
5. [ ] Fuzz anyToAnySwap with edge cases

---

## NEURAL BRAIN INSIGHTS

**High-Value Features Detected:**
- `admin_in_name`: 0.850 (owner functions)
- `upload_in_name`: 0.850 (deposit/withdraw)
- `graphql_in_name`: 0.800 (encoded data parsing)
- `similar_to_success`: 0.850 (ERC4626-like patterns)

**Learning Notes:**
- DeFi vault share manipulation is historically high-payout
- Monad is new chain - implementation bugs more likely
- CLOB-AMM hybrid is novel - edge cases between systems

---

*Report generated by Neural-Enhanced Bug Hunter | Authorization: Kuru Labs Bug Bounty via Cantina*
