# Manual Code Review - Best Approach for Bug Bounty

## ✅ RECOMMENDED: Manual Code Review

**Why manual review is better:**
- ✅ No compilation issues
- ✅ You understand the code better
- ✅ Find context-specific vulnerabilities
- ✅ Create better proof of concepts
- ✅ More reliable for bug bounty submissions

---

## Quick Start: Verify Critical Findings

### Step 1: Open Contract Files
```bash
cd ~/Recon-automation-Bug-bounty-stack/blackhole_verification/Contracts/contracts

# Open Pair.sol (main target)
code Pair.sol
# or
vim Pair.sol
# or
cat Pair.sol | less
```

### Step 2: Search for Reentrancy Patterns

**Find swap functions:**
```bash
grep -n "function swap" Pair.sol
```

**Look for vulnerable pattern:**
```solidity
// VULNERABLE PATTERN:
function swap(...) external {
    // External call BEFORE state update
    IERC20(token).transfer(to, amount);  
    balances[msg.sender] -= amount;      
}

// SAFE PATTERN:
function swap(...) external nonReentrant {
    // State update BEFORE external call
    balances[msg.sender] -= amount;      
    IERC20(token).transfer(to, amount);  
}
```

### Step 3: Check for Flash Loan Attacks

**Search for price functions:**
```bash
grep -n "getPrice\|getAmount\|getRate" Pair.sol
```

**Look for:**
- Missing flash loan checks
- Price oracle manipulation
- MEV vulnerabilities

### Step 4: Check Access Control

**Search for admin functions:**
```bash
grep -n "function.*admin\|function.*onlyOwner\|function.*set" Pair.sol
```

**Look for:**
- Missing `require` statements
- Missing access modifiers
- Public functions that should be restricted

---

## Verification Checklist

### Finding 1: Reentrancy in Pair.sol

**Check these functions:**
```bash
cd ~/Recon-automation-Bug-bounty-stack/blackhole_verification/Contracts/contracts

# Find swap functions
grep -n "function.*swap" Pair.sol

# Check for external calls
grep -n "\.transfer\|\.call\|\.send" Pair.sol

# Check for reentrancy guards
grep -n "nonReentrant\|ReentrancyGuard" Pair.sol

# Check order of operations
# Look for: external call BEFORE state update = VULNERABLE
```

**What to document:**
- Line number of vulnerable function
- Code snippet showing vulnerability
- Explanation of exploit
- Impact assessment

### Finding 2: Flash Loan Attack

**Check these patterns:**
```bash
# Find price calculation functions
grep -n "getAmount\|getPrice\|calculate" Pair.sol

# Check for flash loan protection
grep -n "flash\|loan" Pair.sol
```

**What to document:**
- Price manipulation vector
- Missing flash loan checks
- Potential exploit

### Finding 3: Liquidity Pool Exploit

**Check GenesisPool.sol:**
```bash
# Check access control
grep -n "function\|modifier\|require" GenesisPool.sol

# Check for pool manipulation
grep -n "deposit\|withdraw\|balance" GenesisPool.sol
```

---

## Manual Verification Commands

```bash
cd ~/Recon-automation-Bug-bounty-stack/blackhole_verification/Contracts/contracts

# Find all external functions
grep -n "function.*external" Pair.sol

# Find all state-changing functions
grep -n "function.*public\|function.*external" Pair.sol | grep -v "view\|pure"

# Find external calls
grep -n "\.transfer\|\.call\|\.send\|\.delegatecall" Pair.sol

# Find state updates
grep -n "balances\|totalSupply\|reserves" Pair.sol

# Check for guards
grep -n "nonReentrant\|ReentrancyGuard\|onlyOwner\|onlyAdmin" Pair.sol
```

---

## What to Look For

### Reentrancy Indicators:
1. ❌ External calls before state updates
2. ❌ Missing `nonReentrant` modifier
3. ❌ No reentrancy guard
4. ✅ Good: State updates before external calls

### Flash Loan Indicators:
1. ❌ Price calculation without flash loan check
2. ❌ Missing oracle validation
3. ❌ No MEV protection

### Access Control Indicators:
1. ❌ Public functions without restrictions
2. ❌ Missing `require` statements
3. ❌ No access modifiers

---

## Document Findings

For each verified finding:

1. **Contract**: Pair.sol
2. **Function**: swap(uint256, uint256)
3. **Line**: 123
4. **Vulnerability**: Reentrancy
5. **Code Snippet**:
   ```solidity
   function swap(...) external {
       IERC20(token).transfer(to, amount);  // External call FIRST
       balances[msg.sender] -= amount;      // State update AFTER - VULNERABLE
   }
   ```
6. **Exploit**: Attacker can reenter swap() before balance update
7. **Impact**: Potential loss of funds
8. **Fix**: Add `nonReentrant` modifier or reorder operations

---

## Next Steps

1. **Start with Pair.sol** (most important)
2. **Manually review swap functions**
3. **Search for reentrancy patterns**
4. **Document findings**
5. **Update reports with code references**

---

## Files to Review

**Priority 1 (Critical):**
- `contracts/Pair.sol` - Reentrancy, Flash Loan
- `contracts/RouterV2.sol` - Router vulnerabilities

**Priority 2 (High):**
- `contracts/GenesisPool.sol` - Liquidity pool exploits
- `contracts/GaugeManager.sol` - Access control

---

**Recommendation:** Use manual code review - it's more reliable and gives you better understanding for bug bounty submissions!

