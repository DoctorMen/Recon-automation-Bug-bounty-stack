# ✅ Manual Verification - Ready to Start!

## Status
- ✅ Contracts cloned: `blackhole_verification/Contracts/contracts/`
- ✅ Pair.sol found (26KB)
- ✅ Slither installed but needs solc compiler
- ✅ **RECOMMENDED: Manual code review** (better for bug bounty)

---

## Quick Start: Manual Verification

### Step 1: Open Contract File
```bash
cd ~/Recon-automation-Bug-bounty-stack/blackhole_verification/Contracts/contracts
code Pair.sol  # VS Code
# or
vim Pair.sol   # Vim
# or view it
cat Pair.sol | less
```

### Step 2: Search for Critical Functions

**Find swap/exchange functions:**
```bash
# Search for any function that might swap tokens
grep -i "swap\|exchange\|transfer" Pair.sol | head -20

# Find all external/public functions
grep -E "function.*external|function.*public" Pair.sol | head -20
```

### Step 3: Look for Reentrancy Patterns

**Manual check:**
1. Open `Pair.sol` in your editor
2. Search for functions that:
   - Transfer tokens (`transfer`, `call`, `send`)
   - Update state (`balances`, `totalSupply`)
3. Check if external calls happen BEFORE state updates
4. Look for `nonReentrant` modifier or guards

**Pattern to find:**
```solidity
// VULNERABLE:
function someFunction() external {
    IERC20(token).transfer(to, amount);  // External call FIRST
    balanceOf[msg.sender] -= amount;      // State update AFTER - BAD!
}

// SAFE:
function someFunction() external nonReentrant {
    balanceOf[msg.sender] -= amount;      // State update FIRST
    IERC20(token).transfer(to, amount);   // External call AFTER - GOOD!
}
```

---

## Verification Commands

```bash
cd ~/Recon-automation-Bug-bounty-stack/blackhole_verification/Contracts/contracts

# View contract
cat Pair.sol | less

# Search for external calls
grep -n "\.transfer\|\.call\|\.send" Pair.sol

# Search for state updates
grep -n "balanceOf\|totalSupply" Pair.sol

# Search for guards
grep -n "nonReentrant\|ReentrancyGuard" Pair.sol

# Count functions
grep -c "^[[:space:]]*function" Pair.sol
```

---

## What You Need to Do

### For Each Finding:

1. **Open the contract file**
2. **Find the vulnerable function**
3. **Document:**
   - Function name
   - Line number
   - Code snippet
   - Vulnerability explanation
   - Impact
   - Proof of concept

### Update Reports:

1. Open report: `output/blackhole_code4rena/reports/finding_001_reentrancy.md`
2. Add code references:
   - Contract: `Pair.sol`
   - Function: `swap()` (or whatever function)
   - Line: `123`
   - Code snippet
3. Update proof of concept
4. Add impact assessment

---

## Priority Order

1. **Pair.sol** - Check for reentrancy in swap functions
2. **RouterV2.sol** - Check router vulnerabilities  
3. **GenesisPool.sol** - Check liquidity pool exploits

---

## Summary

**Slither Status:** Installed but needs solc compiler (optional)  
**Recommended:** Manual code review (better for bug bounty)  
**Next Step:** Open `Pair.sol` and manually review for reentrancy

**Quick Command:**
```bash
cd ~/Recon-automation-Bug-bounty-stack/blackhole_verification/Contracts/contracts
code Pair.sol  # Start reviewing!
```

---

**You're ready to start manual verification!** 

Open `Pair.sol` and start reviewing the code for vulnerabilities. This is actually the best approach for bug bounty - you'll understand the code better and create better submissions.

