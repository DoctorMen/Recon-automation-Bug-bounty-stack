# How to Clone & Verify Contracts Against Findings

## ✅ Contracts Already Cloned!

**Location:** `~/Recon-automation-Bug-bounty-stack/blackhole_verification/Contracts`

---

## Quick Start: Verify Critical Findings

### Step 1: Navigate to Contracts
```bash
cd ~/Recon-automation-Bug-bounty-stack/blackhole_verification/Contracts
cd contracts
```

### Step 2: Verify Each Finding

#### Finding 1: Reentrancy (Critical)
**Target Contracts:**
- `Pair.sol`
- `RouterV2.sol`
- `RouterHelper.sol`

**What to Check:**
```bash
# Open Pair.sol
code Pair.sol  # or your preferred editor

# Search for:
# 1. External calls before state updates
# 2. Missing reentrancy guards
# 3. Checks-Effects-Interactions pattern violations
```

**Manual Verification:**
1. Open `Pair.sol`
2. Find swap functions (look for `swap`, `swapExactTokensForTokens`, etc.)
3. Check if external calls happen before state updates
4. Look for `nonReentrant` modifier or reentrancy guards
5. Document findings

**Use Static Analysis:**
```bash
# Install Slither
pip install slither-analyzer

# Run reentrancy detection
cd ~/Recon-automation-Bug-bounty-stack/blackhole_verification/Contracts
slither . --detect reentrancy-eth,reentrancy-no-eth
```

---

#### Finding 2: Flash Loan Attack (Critical)
**Target Contracts:**
- `Pair.sol`
- `PairFactory.sol` (if exists)

**What to Check:**
```bash
# Check Pair.sol for:
# 1. Flash loan checks in swap functions
# 2. Price oracle manipulation vectors
# 3. MEV protection
# 4. Price manipulation vulnerabilities
```

**Manual Verification:**
1. Open `Pair.sol`
2. Find swap/price calculation functions
3. Check for flash loan checks
4. Verify price oracle usage
5. Document findings

**Use Static Analysis:**
```bash
slither . --detect incorrect-equality,unchecked-transfer
```

---

#### Finding 3: Liquidity Pool Exploit (Critical)
**Target Contracts:**
- `Pair.sol`
- `GenesisPool.sol`

**What to Check:**
```bash
# Check for:
# 1. Access control on pool functions
# 2. Liquidity manipulation protection
# 3. Improper access control
# 4. Pool draining vectors
```

**Manual Verification:**
1. Open `Pair.sol` and `GenesisPool.sol`
2. Check access control modifiers
3. Verify liquidity manipulation protection
4. Document findings

**Use Static Analysis:**
```bash
slither . --detect access-control,unchecked-transfer
```

---

## Detailed Verification Process

### Method 1: Manual Code Review (Recommended)

**Step 1: Open Contract File**
```bash
cd ~/Recon-automation-Bug-bounty-stack/blackhole_verification/Contracts/contracts
code Pair.sol  # VS Code
# or
vim Pair.sol   # Vim
# or
nano Pair.sol  # Nano
```

**Step 2: Search for Vulnerability Patterns**

**For Reentrancy:**
```solidity
// Look for patterns like:
function swap(...) external {
    // External call BEFORE state update (BAD)
    IERC20(token).transfer(...);
    balance = balance - amount;  // State update AFTER
    
    // Should be:
    balance = balance - amount;  // State update FIRST
    IERC20(token).transfer(...); // External call AFTER
}
```

**For Flash Loan:**
```solidity
// Look for:
function swap(...) external {
    // Missing flash loan check
    uint256 price = getPrice();
    // No check if price was manipulated
}
```

**For Access Control:**
```solidity
// Look for:
function adminFunction(...) external {
    // Missing require or modifier
    // Should have: require(msg.sender == owner)
}
```

**Step 3: Document Findings**
- Note line numbers
- Copy code snippets
- Explain vulnerability
- Create proof of concept

---

### Method 2: Static Analysis Tools

**Install Slither:**
```bash
pip install slither-analyzer
```

**Run Analysis:**
```bash
cd ~/Recon-automation-Bug-bounty-stack/blackhole_verification/Contracts
slither . --detect reentrancy,access-control,unchecked-transfer,incorrect-equality
```

**Output Example:**
```
contracts/Pair.sol:123: swap() has external call before state update
  - Reentrancy vulnerability detected
  - Recommendation: Use Checks-Effects-Interactions pattern
```

**Install Mythril (Alternative):**
```bash
pip install mythril
myth analyze contracts/Pair.sol
```

---

### Method 3: Local Testing (Advanced)

**Setup Foundry:**
```bash
# Install Foundry
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Create test directory
cd ~/Recon-automation-Bug-bounty-stack/blackhole_verification
forge init blackhole-test
cd blackhole-test

# Copy contracts
cp -r ../Contracts/contracts ./src/

# Create test
forge test --fork-url https://api.avax.network/ext/bc/C/rpc
```

**Write Exploit Test:**
```solidity
// test/ReentrancyExploit.t.sol
contract ReentrancyExploitTest {
    function testReentrancy() public {
        // Your exploit code here
        // Test on forked mainnet
    }
}
```

---

## Verification Checklist Per Finding

### For Each Finding:

1. **Contract Location**
   - [ ] Found contract file
   - [ ] Verified contract is in scope
   - [ ] Checked contract name matches

2. **Code Review**
   - [ ] Opened contract file
   - [ ] Searched for vulnerability pattern
   - [ ] Found vulnerable code section
   - [ ] Verified exploitability

3. **Impact Assessment**
   - [ ] Calculated potential impact
   - [ ] Verified funds at risk
   - [ ] Documented attack vector

4. **Proof of Concept**
   - [ ] Created exploit code (local test)
   - [ ] Documented attack steps
   - [ ] Included code snippets

5. **Documentation**
   - [ ] Updated finding report
   - [ ] Added code references
   - [ ] Included line numbers
   - [ ] Added remediation

---

## Quick Commands Reference

```bash
# Navigate to contracts
cd ~/Recon-automation-Bug-bounty-stack/blackhole_verification/Contracts

# List all contracts
ls contracts/*.sol

# Search for specific contract
find contracts -name "Pair.sol"

# View contract
cat contracts/Pair.sol | less

# Search for patterns
grep -n "external" contracts/Pair.sol
grep -n "transfer" contracts/Pair.sol
grep -n "swap" contracts/Pair.sol

# Run static analysis
slither . --detect reentrancy

# Update contracts
git pull
```

---

## Example: Verifying Reentrancy Finding

### Step 1: Open Contract
```bash
cd ~/Recon-automation-Bug-bounty-stack/blackhole_verification/Contracts/contracts
code Pair.sol
```

### Step 2: Find Swap Function
```solidity
// Search for function swap or swapExactTokensForTokens
function swapExactTokensForTokens(...) external {
    // Look at code flow
}
```

### Step 3: Check for Vulnerability
```solidity
// Vulnerable pattern:
function swap(...) external {
    IERC20(token).transfer(to, amount);  // External call FIRST
    balances[msg.sender] -= amount;      // State update AFTER
    // VULNERABLE TO REENTRANCY!
}

// Safe pattern:
function swap(...) external nonReentrant {
    balances[msg.sender] -= amount;      // State update FIRST
    IERC20(token).transfer(to, amount);  // External call AFTER
    // PROTECTED!
}
```

### Step 4: Document
- Line number: `123`
- Function: `swap()`
- Issue: External call before state update
- Impact: Reentrancy attack possible
- Fix: Add `nonReentrant` modifier or reorder

### Step 5: Update Report
Update `output/blackhole_code4rena/reports/finding_001_reentrancy.md`:
- Add code references
- Include line numbers
- Add proof of concept
- Document impact

---

## Files Location

**Contracts:** `blackhole_verification/Contracts/contracts/`
**Reports:** `output/blackhole_code4rena/reports/`
**Scripts:** `scripts/`

---

## Next Steps

1. **Start with Critical Findings:**
   ```bash
   cd ~/Recon-automation-Bug-bounty-stack/blackhole_verification/Contracts/contracts
   code Pair.sol  # Review for reentrancy
   ```

2. **Use Static Analysis:**
   ```bash
   pip install slither-analyzer
   cd ~/Recon-automation-Bug-bounty-stack/blackhole_verification/Contracts
   slither . --detect reentrancy
   ```

3. **Document Findings:**
   - Update reports with code references
   - Add line numbers
   - Include proof of concept

4. **Submit Verified Findings:**
   - Only submit verified bugs
   - Include code references
   - Provide proof of concept

---

**Status:** ✅ Contracts cloned and ready for verification!
**Location:** `~/Recon-automation-Bug-bounty-stack/blackhole_verification/Contracts`

