# Fix: Slither Command Not Found

## Problem
Slither is installed but not in PATH yet. The shell needs to reload.

## Solution

### Option 1: Reload Shell (Easiest)
```bash
# Close and reopen terminal, or:
source ~/.bashrc

# Then try again
cd ~/Recon-automation-Bug-bounty-stack/blackhole_verification/Contracts
slither . --detect reentrancy-eth,reentrancy-no-eth
```

### Option 2: Use Full Path
```bash
cd ~/Recon-automation-Bug-bounty-stack/blackhole_verification/Contracts
~/.local/bin/slither . --detect reentrancy-eth,reentrancy-no-eth
```

### Option 3: Add to PATH Manually
```bash
export PATH="$HOME/.local/bin:$PATH"
cd ~/Recon-automation-Bug-bounty-stack/blackhole_verification/Contracts
slither . --detect reentrancy-eth,reentrancy-no-eth
```

---

## Correct Slither Commands

**Important:** Slither uses specific detector names, not "reentrancy" alone.

### Correct Reentrancy Detection:
```bash
# Use full path if needed
~/.local/bin/slither . --detect reentrancy-eth,reentrancy-no-eth
```

### Detector Names:
- `reentrancy-eth` - Reentrancy with ETH
- `reentrancy-no-eth` - Reentrancy without ETH  
- `reentrancy-unlimited-gas` - Reentrancy with unlimited gas

### Full Analysis Command:
```bash
cd ~/Recon-automation-Bug-bounty-stack/blackhole_verification/Contracts

# Use full path
~/.local/bin/slither . --detect reentrancy-eth,reentrancy-no-eth,reentrancy-unlimited-gas,access-control,unchecked-transfer
```

---

## Quick Fix (Run This):

```bash
# Reload PATH
export PATH="$HOME/.local/bin:$PATH"

# Navigate to contracts
cd ~/Recon-automation-Bug-bounty-stack/blackhole_verification/Contracts

# Run analysis with correct detector names
slither . --detect reentrancy-eth,reentrancy-no-eth
```

---

## Or Use Full Path:

```bash
cd ~/Recon-automation-Bug-bounty-stack/blackhole_verification/Contracts

# Use full path to slither
~/.local/bin/slither . --detect reentrancy-eth,reentrancy-no-eth

# Analyze specific contract
~/.local/bin/slither contracts/Pair.sol --detect reentrancy-eth,reentrancy-no-eth
```

---

## List All Detectors:

```bash
~/.local/bin/slither . --list-detectors | grep -i reentrancy
```

This will show all reentrancy-related detectors.

