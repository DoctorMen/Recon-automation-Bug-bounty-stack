<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# Slither Detector Names - Correct Usage

## Problem
Slither uses specific detector names, not generic ones like "reentrancy".

## Solution: Use Correct Detector Names

### Correct Reentrancy Detectors:
- `reentrancy-eth` - Reentrancy vulnerabilities (ETH)
- `reentrancy-no-eth` - Reentrancy vulnerabilities (no ETH)
- `reentrancy-unlimited-gas` - Reentrancy with unlimited gas

### Correct Commands:

```bash
cd ~/Recon-automation-Bug-bounty-stack/blackhole_verification/Contracts

# Check for reentrancy (ETH)
slither . --detect reentrancy-eth

# Check for reentrancy (no ETH)
slither . --detect reentrancy-no-eth

# Check for all reentrancy types
slither . --detect reentrancy-eth,reentrancy-no-eth,reentrancy-unlimited-gas

# Check for multiple vulnerability types
slither . --detect reentrancy-eth,reentrancy-no-eth,access-control,unchecked-transfer

# Check all detectors
slither . --detect all
```

### List All Available Detectors:
```bash
slither . --list-detectors
```

### Common Detector Names:
- `reentrancy-eth`
- `reentrancy-no-eth`
- `reentrancy-unlimited-gas`
- `access-control`
- `unchecked-transfer`
- `incorrect-equality`
- `timestamp`
- `tx-origin`
- `uninitialized-state`
- `uninitialized-storage`
- `arbitrary-send`
- `controlled-delegatecall`
- `delegatecall-loop`
- `suicidal`
- `unchecked-send`
- `unchecked-lowlevel`
- `locked-ether`
- `shadowing-state`
- `void-constructor`
- `calls-loop`
- `reentrancy-benign`
- `reentrancy-events`
- `too-many-digits`
- `constable-states`
- `external-function`
- `immutable-states`
- `pragma`
- `solc-version`
- `naming-convention`
- `external-function`
- `low-level-calls`
- `missing-inheritance`
- `missing-events`
- `divide-before-multiply`
- `incorrect-conversion`
- `order-reentrancy`
- `assembly`

### Quick Reference Commands:

```bash
# Navigate to contracts
cd ~/Recon-automation-Bug-bounty-stack/blackhole_verification/Contracts

# Analyze Pair.sol for reentrancy
slither contracts/Pair.sol --detect reentrancy-eth,reentrancy-no-eth

# Analyze RouterV2.sol
slither contracts/RouterV2.sol --detect reentrancy-eth,access-control

# Analyze GenesisPool.sol
slither contracts/GenesisPool.sol --detect reentrancy-eth,access-control,unchecked-transfer

# Full analysis with all detectors
slither . --detect all

# Generate JSON report
slither . --detect reentrancy-eth,reentrancy-no-eth --json slither_report.json
```

### What Each Detector Finds:

**reentrancy-eth**: 
- Reentrancy vulnerabilities involving ETH transfers
- External calls before state updates with ETH

**reentrancy-no-eth**:
- Reentrancy vulnerabilities without ETH
- External calls before state updates

**access-control**:
- Missing access control modifiers
- Unauthorized function access

**unchecked-transfer**:
- Unchecked return values from transfers
- Missing error handling

---

## Recommended Command for Your Findings:

```bash
cd ~/Recon-automation-Bug-bounty-stack/blackhole_verification/Contracts

# Check for all reentrancy types
slither . --detect reentrancy-eth,reentrancy-no-eth,reentrancy-unlimited-gas

# Check for access control issues
slither . --detect access-control

# Check for unchecked transfers
slither . --detect unchecked-transfer

# Full analysis of critical findings
slither . --detect reentrancy-eth,reentrancy-no-eth,access-control,unchecked-transfer,incorrect-equality,timestamp
```

---

## Example Output:

```
INFO:Detectors:Reentrancy in Pair.swap(uint256,uint256) (contracts/Pair.sol#123):
        External calls:
        - IERC20(token).transfer(to, amount) (contracts/Pair.sol#124)
        State variables written after the call(s):
        - balances[msg.sender] -= amount (contracts/Pair.sol#125)
Reference: https://github.com/crytic/slither/wiki/Detector-Documentation#reentrancy-vulnerabilities
```

---

## Quick Start:

```bash
cd ~/Recon-automation-Bug-bounty-stack/blackhole_verification/Contracts

# Run reentrancy detection (correct command)
slither . --detect reentrancy-eth,reentrancy-no-eth
```

