# Kuru DEX Foundry Fork Testing

Security testing suite for Kuru DEX on Monad.

## Setup

```bash
# Install Foundry (if not installed)
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Install dependencies
cd kuru_audit/foundry_fork
forge install foundry-rs/forge-std --no-git

# Build
forge build
```

## Run Tests

### Fork Tests (Against Live Monad)

```bash
# Run all fork tests
forge test --fork-url https://rpc.monad.xyz -vvvv

# Run specific test
forge test --fork-url https://rpc.monad.xyz --match-test test_CreditUser_AccessControl -vvvv

# Run with gas report
forge test --fork-url https://rpc.monad.xyz --gas-report
```

### Local Tests (Without Fork)

```bash
forge test -vvvv
```

### Fuzzing

```bash
# Fuzz creditUsersEncoded
forge test --match-test testFuzz_CreditUsersEncoded --fuzz-runs 1000

# Full fuzzing campaign
forge test --fuzz-runs 10000
```

## Test Coverage

| Test | Target | Purpose |
|------|--------|---------|
| `test_CreditUser_AccessControl` | MarginAccount | Verify only markets can credit |
| `test_DebitUser_AccessControl` | MarginAccount | Verify only markets can debit |
| `test_UpdateMarkets_AccessControl` | MarginAccount | Verify market registration |
| `test_AnyToAnySwap_ArrayMismatch` | Router | Check array length validation |
| `test_FlipOrder_ExtremePriceBounds` | OrderBook | Check flip price validation |
| `testFuzz_CreditUsersEncoded` | MarginAccount | Fuzz encoded data parsing |

## Contract Addresses (Monad)

| Contract | Address |
|----------|---------|
| Router | `0x1f5A250c4A506DA4cE584173c6ed1890B1bf7187` |
| MarginAccount | `0xdDDaBd30785bA8b45e434a1f134BDf304d6125d9` |
| OrderBook | `0xa21ca7b4e308e9E2dC4C60620572792634EA21a0` |

## Expected Results

If access control is properly implemented:
- All `test_*_AccessControl` tests should PASS (reverts expected)
- Fuzzing should not find any successful unauthorized calls

If vulnerabilities exist:
- Tests will FAIL with `CRITICAL` messages
- Document findings and prepare bug bounty submission

## Scripts

```bash
# Check contract info
forge script script/Setup.s.sol --fork-url https://rpc.monad.xyz

# Attempt exploit (testing only)
forge script script/Setup.s.sol:ExploitAttempt --fork-url https://rpc.monad.xyz --broadcast
```

## Security Notes

- These tests are for authorized security research only
- Do not execute exploits on mainnet without permission
- Report all findings through official Cantina bug bounty program
