# Kuru Mainnet Address Status

## Problem

The bug bounty scope shows **truncated** mainnet addresses:

| Contract | Partial Address |
|----------|-----------------|
| KuruFlowEntrypoint | `0xb3...13cb` |
| KuruFlowRouter | `0x46...7040` |
| KuruAMMVaultImpl | `0xDC...70F4` |
| KuruForwarder | `0x97...3FAA` |
| KuruForwarderImpl | `0xbf...Fe2A` |
| KuruUtils | `0xD8...27f6` |
| MarginAccount | `0x2A...90c5` |
| MarginAccountImpl | `0x57...0ca7` |
| MonadDeployer | `0xe2...7D1E` |
| OrderBookImpl | `0xea...23CD` |
| Router | `0xd6...95CC` |
| RouterImpl | `0x0F...A9CD` |

## Why We Can't Reconstruct

- Full address = 40 hex characters
- Partial shows ~4-6 chars (start + end)
- Missing ~34 hex characters = 16^34 possibilities
- **Impossible to brute force**

## What We Tried

1. ❌ Kuru SDK GitHub - No hardcoded mainnet addresses
2. ❌ docs.kuru.io - Only testnet addresses listed
3. ❌ Cantina - Bounty page not directly accessible
4. ❌ Web search - No full addresses found
5. ❌ Kuru API - Endpoints not responding
6. ❌ kuru.io frontend - No contract addresses found

## Testnet Addresses (Confirmed Working)

These are the **testnet** addresses from docs:

```
Router: 0x1f5A250c4A506DA4cE584173c6ed1890B1bf7187
MarginAccount: 0xdDDaBd30785bA8b45e434a1f134BDf304d6125d9
OrderBook: 0xa21ca7b4e308e9E2dC4C60620572792634EA21a0
MonadDeployer: 0x1D90616Ad479c3D814021b1f4C43b1a2fFf87626
KuruUtils: 0xDdAEdbc015fEe6BE50c69Fbf5d771A4563C996B3
```

**Note:** These are NOT deployed on mainnet.

## How to Get Full Mainnet Addresses

### Option 1: Cantina Platform (Recommended)

1. Sign up at https://cantina.xyz
2. Search for Kuru bounty
3. View full scope with complete addresses
4. Must accept program terms to see full details

### Option 2: Monad Block Explorer

1. Go to https://monadscan.com
2. Search for verified contracts by Kuru
3. Look for contracts matching partial addresses
4. Filter by creation date (around Nov 24, 2025)

### Option 3: Contact Kuru Team

- Twitter: @KuruExchange
- Discord: Check their community
- Email: Through Cantina platform

### Option 4: On-Chain Discovery

```python
# If we knew a Kuru user address, we could trace their
# interactions to find contract addresses
# Or look at Kuru factory contract events
```

## Next Steps

Once full addresses are obtained:

1. Update `foundry_fork/test/KuruForkTest.t.sol`:
   ```solidity
   address constant ROUTER = 0xd6...95CC;  // Full address
   address constant MARGIN_ACCOUNT = 0x2A...90c5;  // Full address
   ```

2. Run fork tests:
   ```bash
   cd kuru_audit/foundry_fork
   ~/.foundry/bin/forge test --fork-url https://rpc.monad.xyz -vvvv
   ```

3. Document findings and submit to Cantina

## Current Foundry Setup Status

| Component | Status |
|-----------|--------|
| Project structure | ✅ Complete |
| Interfaces | ✅ Complete |
| Test contracts | ✅ Complete |
| forge-std | ✅ Installed |
| Build | ✅ Passing |
| Mainnet addresses | ❌ Missing |
| Fork tests | ⏳ Blocked |

The testing framework is 100% ready - just need the correct mainnet addresses!
