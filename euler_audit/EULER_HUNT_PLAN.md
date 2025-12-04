# Euler V2 Bug Bounty Hunt Plan

**Target:** Euler V2 Lending Platform  
**Max Reward:** $7,500,000 (with USL vault boost)  
**Status:** 156 findings already submitted - need to find NEW bugs

---

## Reward Structure

| Component | High | Medium | Notes |
|-----------|------|--------|-------|
| **Core (EVC, EVK, EPO)** | $5,000,000 | $200,000 | Main target |
| **+ USL Vaults** | +$2,500,000 | - | USUAL tokens |
| Euler Earn | $500,000 | $100,000 | Risk curation |
| EulerSwap | $250,000 | $50,000 | AMM with JIT |
| Fee Flow / Rewards | $100,000 | $25,000 | Supporting |
| Website | $25,000 | $1,000 | app.euler.finance |

---

## In-Scope Contracts (Ethereum Mainnet)

### Core Perspectives (Query verifiedArray())

```
Escrowed Collateral: 0x4e58BBEa423c4B9A2Fc7b8E58F5499f9927fADdE
Ungoverned 0x:       0xb50a07C2B0F128Faa065bD18Ea2091F5da5e7FbF
Ungoverned nzx:      0x600bBe1D0759F380Fea72B2e9B2B6DCb4A21B507
Governed:            0xC0121817FF224a018840e4D15a864747d36e6Eb2
Euler Earn:          0x492e9FE1289d43F8bB6275237BF16c9248C74D44
```

### Supporting Contracts

```
Fee Flow:            0xFcd3Db06EA814eB21C84304fC7F90798C00D1e32
Balance Tracker:     0x0D52d06ceB8Dcdeeb40Cfd9f17489B350dD7F8a3
EulerSwap:           0xb013be1D0D380C13B58e889f412895970A2Cf228
```

### USL Vaults (BOOSTED - $7.5M potential!)

```
USD0++:              0xF037eeEBA7729c39114B9711c75FbccCa4A343C8
USD0:                0xd001f0a15D272542687b2677BA627f48A4333b5d
```

---

## GitHub Repositories

1. [Ethereum Vault Connector](https://github.com/euler-xyz/ethereum-vault-connector)
2. [Euler Vault Kit](https://github.com/euler-xyz/euler-vault-kit)
3. [Euler Price Oracle](https://github.com/euler-xyz/euler-price-oracle)
4. [Reward Streams](https://github.com/euler-xyz/reward-streams)
5. [Fee Flow](https://github.com/euler-xyz/fee-flow)
6. [Euler Earn](https://github.com/euler-xyz/euler-earn)
7. [EulerSwap](https://github.com/euler-xyz/euler-swap)

---

## High-Priority Attack Vectors

### 1. EVC (Ethereum Vault Connector) - Core Primitive

- **Operator permissions** - Can operators be exploited?
- **Account status checks** - Bypass health checks?
- **Batch execution** - Reentrancy in batch calls?
- **Controller hijacking** - Unauthorized controller changes?

### 2. EVK (Euler Vault Kit) - Credit Vaults

- **Liquidation logic** - Bad debt socialization bugs?
- **Interest rate manipulation** - IRM exploits?
- **Share inflation** - First depositor attacks? (learned from Kuru!)
- **Cross-vault interactions** - Collateral/debt mismatches?
- **Borrow/repay ordering** - Reentrancy vectors?

### 3. Price Oracle Adapters

- **Stale price exploitation** - Chainlink heartbeat gaps?
- **Price manipulation** - Flash loan + oracle update?
- **Decimal handling** - Precision loss across adapters?
- **Fallback logic** - Router fallback exploits?

### 4. EulerSwap - AMM with JIT Liquidity

- **JIT liquidity abuse** - Borrow without repay?
- **Swap manipulation** - Price deviation exploits?
- **Hook interactions** - Uniswap v4 hook bugs?
- **Single-sided liquidity** - Imbalance attacks?

### 5. Euler Earn - Risk Curation

- **Strategy allocation** - Drain via malicious strategy?
- **Withdrawal ordering** - Front-run withdrawals?
- **Yield manipulation** - Inflate/deflate yields?

### 6. USL Vaults (USD0/USD0++) - HIGHEST PRIORITY

- **Depeg scenarios** - What happens if USD0 depegs?
- **Collateral manipulation** - Specific to Usual protocol?
- **Cross-protocol risks** - Usual + Euler interactions?

---

## Out of Scope (Don't Waste Time)

- Governor/deployer misconfigurations
- Non-standard token behaviors
- Oracle stale price without exploit
- Sequencer downtime issues
- Third-party oracle bugs
- Impermanent loss (expected)
- Arbitrage losses (expected)

---

## Hunt Strategy

### Phase 1: Reconnaissance (Today)

1. Clone all 7 repositories
2. Map contract architecture
3. Identify entry points
4. Find previous audit reports

### Phase 2: Static Analysis

1. Slither/Mythril scans
2. Manual code review of critical paths
3. Cross-reference with known ERC4626 bugs
4. Check for reentrancy patterns

### Phase 3: Dynamic Testing

1. Fork mainnet with Foundry
2. Test liquidation edge cases
3. Fuzz oracle price updates
4. Test cross-vault interactions

### Phase 4: Economic Analysis

1. Flash loan attack vectors
2. Oracle manipulation scenarios
3. Bad debt scenarios
4. Yield extraction attacks

---

## Key Learning from Kuru Hunt

1. **Verify math before submission** - Don't submit false positives
2. **Self-triage findings** - Test on fork before reporting
3. **Check existing protections** - Dead shares, access controls
4. **Read previous audits** - Don't duplicate known issues

---

## Resources

- [Euler Docs](https://docs.euler.finance)
- [Contract Addresses](https://docs.euler.finance/contract-addresses)
- [Previous Audits](https://github.com/euler-xyz/euler-vault-kit/tree/master/audits)

---

## Next Steps

1. [ ] Clone repositories
2. [ ] Download deployed bytecode
3. [ ] Set up Foundry fork tests
4. [ ] Run static analysis
5. [ ] Begin manual review of EVC
6. [ ] Focus on USL vaults for max bounty
