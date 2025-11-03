# Blackhole DEX Attack - Code4rena (PT Enhanced)

## 🎯 Target Information
- **Platform**: Code4rena
- **Project**: Blackhole DEX
- **Chain**: Avalanche
- **Max Bounty**: $100,000 in $BLACK tokens
- **Program URL**: https://code4rena.com/bounties/blackhole
- **GitHub Repo**: https://github.com/BlackHoleDEX/Contracts
- **Previous Audits**: https://docs.blackhole.xyz/security

## ✅ In-Scope Contracts

### AMM Pools
- Pair.sol
- PairFees.sol
- PairFactory.sol
- PairGenerator.sol
- RouterV2.sol
- RouterHelper.sol
- TokenHandler.sol

### VE(3,3)
- GaugeManager.sol
- GaugeFactory.sol
- GaugeFactoryCL.sol
- GaugeExtraRewarder.sol
- GaugeOwner.sol
- GaugeV2.sol
- GaugeCL.sol

### Genesis Pool
- GenesisPool.sol
- GenesisPoolFactory.sol
- GenesisPoolManager.sol

### API Helpers
- AlgebraPoolApi.sol
- BlackHolePairApiV2.sol
- GenesisPoolApi.sol
- RewardApi.sol
- TokenApi.sol
- VNFTAPIV1.sol

### VE NFT
- AutoVotingEscrow.sol
- AutoVotingEscrowManager.sol

## ⚠️ Out of Scope (Will Be Filtered)
- VNFTApi.sol
- ChainLink contracts
- Governance contracts
- BlackGovernor.sol
- TradeHelper.sol
- CustomToken.sol
- GlobalRouter.sol
- Waves.sol

## 🚫 Known Issues (Will Be Filtered)
The system automatically filters these known issues:
1. getNFTPoolVotes() function (unused variable)
2. VotingEscrow::delegateBySig::DOMAIN_TYPEHASH variable issue
3. GaugeCL.sol: getReward() function flaw
4. GaugeCL.sol: createGauge issues
5. GenesisPoolManager.depositNativeToken issues
6. GenesisPool DoS before approveGenesisPool
7. GenesisPool token ratio manipulation

## 📊 Severity Criteria
- **Critical**: Loss of user funds
- **Severe**: Temporary denial of service, incorrect calculations
- **Payout**: Based on TVL at time of report

## 💰 TVL-Based Payout Ratios
- Below $50M: 50% of category bounty
- $50M-$125M: 75% of category bounty
- Above $125M: 100% of category bounty

## 🚀 Quick Start

### Run the Attack Script:
```bash
cd ~/Recon-automation-Bug-bounty-stack
python3 scripts/attack_blackhole.py
```

### What It Does:
1. **Discovers endpoints** - Finds API endpoints, web frontend, GraphQL
2. **Tests DEX vulnerabilities** - 10 critical DEX vulnerability types with PT methodology
3. **Scans API endpoints** - Uses hackingapis.pdf + penetrationtesting.pdf methodology
4. **Filters known issues** - Automatically excludes known issues
5. **Generates reports** - Creates Code4rena submission-ready reports with PT analysis

## 📋 Methodology Integration

### Penetration Testing PDF Techniques:
- **Reconnaissance**: Passive recon, subdomain enumeration
- **Scanning**: Port scanning, service identification
- **Enumeration**: Directory enumeration, endpoint discovery
- **Vulnerability Assessment**: Automated + manual verification
- **Exploitation**: Proof of concept development
- **Impact Assessment**: CIA (Confidentiality, Integrity, Availability) analysis

### API Testing (hackingapis.pdf):
- Authentication testing (JWT, OAuth, API keys)
- Authorization testing (IDOR, privilege escalation)
- Input validation (parameter manipulation, mass assignment)
- Business logic (rate limiting, batch operations, race conditions)

### DeFi Security Focus:
- Reentrancy attacks
- Flash loan vulnerabilities
- Price manipulation
- Liquidity pool exploits
- Access control issues
- Integer overflow/underflow
- Front-running vulnerabilities
- MEV exploitation

## 📁 Output Location
All findings saved to: `output/blackhole_code4rena/`

## ✅ Features
- ✅ Automatic filtering of known issues
- ✅ Scope validation (only in-scope contracts)
- ✅ PT methodology integration
- ✅ TVL-based impact calculation
- ✅ Code4rena submission format
- ✅ Exploitation steps generation
- ✅ Impact assessment (CIA)

## 📝 Submission
Submit findings via Code4rena: https://code4rena.com/bounties/blackhole/make-submission

## ⚠️ Important Notes
1. **Check GitHub repo** before submitting: https://github.com/BlackHoleDEX/Contracts
2. **Review previous audits**: https://docs.blackhole.xyz/security
3. **Verify scope** - Only submit findings for in-scope contracts
4. **Filter duplicates** - System automatically filters known issues
5. **TVL impact** - Calculate TVL at risk for accurate payout estimation
