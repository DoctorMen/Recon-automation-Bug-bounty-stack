# ✅ Real Crypto Bug Bounty Programs - Scope Configuration

## 🎯 Programs Configured

### 1. **Crypto.com** - HackerOne
- **Domains**: `*.crypto.com`, `*.crypto.org`
- **Max Reward**: $2,000,000
- **Scope**: API, Exchange, App, Pay endpoints
- **Platform**: HackerOne
- **Program**: https://hackerone.com/cryptocom

### 2. **WhiteBIT** - HackenProof
- **Domains**: `*.whitebit.com`
- **Max Reward**: $10,000
- **Scope**: API, Web, Exchange endpoints
- **Platform**: HackenProof
- **Program**: https://hackenproof.com/whitebit

### 3. **NiceHash** - HackenProof
- **Domains**: `*.nicehash.com`
- **Max Reward**: $22,500
- **Scope**: API, Mining, Platform endpoints
- **Platform**: HackenProof
- **Program**: https://hackenproof.com/nicehash

### 4. **Coinbase** - HackerOne
- **Domains**: `coinbase.com`, `pro.coinbase.com`, `api.coinbase.com`, `commerce.coinbase.com`
- **Max Reward**: $250,000
- **Scope**: API, Exchange, Commerce endpoints
- **Platform**: HackerOne
- **Program**: https://hackerone.com/coinbase

### 5. **Binance** - HackerOne
- **Domains**: `binance.com`, `binance.us`, `api.binance.com`
- **Max Reward**: $10,000
- **Scope**: API, Exchange endpoints
- **Platform**: HackerOne
- **Program**: https://hackerone.com/binance

### 6. **Kraken** - HackerOne
- **Domains**: `kraken.com`, `api.kraken.com`
- **Max Reward**: $100,000
- **Scope**: API, Exchange endpoints
- **Platform**: HackerOne
- **Program**: https://hackerone.com/kraken

### 7. **Gemini** - HackerOne
- **Domains**: `gemini.com`, `api.gemini.com`
- **Max Reward**: $30,000
- **Scope**: API, Exchange endpoints
- **Platform**: HackerOne
- **Program**: https://hackerone.com/gemini

### 8. **Rapyd** - Bugcrowd
- **Domains**: `rapyd.net`, `api.rapyd.net`
- **Max Reward**: $5,000
- **Scope**: API, Payment endpoints
- **Platform**: Bugcrowd
- **Program**: https://bugcrowd.com/rapyd

### 9. **PayPal (Crypto)** - HackerOne
- **Domains**: `paypal.com`, `crypto.paypal.com`
- **Max Reward**: $30,000
- **Scope**: API, Crypto, Payment endpoints
- **Platform**: HackerOne
- **Program**: https://hackerone.com/paypal

---

## ✅ Scope Validation

### What Gets Checked:
1. ✅ **Domain matches program scope** (wildcards supported)
2. ✅ **Endpoint type matches program scope** (API, Exchange, etc.)
3. ✅ **Removed example.com** from all patterns
4. ✅ **Filters test/staging/dev** environments
5. ✅ **Validates against actual program scopes**

### Scope Matching Logic:
```python
For each finding:
1. Extract domain from URL
2. Check against CRYPTO_PROGRAM_SCOPES
3. Verify endpoint type matches program scope
4. Return: (is_in_scope, program_name, program_info)
```

---

## 🔒 Idempotency Maintained

✅ **Checkpoints preserved**
- Stage completion tracking
- Resume capability
- No duplicate work

✅ **Duplicate Detection**
- Checks against known vulnerabilities
- Prevents submitting duplicate bugs
- Analyzes duplicate risk before reporting

---

## 🎯 Original Bug Finding

### Duplicate Prevention:
- ✅ Analyzes vulnerability patterns
- ✅ Checks against common bug types
- ✅ Scores duplicate risk
- ✅ Only reports original findings

### Originality Indicators:
- ✅ Unique vulnerability patterns
- ✅ Novel exploitation techniques
- ✅ Crypto-specific issues
- ✅ Program-specific configurations

---

## 📊 What Gets Reported

### Only Reports If:
1. ✅ **In real crypto program scope**
2. ✅ **Endpoint type matches scope**
3. ✅ **Not test/staging/dev**
4. ✅ **Verified exploitable** (or high confidence)
5. ✅ **Low duplicate risk**

### Scope Validation Example:
```
URL: https://api.crypto.com/v1/auth/login
→ Domain: crypto.com ✅
→ Endpoint: /api/ ✅
→ Program: crypto.com ✅
→ Scope: API endpoint ✅
→ Result: IN SCOPE ✅
```

---

## 🚀 Usage

The system automatically:
1. ✅ Checks if URL is in crypto program scope
2. ✅ Validates endpoint type matches scope
3. ✅ Filters test/staging environments
4. ✅ Only reports verified, original findings
5. ✅ Maintains idempotency

**No more example.com - only real crypto bug bounty programs with verified scopes!** ✅🔒

