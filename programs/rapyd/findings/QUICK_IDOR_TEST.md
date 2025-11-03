# Quick IDOR Test - Rapyd API

## The Problem
You're in `programs/rapyd/findings/` but trying to run `scripts/quick_client_scan.py` which is:
1. In the wrong location (it's in `~/Recon-automation-Bug-bounty-stack/scripts/`)
2. The wrong script (that's for client scanning, not IDOR testing)

## The Solution

You're already in the right directory! Use `quick_api_test.py` which is right here.

### Option 1: Quick Test (Recommended)

```bash
# Make sure you're in the findings directory
cd ~/Recon-automation-Bug-bounty-stack/programs/rapyd/findings

# Load credentials
source ../credentials.sh

# Run the IDOR test (you need TOKEN_A and TOKEN_B)
python3 quick_api_test.py "$TOKEN_A" "$TOKEN_B" "PAYMENT_ID"
```

### Option 2: Use the Helper Script

I've created `run_idor_test.sh` for you:

```bash
# Make sure you're in the findings directory
cd ~/Recon-automation-Bug-bounty-stack/programs/rapyd/findings

# Make it executable (in Ubuntu terminal, not PowerShell)
chmod +x run_idor_test.sh

# Run it
./run_idor_test.sh [PAYMENT_ID]
```

### Option 3: Manual Test with Your Data

If you have TOKEN_A and TOKEN_B already:

```bash
cd ~/Recon-automation-Bug-bounty-stack/programs/rapyd/findings

# Set your tokens
export TOKEN_A="your_token_a_here"
export TOKEN_B="your_token_b_here"

# Test with payment ID
python3 quick_api_test.py "$TOKEN_A" "$TOKEN_B" "PAYMENT_ID"
```

## What the Script Does

The `quick_api_test.py` script:
1. Tests Account B with TOKEN_B → Should get 200 (owns the payment)
2. Tests Account A with TOKEN_A → If gets 200, IDOR vulnerability found!
3. Saves evidence to `evidence/idor_api_PAYMENT_ID.json`

## Getting Your Tokens

If you need to set up TOKEN_A and TOKEN_B:

1. **Create two separate Rapyd accounts** (Account A and Account B)
2. **Create a payment in Account B**
3. **Get the payment ID** from Account B
4. **Get API tokens** from both accounts
5. **Test**: Account A trying to access Account B's payment

## Example Output

```
============================================================
Quick API IDOR Test - Rapyd
============================================================
Testing: https://sandboxapi.rapyd.net/v1/payments/PAYMENT_ID
Account B: 200
Account A: 200
VULNERABILITY FOUND!
Saved: evidence/idor_api_PAYMENT_ID.json
```

## Common Issues

### "can't open file"
- Make sure you're in `programs/rapyd/findings/` directory
- Use `pwd` to check your current directory
- The script is `quick_api_test.py`, not `quick_client_scan.py`

### "No such file or directory"
- You're probably in PowerShell, not Ubuntu terminal
- Open Ubuntu terminal (WSL) and run commands there
- Or use: `wsl bash -c "cd ~/Recon-automation-Bug-bounty-stack/programs/rapyd/findings && python3 quick_api_test.py ..."`

### Missing tokens
- Check `../credentials.sh` for `TOKEN_A` and `TOKEN_B`
- Or set them manually: `export TOKEN_A="..."` and `export TOKEN_B="..."`

