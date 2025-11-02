# Bolt Bug Findings - Scope Verification Required

## ⚠️ CRITICAL FINDING

**Issue**: Our bug findings are for `merchant.bolt.com`, but the Bolt Technology OÜ bug bounty program scope only includes:
- `*.bolt.eu` 
- `*.taxify.eu`
- Mobile apps (Bolt Rider, Bolt Food)

**`merchant.bolt.com` is NOT listed in scope.**

## Findings Summary

We found 8 HIGH severity bugs for Bolt:

### Authentication Bypass (4 bugs)
1. `https://merchant.bolt.com/admin`
2. `https://merchant.bolt.com/dashboard`
3. `https://merchant.bolt.com/settings`
4. `https://merchant.bolt.com/api/admin`

### Payment Manipulation (4 bugs)
All at `https://merchant.bolt.com/api/v1/payments`:
1. Negative amount (-100)
2. Zero amount (0)
3. Minimal amount (0.01)
4. Excessive amount (999999999)

## Next Steps

**BEFORE SUBMISSION:**

1. **Verify Scope**: 
   - Check if `merchant.bolt.com` belongs to Bolt Technology OÜ
   - Check if Bolt Payments has a separate bug bounty program
   - Verify if `merchant.bolt.com` should be in scope

2. **If merchant.bolt.com is OUT OF SCOPE**:
   - These findings may belong to a different company (Bolt Payments)
   - Need to find the correct bug bounty program
   - Or verify if Bolt Technology OÜ accepts out-of-scope findings (marked as "not applicable")

3. **If merchant.bolt.com should be IN SCOPE**:
   - Verify bugs are still exploitable
   - Create proper Bugcrowd submissions
   - Submit through Bugcrowd platform

## Bugcrowd Program Details

- **Program**: Bolt Technology OÜ
- **URL**: https://bugcrowd.com/engagements/bolt-og
- **Rewards**: $150 - $6,500
- **Status**: In progress (Public)
- **Scope Rating**: 2 out of 4

## Program Scope (from Bugcrowd)

### In Scope:
- **Mobile**: Bolt Rider (iOS/Android), Bolt Food (iOS/Android)
- **Web**: `*.taxify.eu`, `*.bolt.eu`

### Out of Scope:
- `*.test.bolt.eu`
- `*.test.taxify.eu`
- `business-old.bolt.eu`
- Bolt Driver apps

## Recommendations

1. **DO NOT SUBMIT** until scope is verified
2. Verify if `merchant.bolt.com` belongs to Bolt Technology OÜ
3. Check if Bolt Payments has a separate bug bounty program
4. If submitting to Bolt Technology OÜ, note that `merchant.bolt.com` is not explicitly listed as in-scope

## Files Generated

- Bug reports: `programs/bolt/reports/bolt_bug_*.md`
- Evidence: `programs/bolt/reports/bolt_bug_*_evidence.json`
- Index: `programs/bolt/reports/INDEX.md`

