# Multi-Target Automated Exploitation Testing

## âœ… EXPANDED SCOPE - NO LONGER JUST BOLT!

### Targets Being Tested:
1. **Stripe** - api.stripe.com
2. **Square** - api.squareup.com
3. **PayPal** - api.paypal.com
4. **Shopify** - api.shopify.com
5. **Bolt** - merchant.bolt.com

### Script Location:
utomated_exploitation_test.py (root directory)

### To Run:


### Results Location:
Each target has its own directory:
- programs/{target}/recon/output/confirmed_exploitable_bugs.json
- programs/{target}/submissions/{target}_bug_*.json

### What It Tests:
1. Sensitive Data Exposure (Credit cards, tokens, emails)
2. Authentication Bypass (Admin endpoints)
3. Payment Manipulation (Amount manipulation)

### Status:
âœ… General-purpose script created
âœ… Tests multiple targets simultaneously
âœ… Generates submissions for each target
âœ… Scalable to add more targets

## Next Steps:
1. Run the script
2. Review findings for each target
3. Add more targets as needed
4. Submit findings to respective bug bounty programs
