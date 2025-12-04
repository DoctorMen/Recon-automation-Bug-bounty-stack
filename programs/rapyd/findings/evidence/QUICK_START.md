<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# IDOR Evidence Capture - Quick Start

## Status: Ready to Execute

âœ… Evidence directory created: programs/rapyd/findings/evidence/
âœ… State tracker initialized: evidence/.capture_state.json
âœ… Process guide available: evidence/IDOR_CAPTURE_PROCESS.md

## Next Steps

### 1. Start Browser Session
- Navigate to: https://dashboard.rapyd.net/login
- Browser is already open at login page

### 2. Login to Account A
- Email: DoctorMen@bugcrowdninja.com
- Password: [Enter password manually]
- After login, take screenshot â†’ Save as: evidence/account_a_dashboard.png

### 3. Follow Process Guide
Open: evidence/IDOR_CAPTURE_PROCESS.md
Follow all 6 steps sequentially.

## Evidence Files to Create

1. account_a_dashboard.png - Account A dashboard screenshot
2. account_b_created.png - Account B creation/login
3. account_b_payment_created.png - Payment creation in Account B
4. idor_account_context.png - Account A accessing Account B payment
5. idor_payment_details.png - Payment details page
6. idor_url_bar.png - URL bar showing Payment ID
7. idor_full_page.png - Full page view
8. idor_request_curl.txt - Network request (cURL)
9. idor_response_raw.json - Raw API response
10. idor_response_redacted.json - Redacted API response

## Quick Commands

Check current state:


Run redaction script (after Step 4):


## Notes
- Browser automation had issues with form fields - manual login required
- All screenshots must show Account A username for context
- Remember to include X-Bugcrowd header in all API requests
