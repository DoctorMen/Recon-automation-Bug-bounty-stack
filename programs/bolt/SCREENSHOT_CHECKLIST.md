# Bugcrowd Submission Screenshot Checklist

## BUG 1: Authentication Bypass - Admin Endpoint

### Required Screenshots:

âœ… **Screenshot 1: Network Tab Overview**
- URL bar showing: merchant.bolt.com/admin
- Network tab with 'admin' request visible
- Status: 200 OK visible
- Type: document visible
**Status: [ ] Captured**

âœ… **Screenshot 2: Request Headers (No Auth)**
- Click on 'admin' request
- Headers tab â†’ Request Headers section
- Should show NO Authorization header
- Shows the request was made without authentication
**Status: [ ] Captured**

âœ… **Screenshot 3: Response Headers**
- Still on Headers tab
- Response Headers section
- Shows Status: 200 OK
- Content-Type: text/html
**Status: [ ] Captured**

âœ… **Screenshot 4: Response Content**
- Click Response tab
- Shows the HTML content returned
- Proves data was returned (not just an error page)
**Status: [ ] Captured**

âœ… **Screenshot 5: Full Page View (Optional but Recommended)**
- Browser showing the page loaded
- URL bar visible
- Network tab summary showing request count
**Status: [ ] Captured**

### What Makes a Good Submission:

1. **Clear Proof**: Shows endpoint accessible without auth
2. **Status Code**: 200 OK visible (not 401/403)
3. **No Auth Headers**: Request headers show no Authorization token
4. **Response Data**: Shows actual HTML/content returned
5. **Reproducible**: Steps are clear from screenshots

### Common Issues:

âŒ Missing Request Headers (can't prove no auth was used)
âŒ Missing Response tab (can't prove data was returned)
âŒ Unclear URL (hard to see which endpoint)
âŒ Status code not visible (can't prove 200 OK)

