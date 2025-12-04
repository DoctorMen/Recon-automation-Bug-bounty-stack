<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# SecurityScore - Production Ready

## Files Structure
```
securityscore/
├── index.html          # Main landing page (browser-ready)
├── backend/
│   ├── api.py          # FastAPI backend
│   └── requirements.txt
└── README.md           # Setup guide
```

## Quick Deploy

### Option 1: Static Hosting (GitHub Pages, Netlify, Vercel)
1. Upload `index.html` to static host
2. Update Stripe key in HTML
3. Deploy backend API separately
4. Update API endpoint in HTML (if needed)

### Option 2: Full Stack (Render, Railway, Fly.io)
1. Upload entire `securityscore/` folder
2. Set environment variables
3. Deploy backend API
4. Update frontend to point to backend URL

## Environment Variables
```bash
STRIPE_SECRET_KEY=sk_test_...
STRIPE_PUBLISHABLE_KEY=pk_test_...
```

## Testing
1. Open `index.html` in browser
2. Enter a test website URL
3. Test payment flow (use Stripe test mode)
4. Verify results display

## Production Checklist
- [ ] Replace Stripe test keys with live keys
- [ ] Set up proper CORS origins
- [ ] Add error handling
- [ ] Set up monitoring
- [ ] Add analytics
- [ ] Set up email notifications
- [ ] Add PDF report generation

## Support
Email: support@securityscore.com

