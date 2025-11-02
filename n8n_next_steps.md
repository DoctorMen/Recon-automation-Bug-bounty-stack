# n8n Next Steps - After Installation
# ====================================

## Current Status
âœ… n8n is installing via npm (in progress...)

## Once Installation Completes

### Step 1: Start n8n


This will:
- Start n8n server
- Show you the URL (usually http://localhost:5678)
- Display an initial setup wizard

### Step 2: Initial Setup
1. Open browser: http://localhost:5678
2. Create your n8n account (first time only)
3. Set up your user credentials

### Step 3: Import Workflow
1. In n8n dashboard, click **Import** button (top right)
2. Select **Import from File**
3. Choose: workflows/rapyd-hourly-monitor-enhanced.json
4. Click **Import**

### Step 4: Configure Environment Variables
In n8n, go to **Settings â†’ Environment Variables** and add:

- ENABLE_SCREENSHOTS=true
- SCREENSHOT_TARGETS=dashboard.rapyd.net,verify.rapyd.net
- DISCORD_WEBHOOK_URL=your_discord_webhook_url

### Step 5: Configure Credentials
1. Click on **Check Rapyd API Status** node
2. Set up HTTP Header Auth credentials
3. Add header: X-Bugcrowd: Bugcrowd-DoctorMen

### Step 6: Activate Workflow
1. Click **Activate** button on the workflow
2. Test execution to verify it works
3. Workflow will run automatically every hour

## Workflow Files Available
- workflows/rapyd-hourly-monitor-enhanced.json - Enhanced with screenshots
- workflows/rapyd-hourly-monitor.json - Basic version

## Troubleshooting

### If n8n doesn't start:


### If import fails:
- Check workflow file exists: ls workflows/*.json
- Verify JSON is valid: cat workflows/rapyd-hourly-monitor-enhanced.json | jq .

## Success Indicators
âœ… n8n starts without errors
âœ… Can access http://localhost:5678
âœ… Workflow imports successfully
âœ… Can activate workflow
âœ… Workflow executes when triggered
