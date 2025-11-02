# Prepare n8n Setup - While Node.js Compiles
# ===========================================

## âœ… Tasks You Can Do Now

### 1. Get Discord Webhook URL (Required)
- Open Discord
- Go to your server
- Settings â†’ Integrations â†’ Webhooks
- Create New Webhook
- Copy the webhook URL
- Save it somewhere safe (you'll need it for ENABLE_SCREENSHOTS and alerts)

### 2. Review Workflow Files
- Check: workflows/rapyd-hourly-monitor-enhanced.json
- Understand what it does:
  * Hourly cron trigger
  * Rapyd API monitoring
  * Screenshot capture
  * Discord alerts
  * Logging

### 3. Review Documentation
- Read: workflows/SCREENSHOT_FEATURES.md
- Understand idempotent screenshot functionality
- Review configuration options

### 4. Prepare Environment Variables
Write down these values for n8n:
- ENABLE_SCREENSHOTS=true
- SCREENSHOT_TARGETS=dashboard.rapyd.net,verify.rapyd.net
- DISCORD_WEBHOOK_URL=(your webhook URL from step 1)

### 5. Review Rapyd Setup
- Check: programs/rapyd/targets.txt
- Review: programs/rapyd/config.yaml
- Verify: programs/rapyd/permission.txt

### 6. Check Delegation Structure
- Review: delegation/MASTER_PLAN.txt
- Check: delegation/status/composer1_status.txt
- Update status files if needed

### 7. Test Docker (if needed)
- Verify Docker is working: docker ps
- Check Docker images: docker images

## Quick Checklist
- [ ] Discord webhook URL ready
- [ ] Environment variables prepared
- [ ] Workflow files reviewed
- [ ] Rapyd targets verified
- [ ] Documentation read

## Next Steps After Node.js Compiles
1. Load nvm: export NVM_DIR=" C:UsersDoc
