<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# One‑Command Automation

From the repo root:

```bash
# Optional: set config via env vars (keeps docs/config.js in sync)
export STRIPE_CHECKOUT_URL="https://buy.stripe.com/..."
export STRIPE_EXPRESS_URL="https://buy.stripe.com/..."
export STRIPE_MONTHLY_URL="https://buy.stripe.com/..."
export GOOGLE_FORM_URL="https://docs.google.com/forms/.../viewform"
export CALENDLY_URL="https://calendly.com/your-15min-link"
export SLOTS_REMAINING=3

chmod +x scripts/*.sh
bash scripts/quick_go_live.sh
```

What it does:
- Applies config (if env vars present)
- Runs staging dry‑run and prints the latest summary path
- Zips the docs site to `dist/docs-<timestamp>.zip`
- Opens landing, status, validation, and sample report in Windows (if interop enabled)

Manual open if needed (Windows PowerShell):

```powershell
Start-Process "\\wsl$\Ubuntu\home\ubuntu\Recon-automation-Bug-bounty-stack\docs\landing.html"
Start-Process "\\wsl$\Ubuntu\home\ubuntu\Recon-automation-Bug-bounty-stack\docs\status.html"
```



