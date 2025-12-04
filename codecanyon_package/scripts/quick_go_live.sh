#!/usr/bin/env bash
#!/bin/bash
# Copyright © 2025 DoctorMen. All Rights Reserved.
set -euo pipefail

# 1) Optional config via env vars
if [[ -n "${STRIPE_CHECKOUT_URL:-}" || -n "${STRIPE_EXPRESS_URL:-}" || -n "${STRIPE_MONTHLY_URL:-}" || -n "${GOOGLE_FORM_URL:-}" || -n "${CALENDLY_URL:-}" || -n "${SLOTS_REMAINING:-}" ]]; then
  python3 scripts/config_set.py || true
fi

# 2) Run staging dry-run
bash scripts/run_staging.sh || true

# 3) Package the site
ZIP_PATH=$(bash scripts/package_site.sh)
echo "Packaged site to: $ZIP_PATH"

# 4) Open key pages in Windows (if interop)
bash scripts/open_pages_win.sh landing.html status.html validation_walkthrough.html sample_report.html || true

echo "Quick go-live completed. Upload $ZIP_PATH to your static host or push docs/ to GitHub Pages."



