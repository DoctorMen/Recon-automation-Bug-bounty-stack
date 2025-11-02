# Licensing README (Model #2: Training & System Licensing)

This folder contains the materials to sell and deliver the Bug Bounty Automation System as a licensed product.

## What to Sell
- Basic: $97/month – system access, monthly updates, email support (48h)
- Pro: $297/month – weekly updates, priority support (24h), group Q&A monthly
- Enterprise: $997/month – custom features, monthly 1:1, white-label option

## What Customers Receive
1. Download `system_release_*.zip` (built by `scripts/package_system.py`)
2. Read and accept `EULA_COMMERCIAL_LICENSE.md`
3. Add `.license` file (provided privately) to the repo root
4. Run: `python run_pipeline.py`

## How to Package (Owner)
```bash
python3 scripts/package_system.py
```
The script creates `dist/system_release_YYYYMMDD_HHMM.zip` excluding `output/`, `.git/`, `.license`, etc.

## License Keys
- Generate: `python3 license_check.py generate`
- Save the printed key as `.license` on the customer’s machine
- Keep the SHA256 hash private; rotate if compromised

## Sales Assets
- `SALES_PAGE_COPY.md` – paste into Gumroad/Teachable/Lemon Squeezy
- `EMAIL_SEQUENCE.md` – onboarding sequence (days 1, 3, 5, 7, 14)

## Compliance Notes
- System is for authorized testing only; customers must follow program scopes
- Include OSS licenses as needed; you are licensing your automation and methodology

## Support Workflow
- Basic: email support within 48 hours
- Pro: email within 24 hours + monthly group Q&A
- Enterprise: dedicated email + monthly 1:1 + custom requests

---
Owner: DoctorMen • Contact: doctormen131@outlook.com



