# Same‑Day Security Surface Check — Launch Guide

1) Replace placeholders
- In `docs/landing.html` set:
  - `stripeCheckoutUrl` → your Stripe Checkout link
  - `googleFormUrl` → your Google Form public URL
- In `docs/TERMS_REFUND.html` and `docs/landing.html` set contact email/phone.

2) Publish landing & flowchart locally
- Windows:
  ```powershell
  Start-Process "\\wsl$\Ubuntu\home\ubuntu\Recon-automation-Bug-bounty-stack\docs\landing.html"
  Start-Process "\\wsl$\Ubuntu\home\ubuntu\Recon-automation-Bug-bounty-stack\docs\flowchart.html"
  ```
- Ubuntu/WSL:
  ```bash
  xdg-open docs/landing.html
  xdg-open docs/flowchart.html
  ```

3) Create the Google Form
- Use `docs/consent_form_template.md` for exact fields and settings.
- Copy the public form URL into `googleFormUrl` in `landing.html`.

4) Add the Apps Script for PDF + email
- In the Form: Extensions → Apps Script → paste `docs/apps_script/consent_pdf_email.gs`.
- Add file `email_template.html` from `docs/apps_script/` as an HTML file.
- Triggers → Add Trigger: `onFormSubmit`, event type: On form submit.
- Set `INTERNAL_EMAIL` and `SENDER_NAME` in the script.

5) Test the end‑to‑end flow (5 minutes)
- Open the landing page, click “Consent & scope form”.
- Submit a test response. Confirm both parties receive the PDF email.

6) Optional: host the pages
- You can serve `docs/` via any static host (GitHub Pages, Netlify, S3) or keep them local.


