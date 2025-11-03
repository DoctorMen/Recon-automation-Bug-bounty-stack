## Consent & Scope — Google Form Template

Create a new Google Form with the following fields (all Required unless noted):

1) Company details
- Company / Organization (Short answer)
- Authorized Signer Full Name (Short answer)
- Title / Role (Short answer)
- Work Email (Short answer, response validation: email)

2) Scope
- Domains (Paragraph; explicit list, one per line)
- IP Ranges (Paragraph; e.g., 203.0.113.0/24; one per line; optional)
- In-Scope Applications / API base URLs (Paragraph; optional)
- Out-of-Scope Assets (Paragraph; optional)

3) Testing Window & Rate Limits
- Testing Start (Date)
- Testing End (Date)
- Preferred Daily Time Window (Short answer; e.g., 08:00–18:00 PT)
- Rate-Limit Preference (Multiple choice): Conservative / Standard / Aggressive (read‑only)

4) Legal Consent
- Checkbox: “I am authorized to permit external, non‑intrusive security testing only within the scope listed above.”
- Checkbox: “No production‑impacting or intrusive techniques are authorized. Read‑only recon only.”
- Checkbox: “I understand findings may include URLs, headers, and public metadata.”

5) Delivery & Contact
- Secondary Contact Email(s) (Short answer; optional)
- Phone/Signal (Short answer; optional)

Form Settings
- Collect email addresses: Enabled
- Confirmation message: “Thanks — a signed PDF with your scope and consent will be emailed shortly.”
- Trigger Apps Script on submit (see `docs/apps_script/consent_pdf_email.gs`).

Linking in `landing.html`
- Replace `GOOGLE_FORM_URL_HERE` with your Form’s public URL.


