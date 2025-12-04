<!--
Copyright © 2025 DoctorMen. All Rights Reserved.
-->
# Deploy Options (static)

- GitHub Pages
  1. Create a repo and push the `docs/` folder.
  2. In repo Settings → Pages → Deploy from `/docs` folder.
  3. Open `https://<user>.github.io/<repo>/docs/landing.html`.

- Netlify (drag‑and‑drop)
  1. Drag the `docs/` folder into the Netlify dashboard.
  2. Set landing page path to `docs/landing.html`.

- S3/CloudFront
  1. Upload `docs/` to an S3 bucket with static website hosting.
  2. Set index to `landing.html`.

- Local
  - Windows: `Start-Process "\\\\wsl$\\\\Ubuntu\\\\home\\\\ubuntu\\\\Recon-automation-Bug-bounty-stack\\\\docs\\\\landing.html"`
  - Ubuntu/WSL: `xdg-open docs/landing.html`

Update config
- Edit `docs/config.js` to set Stripe URLs, Google Form URL, Calendly link, and `slotsRemaining`.


