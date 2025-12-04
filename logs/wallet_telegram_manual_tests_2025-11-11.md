# Wallet (Telegram) Manual Testing Log — 2025-11-11

**Researcher:** shadowstep_131 (HackerOne)
**Secondary account:** shadowstep_alt (pending approval)
**Time window:** 14:31–19:30 EST
**Scope reference:** https://hackerone.com/wallet
**Required header:** `X-HackerOne-Research: shadowstep_131`

---

## Test Summary

| Timestamp (EST) | Endpoint / Flow | Tamper Action | Result | Notes |
|-----------------|-----------------|---------------|--------|-------|

---

## Outstanding / Next Actions

- Confirm eligibility/approval for secondary Telegram Wallet account.
- Capture custody sharing or invite flows (if available) via Burp.
- Run tamper checklist on:
  - Wallet invites / shared custody APIs.
  - On-chain transaction signing and broadcast endpoints.
  - Off-ramp/on-ramp funding APIs (fiat ↔ crypto).
  - Notification/document delivery endpoints.
- Log each attempt immediately with timestamp, request, and response snippet.
- Export Burp project snapshots for evidence.

---

_All testing manual per program policy; automated scanners disabled._
