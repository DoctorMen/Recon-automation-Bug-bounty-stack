# Robinhood Markets Manual Testing Log — 2025-11-11

**Researcher:** shadowstep_131 (HackerOne)
**Secondary account:** shadowstep_alt (invite-only)
**Time window:** 14:05–19:00 EST
**Scope reference:** https://hackerone.com/robinhood
**Required header:** `X-HackerOne-Research: shadowstep_131`

---

## Test Summary

| Timestamp (EST) | Endpoint / Flow | Tamper Action | Result | Notes |
|-----------------|-----------------|---------------|--------|-------|

---

## Outstanding / Next Actions

- Confirm primary and secondary Robinhood test accounts per program rules.
- Capture invite/referral and funding flows with Burp (header injected).
- Run auth tamper checklist on:
  - Account invitations and authorized trader APIs.
  - ACH funding/transfer APIs.
  - Order submission endpoints (equities/options/crypto).
  - Document download URLs (statements, tax forms).
- Log each attempt immediately (timestamp, request, response).
- Export Burp project snapshots for evidence.

---

_Manual testing only; automated scanners disabled per program policy._
