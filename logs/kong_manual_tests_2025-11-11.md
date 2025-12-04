# Kong Konnect Manual Testing Log — 2025-11-11

**Researcher:** shadowstep_131 (HackerOne)
**Secondary account:** shadowstep_alt (invite-only)
**Time window:** 13:55–18:00 EST
**Scope reference:** https://hackerone.com/kong
**Required header:** `X-HackerOne-Research: shadowstep_131`

---

## Test Summary

| Timestamp (EST) | Endpoint / Flow | Tamper Action | Result | Notes |
|-----------------|-----------------|---------------|--------|-------|

---

## Outstanding / Next Actions

- Provision Konnect workspace (Owner) and invite secondary account (Viewer/Member).
- Capture invite and acceptance flows with Burp (header injected).
- Run auth tamper checklist on:
  - Workspace membership invites and role changes.
  - Control plane configuration APIs (services/routes/plugins).
  - Secrets/certificates management endpoints.
- Log each attempt immediately (timestamp, request, response).
- Export Burp project snapshots for evidence.

---

_All requests executed manually via Burp Suite per program policy. Automated scanners disabled._
