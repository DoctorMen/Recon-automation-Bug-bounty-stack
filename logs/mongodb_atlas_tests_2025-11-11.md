# MongoDB Atlas Manual Testing Log — 2025-11-11

**Researcher:** shadowstep_131 (HackerOne)
**Secondary account:** shadowstep_alt (invite-only)
**Time window:** 11:20–16:20 EST
**Scope reference:** https://hackerone.com/mongodb (Atlas authorization campaign, 1.5× bounty promo)
**Required header:** `X-HackerOne-Research: shadowstep_131`

---

## Test Summary

| Timestamp (EST) | Endpoint / Flow | Tamper Action | Result | Notes |
|-----------------|-----------------|---------------|--------|-------|
| 11:40 | Org & Project setup | Baseline (no tamper) | Success | Created Org A (Owner) and Org B (ReadOnly); captured invitation emails sent to shadowstep_alt account. |
| 12:02 | Project invite acceptance | Baseline (no tamper) | Success | doctormen tester accepted Project Read Only invite; Burp captured POST /api/private/iam/invitations/<id>/accept. |
| 12:25 | POST /v2/automation/changes/<projectId> | Baseline replay | 200 | Owner invited doctormen (Project Read Only). Stored request for tampering. |
| 12:27 | POST /v2/automation/changes/<projectId> | Remove Cookie header | 403 | Invitation rejected when cookies stripped; confirms auth enforcement. |
| 12:30 | POST /v2/automation/changes/<projectId> | roleName → PROJECT_OWNER | 403 | Attempted role escalation during invite denied (JSON error: "role not allowed"). |
| 12:33 | POST /v2/automation/changes/<projectId> | groupId swapped to Org B UUID | 403 | Cross-tenant invite blocked; response: "Group not found". |

---

## Outstanding / Next Actions

- Capture invite/accept flows with Burp (header injected).
- Run auth tamper checklist on:
  - Project membership role changes.
  - Project-level API key usage across orgs.
  - Charts & Data Federation sharing tokens.
- Log each attempt immediately (timestamp, request, response).
- Export Burp project snapshots for evidence.

---

_All requests executed via Burp Suite with manual tampering. Automated scanning disabled per program policy._
