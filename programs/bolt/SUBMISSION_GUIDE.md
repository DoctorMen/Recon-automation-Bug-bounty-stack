# Bolt Technologies - Bug Submission Guide

## Bugs Found: 8 HIGH Severity

### Authentication Bypass Bugs (4):
1. https://merchant.bolt.com/admin
2. https://merchant.bolt.com/dashboard
3. https://merchant.bolt.com/settings
4. https://merchant.bolt.com/api/admin

### Payment Manipulation Bugs (4):
5. Payment manipulation with negative amount (-100)
6. Payment manipulation with zero amount (0)
7. Payment manipulation with minimal amount (0.01)
8. Payment manipulation with excessive amount (999999999)

## For Each Submission:

### Title:
[Type] - [URL]

### Severity:
HIGH

### Description:
[Type] vulnerability found - [Details]

### Steps to Reproduce:
1. Access: [URL]
2. Observe vulnerability
3. Verify impact

### Impact:
[Type] allows unauthorized access/manipulation

### Evidence:
- Automated testing results
- Response codes
- Payloads tested

## Submission Files:
All JSON files ready in: submissions/bolt_bug_*.json
