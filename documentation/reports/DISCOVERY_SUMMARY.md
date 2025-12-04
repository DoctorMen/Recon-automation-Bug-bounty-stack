# Robinhood Crypto Discovery Summary

## Overview

Autonomous discovery completed on Dec 1, 2025 at 21:15. Found 292 subdomains/domains.

## Top Scored Targets

Based on scoring algorithm (admin panels: 10, GraphQL: 8, old tech: 7, auth flows: 6):

1. **admin.robinhood.com** (Score: 10) - HTTP 403 (CloudFront)
2. **admin.api.robinhood.com** (Score: 10) - HTTP 403 (CloudFront)
3. **login.robinhood.com** (Score: 6) - HTTP 403 (CloudFront)
4. **login.api.robinhood.com** (Score: 6) - HTTP 403 (CloudFront)
5. **acapi.api.robinhood.com** (Score: 0) - HTTP 403 (CloudFront)

## Key Findings

- **Total discovered**: 292 endpoints
- **Most common response**: HTTP 403 (CloudFront protection)
- **Technology stack**: Primarily Amazon CloudFront, AWS infrastructure
- **Notable services**:
  - affiliates.robinhood.com (HTTPS 200 - Affiliate Program)
  - press.robinhood.com (HTTPS 200 - Press page)
  - status.robinhood.com (HTTPS 200 - Status page)

## Scan Results

### Guided Hunting Results

**Target scanned**: <http://login.robinhood.com>

- **Nuclei scan**: No vulnerabilities found (empty result)
- **Katana crawl**: Only returned CloudFront 403 error page

### Domain Categories

- **API endpoints**: Multiple `*.api.robinhood.com` subdomains
- **Email services**: `*.o6.email.robinhood.com`
- **CDN test endpoints**: akamai-test.*, cdn.*
- **Crypto-specific**: `*.crypto.robinhood.com`
- **Blog/Content**: `*.blog.robinhood.com`, `*.learn.robinhood.com`

## Recommendations

1. Focus on authenticated endpoints that may bypass CloudFront protection
2. Investigate API endpoints for potential business logic flaws
3. Check affiliate and press pages for potential XSS or injection vulnerabilities
4. Monitor status page for potential information disclosure

## Next Steps

1. Run deeper scans on selected targets (e.g., admin.api.robinhood.com)
2. Perform authenticated testing if credentials are available
3. Check for subdomain takeover possibilities on unused endpoints
4. Analyze JavaScript files for exposed API keys or endpoints
