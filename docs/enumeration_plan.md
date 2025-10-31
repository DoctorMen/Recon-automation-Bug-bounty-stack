## Enumeration Roadmap (Medium–High Impact Focus)

### 1. Pre‑engagement Intake
- **Scope ingestion**: Normalize the in-scope assets (domains, IP ranges, cloud accounts, repositories) into `scope/targets.yaml`. Track ownership, business criticality, and change cadence.
- **Threat modeling**: Identify high-value data flows (auth, payments, PII, integrations). Tag these assets for higher priority in later phases.
- **Rules of engagement**: Document rate limits, prohibited actions, escalation contacts, and safe-harbor language.

### 2. Intelligence Gathering
- **Passive sources**: Use SecurityTrails, crt.sh, Rapid7, Shodan, GitHub, search engines, ASN lookups, Wayback Machine. Capture artifacts in `data/passive/` with timestamps.
- **Change monitoring**: Schedule daily passive sweeps. Diff against stored results to flag new assets automatically.
- **Third-party dependencies**: Enumerate vendors, shared authentication providers, and embedded widgets (SSO, analytics, payment processors) that could introduce shared risk.

### 3. Subdomain & Host Discovery
- **Toolchain**: Combine `subfinder`, `amass`, `assetfinder`, `dnsx`, and certificate transparency enumerators. Merge, deduplicate, and resolve to IPs.
- **Wordlist brute force**: Run `puredns`/`dnsx` with tuned wordlists for specific business verticals (e.g., `admin`, `staging`, `vpn`, `dev`).
- **Filtering**: Store results in `data/subdomains/raw.txt`; resolve live hosts only into `data/subdomains/live.txt`. Maintain metadata for dead hosts to catch reactivations.

### 4. Service & Port Discovery
- **Fast sweep**: Run `masscan` for top TCP/UDP ports per ASN/IP range. Respect bandwidth limits.
- **Deep scan**: Pipe live IPs into `nmap` with `-sV -sC --script vuln` for service fingerprinting, default credential checks, and TLS misconfig analysis.
- **Protocol tagging**: Record discovered protocols (RDP, SSH, MQTT, Redis, etc.) with service banners for vulnerability correlation.

### 5. Web Surface Mapping
- **HTTP probing**: Feed subdomains into `httpx` to identify live web services, capture status codes, titles, tech stacks, TLS info, and response sizes.
- **Crawling**: Use `katana` or `gospider` to discover endpoints, parameters, JS files, sitemap/link structures per host.
- **JavaScript analysis**: Extract endpoints/keys with `linkfinder`, `xnLinkFinder`, or custom regex to find API paths, secrets, third-party services.

### 6. API & Microservice Enumeration
- **OpenAPI discovery**: Search for `/swagger`, `/openapi.json`, GraphQL endpoints. Use `nuclei` templates for known patterns.
- **Endpoint cataloging**: Collect methods, auth requirements, rate limits, and data sensitivity tags for each API. Highlight mutation endpoints and file handlers.
- **Test data**: Prepare benign payload sets per endpoint category (uploads, SSRF candidates, deserialization vectors).

### 7. Storage & Asset Exposure Checks
- **Cloud buckets**: Scan for exposed S3/GCS/Azure Blob buckets named after company patterns using `s3scanner`, `gcp_bucket_finder`, `MicroBurst`.
- **Code/config exposures**: Monitor GitHub, GitLab, Bitbucket, and Paste sites for accidental leaks. Automate using the `trufflehog` CLI and `github-search` scripts.
- **Backup & artifact stores**: Look for `.bak`, `~`, `.old`, `.git`, `.svn`, `/.env` exposures via `ffuf` wordlists.

### 8. Authentication & Access Surface
- **Login tracking**: Record every discovered auth surface (SSO, OAuth, JWT, custom forms). Note MFA stance, password reset behavior, and SSO chaining.
- **Privilege mapping**: Identify roles/groups, escalation possibilities, shared credentials.
- **Session analysis**: Collect cookie flags, token lifetimes, and logout behavior to target session fixation or revocation weaknesses.

### 9. Prioritization & Severity Mapping
- **Risk scoring**: Combine business criticality, exposure level, and change frequency to prioritize testing queue.
- **Medium/High severity focus**: Flag SSRF, RCE, deserialization, auth bypass, account takeover, sensitive data exposure, privilege escalation, and lateral movement vectors.
- **Playbooks**: Maintain playbooks per vulnerability class with tailored payloads/scripts ready for each tech stack.

### 10. Automation & CI
- **Orchestration**: Use `scripts/run_enumeration.py` to coordinate tool execution, normalize output, and push to `data/` directories.
- **Scheduling**: Run via cron/GitHub Actions with environment-specific concurrency and rate limiting.
- **Result storage**: Track raw outputs plus normalized `assets.json` for trending. Use SQLite/JSON for diffing.

### 11. Reporting & Feedback Loop
- **Finding pipeline**: Pipe high-signal findings into triage queue, linking evidence, reproduction steps, and severity rationale.
- **Continuous updates**: Retest closed issues, document false positives, and refine wordlists/tool configs based on outcomes.
- **Stakeholder communication**: Provide weekly summaries covering new assets, critical exposure changes, and pending high-impact tests.

### 12. Operational Hygiene
- **Logging & artifacts**: Keep logs with timestamps, tool versions, and command params for defensibility.
- **Safe guardrails**: Rate-limit scans, honor opt-out signals (RBLs, `scan.txt`), and use tagging to quarantine risky actions.
- **Knowledge base**: Store runbooks, screenshot evidence, and payload libraries in `docs/` for team reuse.
