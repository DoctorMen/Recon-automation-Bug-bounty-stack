# SSRF Baseline Checklist

Purpose: provide a repeatable, high-ROI workflow for finding and reporting
Server-Side Request Forgery (SSRF) issues in web applications and APIs.

This baseline is aligned with:
- **CWE-918**: Server-Side Request Forgery (SSRF)
- **CWE-610**: Externally Controlled Reference to a Resource in Another Sphere
- **CWE-200**: Exposure of Sensitive Information to an Unauthorized Actor

You will typically run this on high-value, URL-taking features:
- Image / avatar URLs (imageUrl, logoUrl, bannerUrl)
- Webhook URLs and integration endpoints
- "Import from URL" features (PDF, screenshot, HTML importers)
- Screenshot / thumbnail generators
- "Test connection" / "Ping URL" admin tools

---

## 1. Map potential SSRF entrypoints

- [ ] In the UI and DevTools Network tab, list features that:
  - Accept a full URL as input (query/body/header/JSON/GraphQL).
  - Fetch remote content (images, files, feeds) on behalf of the user.
- [ ] Pay attention to parameters like:
  - `imageUrl`, `logoUrl`, `url`, `target`, `webhook`, `callback`, `feedUrl`, `importUrl`.
- [ ] Note where the server later uses that input:
  - As an HTTP client argument (curl, requests, urllib, HttpClient).
  - In background jobs, workers, or "test" buttons.

---

## 2. Establish baseline behaviour

For each candidate endpoint:

- [ ] Send a request using a benign external URL, e.g. `https://example.org/logo.png`.
- [ ] Observe and record:
  - Status code and response body.
  - Any side effects (image appears, job created, log entry, etc.).
  - Timing characteristics (fast/slow).

Capture one **golden request/response** per endpoint; store in your notes or as
input for the SSRF report generator later.

---

## 3. Test controlled internal targets

Carefully and within scope, replace the URL with internal targets.

Common internal targets to try (only if allowed by program policy):

- [ ] Loopback and local services
  - `http://127.0.0.1/`
  - `http://localhost/`
  - `http://127.0.0.1:80/`, `:443`, or app-specific ports if documented.

- [ ] Cloud metadata services
  - AWS: `http://169.254.169.254/latest/meta-data/`
  - GCP: `http://169.254.169.254/computeMetadata/v1/` with header `Metadata-Flavor: Google`
  - Azure: `http://169.254.169.254/metadata/instance?api-version=2021-02-01` with header `Metadata: true`

- [ ] Known internal hostnames (only if mentioned in documentation or responses)
  - e.g. `http://internal-service/`, `http://admin.internal/`

Observe for each:

- [ ] Does the response content change (metadata, HTML from internal apps)?
- [ ] Do status codes or headers change in a way that proves an internal request?
- [ ] Do timing changes (longer/shorter) clearly correlate with internal hits vs external?

---

## 4. Apply syntax-confusion payloads (optional, advanced)

To bypass naive filtering or normalization, try a few advanced variants:

- [ ] Leading spaces or odd characters in URLs (Parser confusion):
  - `" http://127.0.0.1/"` (space before scheme)
- [ ] Port normalization tricks for URL parsers:
  - `http://example.com:000443/`
  - `http://example.com:000123:443/`
- [ ] file:// URIs with host component (from syntax-confusion research):
  - `file:///etc/passwd`
  - `file://127.0.0.1/etc/passwd`
- [ ] Mixed-encoding or encoded delimiters when allowed:
  - `%0d%0a` sequences or encoded characters in the path/query.

Use these only to the extent allowed by scope and program rules; the goal is to
identify SSRF behaviour, not to brute-force or stress the target.

---

## 5. Confirm impact

Once you see evidence of SSRF, evaluate impact:

- [ ] Can you retrieve sensitive data (e.g., credentials, tokens, config)?
- [ ] Can you reach internal admin panels or APIs that should not be accessible?
- [ ] Can you pivot into further bugs (e.g., deserialization, XSS, RCE behind the SSRF)?

Document at least one clear, reproducible scenario that demonstrates real
security impact, not just "open redirect-like" behaviour.

---

## 6. Prepare evidence for reporting

For the final report, you will want:

- [ ] One **benign request/response pair** showing normal behaviour.
- [ ] One or more **SSRF request/response pairs** showing internal access.
- [ ] A short, numbered "Steps to Reproduce" that a triager can follow.
- [ ] A precise description of the impacted asset and parameter.

Once you have these, you can create a JSON file like `output/example_ssrf.json`,
update it with your real data, and run:

```bash
python3 scripts/generate_ssrf_report.py --input output/example_ssrf.json
```

This will generate a ready-to-paste Markdown report in `output/reports/` that
maps the finding to CWE-918/CWE-610 and includes your evidence, while keeping
you in full control before submission.
