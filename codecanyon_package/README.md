# Professional Security Automation Suite

Enterprise-grade security automation tools for penetration testers, security consultants, and bug bounty hunters.

## Features

✅ **Complete Reconnaissance Automation**
- Subdomain enumeration
- Service discovery
- Port scanning
- SSL/TLS analysis
- Technology detection

✅ **Vulnerability Scanning**
- Nuclei integration (1000+ templates)
- Custom vulnerability checks
- OWASP Top 10 coverage
- CVE detection

✅ **Professional Reporting**
- JSON/CSV/PDF output
- Risk scoring
- Remediation guidance
- Executive summaries

✅ **Legal Compliance**
- Authorization tracking
- Scope management
- Audit logging
- GDPR compliance

## Quick Start

### Installation

```bash
chmod +x install.sh
./install.sh
```

### Basic Usage

```bash
# Single target scan
python3 run_pipeline.py --target example.com

# Full assessment
python3 SENTINEL_AGENT.py example.com

# One-click assessment
python3 ONE_CLICK_ASSESSMENT.py --target example.com
```

### Advanced Usage

```bash
# Bug bounty hunting
python3 BUG_HUNT_TONIGHT.py

# Custom pipeline
python3 smart_pipeline.py --target example.com --tier advanced
```

## Requirements

- Linux/WSL/macOS
- Python 3.8+
- 4GB RAM minimum
- Internet connection

## Installation

The install.sh script will automatically install:
- Python dependencies
- Required tools (subfinder, httpx, nuclei)
- Configuration files

## Configuration

Edit `config/` files to customize:
- Scan parameters
- Output formats
- Tool settings
- API keys (optional)

## Output

Results are saved to `output/[target]/`:
- `recon.json` - Reconnaissance data
- `vulnerabilities.json` - Found vulnerabilities
- `report.pdf` - Professional report (if enabled)

## Support

Documentation: See DOCUMENTATION.txt
Issues: Check TROUBLESHOOTING.txt

## License

Commercial use permitted. See LICENSE.txt

## Security Notice

⚠️ Only scan systems you have explicit permission to test.
⚠️ Unauthorized scanning may be illegal in your jurisdiction.
⚠️ Always obtain written authorization before testing.

## Credits

Built with industry-standard tools:
- Subfinder (subdomain enumeration)
- Httpx (HTTP probing)
- Nuclei (vulnerability scanning)
- Custom automation framework

© 2025 All Rights Reserved
