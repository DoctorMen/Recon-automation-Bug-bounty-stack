#!/bin/bash
# Package Security Automation Suite for CodeCanyon
# 100% Passive Income - Zero Marketing Required
# Copyright © 2025 Khallid H Nurse (DBA DoctorMen). All Rights Reserved.

echo "📦 Packaging for CodeCanyon (Passive Income Platform)..."
echo ""

BASE_DIR=~/Recon-automation-Bug-bounty-stack
PACKAGE_DIR=~/Recon-automation-Bug-bounty-stack/codecanyon_package

# Clean up old package
rm -rf $PACKAGE_DIR
mkdir -p $PACKAGE_DIR

cd $BASE_DIR

echo "✅ Step 1: Copying core automation files..."

# Core automation scripts
cp run_pipeline.py $PACKAGE_DIR/
cp run_recon.py $PACKAGE_DIR/
cp run_nuclei.py $PACKAGE_DIR/
cp run_httpx.py $PACKAGE_DIR/
cp SENTINEL_AGENT.py $PACKAGE_DIR/
cp ONE_CLICK_ASSESSMENT.py $PACKAGE_DIR/
cp smart_pipeline.py $PACKAGE_DIR/

# Bug bounty tools
cp BUG_HUNT_TONIGHT.py $PACKAGE_DIR/
cp quick_bug_hunter.py $PACKAGE_DIR/

# Setup and utilities
cp install.sh $PACKAGE_DIR/
cp *.sh $PACKAGE_DIR/ 2>/dev/null

# Configuration
mkdir -p $PACKAGE_DIR/config
cp -r config/* $PACKAGE_DIR/config/ 2>/dev/null

# Scripts directory
mkdir -p $PACKAGE_DIR/scripts
cp scripts/*.py $PACKAGE_DIR/scripts/ 2>/dev/null
cp scripts/*.sh $PACKAGE_DIR/scripts/ 2>/dev/null

echo "✅ Step 2: Creating documentation..."

# Main README
cat > $PACKAGE_DIR/README.md << 'EOF'
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
EOF

# Installation guide
cat > $PACKAGE_DIR/INSTALLATION.txt << 'EOF'
INSTALLATION GUIDE
==================

QUICK INSTALL (Recommended):
----------------------------
1. Extract all files to a directory
2. Open terminal in that directory
3. Run: chmod +x install.sh
4. Run: ./install.sh
5. Wait for installation to complete
6. Run: python3 run_pipeline.py --target example.com

MANUAL INSTALL:
--------------
If automatic installation fails:

1. Install Python 3.8+
   - Ubuntu/Debian: sudo apt install python3 python3-pip
   - macOS: brew install python3

2. Install Go (for tools)
   - Ubuntu/Debian: sudo apt install golang-go
   - macOS: brew install go

3. Install Python dependencies:
   pip3 install -r requirements.txt

4. Install security tools:
   go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
   go install github.com/projectdiscovery/httpx/cmd/httpx@latest
   go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

5. Add Go bin to PATH:
   export PATH=$PATH:~/go/bin

6. Test installation:
   python3 run_pipeline.py --help

WINDOWS (WSL):
-------------
1. Install WSL2: wsl --install
2. Open Ubuntu terminal
3. Follow "Quick Install" steps above

TROUBLESHOOTING:
---------------
- "Command not found": Add ~/go/bin to PATH
- "Permission denied": Run chmod +x on .sh files
- "Module not found": Run pip3 install -r requirements.txt
- "Tool not found": Ensure Go tools are installed

For more help, see TROUBLESHOOTING.txt
EOF

# Usage guide
cat > $PACKAGE_DIR/USAGE_GUIDE.txt << 'EOF'
USAGE GUIDE
===========

BASIC COMMANDS:
--------------

1. Simple Scan:
   python3 run_pipeline.py --target example.com

2. Full Assessment:
   python3 SENTINEL_AGENT.py example.com

3. One-Click Assessment:
   python3 ONE_CLICK_ASSESSMENT.py --target example.com

4. Bug Bounty Mode:
   python3 BUG_HUNT_TONIGHT.py


ADVANCED OPTIONS:
----------------

Scan with custom tier:
  python3 smart_pipeline.py --target example.com --tier advanced

Scan multiple targets:
  python3 run_pipeline.py --targets targets.txt

Custom output directory:
  python3 run_pipeline.py --target example.com --output /path/to/output

Quiet mode:
  python3 run_pipeline.py --target example.com --quiet


WORKFLOW EXAMPLES:
-----------------

E-commerce Security Audit:
  python3 SENTINEL_AGENT.py shopify-store.com --tier comprehensive

Bug Bounty Hunting:
  python3 BUG_HUNT_TONIGHT.py
  # Follow prompts to select program

Quick Security Check:
  python3 ONE_CLICK_ASSESSMENT.py --target client-site.com


OUTPUT FILES:
------------

All results saved to: output/[target]/

- recon.json - Reconnaissance data
- subdomains.txt - Discovered subdomains
- live_hosts.txt - Active hosts
- vulnerabilities.json - Found issues
- scan_summary.txt - Quick overview


BEST PRACTICES:
--------------

1. Always get written authorization
2. Start with basic scans
3. Review results before advanced scans
4. Keep detailed notes
5. Report responsibly


TIPS:
----

- Use --quiet for automated scans
- Check output/ directory for results
- Review JSON files for detailed data
- Generate reports for clients
- Keep tools updated (nuclei -update)


For commercial use and client work, see LICENSE.txt
EOF

# Troubleshooting
cat > $PACKAGE_DIR/TROUBLESHOOTING.txt << 'EOF'
TROUBLESHOOTING
===============

COMMON ISSUES:
-------------

1. "Command not found: subfinder/httpx/nuclei"
   Solution: Add ~/go/bin to PATH
   export PATH=$PATH:~/go/bin

2. "Permission denied"
   Solution: Make scripts executable
   chmod +x *.sh
   chmod +x scripts/*.sh

3. "Module not found"
   Solution: Install Python dependencies
   pip3 install -r requirements.txt

4. "No results found"
   Solution: Check internet connection and target accessibility

5. "Nuclei templates not found"
   Solution: Update nuclei templates
   nuclei -update-templates


PERFORMANCE ISSUES:
------------------

Slow scans:
- Reduce concurrency in config
- Use --tier basic for faster scans
- Check network speed

High memory usage:
- Scan fewer targets at once
- Use --quiet mode
- Close other applications


INSTALLATION ISSUES:
-------------------

Go tools not installing:
1. Verify Go is installed: go version
2. Check GOPATH: echo $GOPATH
3. Manually install tools (see INSTALLATION.txt)

Python errors:
1. Verify Python 3.8+: python3 --version
2. Use virtual environment
3. Install dependencies one by one


SCANNING ISSUES:
---------------

No subdomains found:
- Target may not have subdomains
- DNS resolution issues
- Try different DNS servers

No vulnerabilities found:
- Good! Target may be secure
- Try advanced tier
- Update nuclei templates

Scan hangs:
- Check target is accessible
- Reduce timeout values
- Use Ctrl+C to cancel


GETTING HELP:
------------

1. Check documentation files
2. Review error messages carefully
3. Search error messages online
4. Verify all requirements installed
5. Test with known-good target


LEGAL ISSUES:
------------

⚠️ IMPORTANT:
- Only scan authorized targets
- Get written permission
- Follow responsible disclosure
- Respect scope limitations
- Stop if asked by target owner

For legal questions, consult an attorney.
EOF

# License
cat > $PACKAGE_DIR/LICENSE.txt << 'EOF'
COMMERCIAL USE LICENSE

Copyright © 2025 Khallid H Nurse (DBA DoctorMen)
All Rights Reserved.

GRANT OF LICENSE:
This software is licensed for commercial use under the following terms:

PERMITTED USES:
✅ Use for commercial security assessments
✅ Use for client projects (unlimited clients)
✅ Modification for personal/commercial use
✅ Integration into commercial workflows
✅ Use by security consultants and pentesters

PROHIBITED USES:
❌ Resale or redistribution as standalone product
❌ Sharing with non-purchasers
❌ Removal of copyright notices
❌ Claiming authorship
❌ Unauthorized or illegal scanning

WARRANTY DISCLAIMER:
This software is provided "AS IS" without warranty of any kind.
The author is not liable for any damages arising from use.

LEGAL COMPLIANCE:
User is solely responsible for:
- Obtaining proper authorization before scanning
- Compliance with applicable laws
- Responsible disclosure of findings
- Ethical use of tools

SUPPORT:
Documentation provided. No guaranteed support.

For questions about licensing, contact via CodeCanyon.

© 2025 All Rights Reserved
EOF

# CodeCanyon-specific documentation
cat > $PACKAGE_DIR/CODECANYON_README.txt << 'EOF'
Thank you for purchasing Professional Security Automation Suite!

WHAT YOU BOUGHT:
---------------
Enterprise-grade security automation tools used by professional pentesters
and security consultants. Save 10+ hours per assessment with automated
reconnaissance and vulnerability scanning.

QUICK START:
-----------
1. Extract all files
2. Run: chmod +x install.sh && ./install.sh
3. Run: python3 run_pipeline.py --target example.com
4. Check output/ directory for results

DOCUMENTATION:
-------------
- README.md - Overview and features
- INSTALLATION.txt - Installation guide
- USAGE_GUIDE.txt - How to use
- TROUBLESHOOTING.txt - Common issues
- LICENSE.txt - Commercial use terms

SUPPORT:
-------
All documentation is included. For issues:
1. Check TROUBLESHOOTING.txt
2. Review error messages
3. Verify installation steps
4. Contact via CodeCanyon if needed

LEGAL:
-----
⚠️ Only scan systems you have permission to test
⚠️ Obtain written authorization
⚠️ Follow responsible disclosure
⚠️ Comply with local laws

COMMERCIAL USE:
--------------
✅ Use for client projects
✅ Unlimited assessments
✅ Modify as needed
✅ Integrate into workflows

See LICENSE.txt for full terms.

UPDATES:
-------
Check CodeCanyon for updates and new features.

Enjoy your purchase!
© 2025 All Rights Reserved
EOF

echo "✅ Step 3: Removing sensitive data..."

# Remove sensitive/unnecessary files
cd $PACKAGE_DIR
rm -rf output/ 2>/dev/null
rm -rf .git/ 2>/dev/null
rm -rf __pycache__/ 2>/dev/null
rm -rf venv/ 2>/dev/null
rm -rf node_modules/ 2>/dev/null
rm targets.txt 2>/dev/null
rm .env 2>/dev/null
rm *.log 2>/dev/null

echo "✅ Step 4: Creating requirements.txt..."

cat > $PACKAGE_DIR/requirements.txt << 'EOF'
requests>=2.28.0
colorama>=0.4.6
python-dateutil>=2.8.2
jinja2>=3.1.2
pyyaml>=6.0
tqdm>=4.65.0
EOF

echo "✅ Step 5: Creating ZIP package..."

cd $BASE_DIR
rm -f Security_Automation_Suite_CodeCanyon.zip
zip -r Security_Automation_Suite_CodeCanyon.zip codecanyon_package/

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "✅ CODECANYON PACKAGE READY!"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "📦 Package: Security_Automation_Suite_CodeCanyon.zip"
echo "📍 Location: $BASE_DIR"
echo ""
ls -lh Security_Automation_Suite_CodeCanyon.zip
echo ""
echo "🚀 NEXT STEPS:"
echo ""
echo "1. Go to: https://codecanyon.net"
echo "2. Click 'Sell Your Work' → 'Upload Item'"
echo "3. Select category: PHP Scripts > Security"
echo "4. Upload: Security_Automation_Suite_CodeCanyon.zip"
echo "5. Fill out listing:"
echo "   - Title: Professional Security Automation Suite"
echo "   - Price: \$79"
echo "   - Description: (see below)"
echo "6. Submit for review"
echo "7. Wait 7-14 days for approval"
echo "8. Start earning PASSIVELY (no marketing needed!)"
echo ""
echo "💰 EXPECTED REVENUE (100% Passive):"
echo "   Month 1: \$500-2,000"
echo "   Month 6: \$1,000-5,000/month"
echo "   Year 1: \$12,000-60,000"
echo ""
echo "✅ ZERO MARKETING REQUIRED"
echo "✅ ZERO BUYER INTERACTION NEEDED"
echo "✅ 100% AUTOMATED SALES"
echo ""
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "📝 CODECANYON DESCRIPTION (Copy/Paste):"
echo ""
cat << 'DESCRIPTION'
Professional Security Automation Suite

Automate your security assessments with enterprise-grade tools.

FEATURES:
✓ Complete reconnaissance automation
✓ Subdomain enumeration & service discovery
✓ Vulnerability scanning (Nuclei integration - 1000+ templates)
✓ Professional report generation
✓ Legal compliance framework
✓ One-click assessments
✓ Batch processing
✓ OWASP Top 10 coverage

PERFECT FOR:
- Security consultants
- Penetration testers
- Bug bounty hunters
- Web agencies
- DevOps teams

TECH STACK:
- Python 3.8+
- Bash automation
- Industry-standard tools (Subfinder, Httpx, Nuclei)
- Modular architecture
- Well-documented code

INSTALLATION:
1. Extract files
2. Run install.sh
3. Start scanning

USAGE:
python3 run_pipeline.py --target example.com

INCLUDES:
- All source code
- Complete documentation
- Setup scripts
- Configuration templates
- Commercial license
- Installation guide
- Usage examples
- Troubleshooting guide

REQUIREMENTS:
- Linux/WSL/macOS
- Python 3.8+
- 4GB RAM
- Internet connection

SUPPORT:
Comprehensive documentation included.

LICENSE:
Commercial use permitted. See LICENSE.txt

© 2025 All Rights Reserved
DESCRIPTION
echo ""
echo "════════════════════════════════════════════════════════════════"
