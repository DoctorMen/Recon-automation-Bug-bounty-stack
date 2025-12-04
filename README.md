# Recon Bounty Stack

[![CI](https://github.com/DoctorMen/Recon-automation-Bug-bounty-stack/actions/workflows/ci.yml/badge.svg)](https://github.com/DoctorMen/Recon-automation-Bug-bounty-stack/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: Proprietary](https://img.shields.io/badge/license-Proprietary-red.svg)](./LICENSE)

> **Automated bug bounty reconnaissance toolkit with multi-agent orchestration**

Recon Bounty Stack is a professional-grade reconnaissance automation framework designed for authorized security testing and bug bounty hunting. It combines multiple security tools into a unified pipeline with intelligent triage and reporting.

## ✨ Features

- **🔍 Multi-Tool Reconnaissance** - Integrated subdomain enumeration with Subfinder and Amass
- **🌐 HTTP Probing** - Automatic web endpoint discovery with httpx
- **🔓 Vulnerability Scanning** - Template-based vulnerability detection with Nuclei
- **🤖 Multi-Agent Orchestration** - Coordinated pipeline execution with agent roles
- **⚖️ Legal Authorization System** - Built-in compliance and authorization checks
- **📊 Intelligent Triage** - Automated prioritization and false positive filtering
- **📝 Professional Reports** - Markdown reports with PoC details and remediation

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/DoctorMen/Recon-automation-Bug-bounty-stack.git
cd Recon-automation-Bug-bounty-stack

# Install the package
pip install -e .

# Or with development dependencies
pip install -e ".[dev]"
```

### External Tools

Install required security tools (not included in the package):

```bash
# Using Go
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

### Basic Usage

```bash
# Create authorization (required before scanning)
recon-bounty auth create example.com --client "Your Company"
# Edit the generated JSON file with proper authorization details

# Run a scan
recon-bounty scan example.com --mode quick

# Check status
recon-bounty status

# View help
recon-bounty --help
```

### Python API

```python
from recon_bounty_stack import Pipeline, Config

# Create configuration
config = Config.from_env()

# Initialize pipeline
pipeline = Pipeline(config=config)

# Run scan (requires authorization)
results = pipeline.run(targets=["example.com"])

# Print summary
print(f"Found {results['summary'].get('triaged_findings', 0)} findings")
```

## 📁 Project Structure

```
recon-bounty-stack/
├── src/recon_bounty_stack/       # Main package
│   ├── cli.py                    # Command-line interface
│   ├── core/                     # Core modules (pipeline, config, logger)
│   ├── scanners/                 # Scanner implementations
│   ├── agents/                   # Multi-agent orchestration
│   ├── reports/                  # Report generation
│   └── utils/                    # Utilities (safety, legal, helpers)
├── tests/                        # Test suite
├── docs/                         # Documentation
├── scripts/                      # Utility scripts
├── examples/                     # Example code
└── _archive/                     # Archived original files
```

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        CLI Interface                        │
│                    (recon-bounty scan)                      │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│                  Pipeline Orchestrator                       │
│   ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐       │
│   │  Recon   │→│  HTTPx   │→│  Nuclei  │→│  Triage  │→Report│
│   └──────────┘ └──────────┘ └──────────┘ └──────────┘       │
└─────────────────────┬───────────────────────────────────────┘
                      │
┌─────────────────────▼───────────────────────────────────────┐
│              Legal Authorization Shield                      │
│         (Blocks unauthorized scan attempts)                  │
└─────────────────────────────────────────────────────────────┘
```

## ⚖️ Legal Authorization

**IMPORTANT**: This tool requires written authorization before scanning any target.

1. Create an authorization file:
   ```bash
   recon-bounty auth create target.com --client "Client Name"
   ```

2. Edit the generated JSON file with proper authorization details

3. Get client signature (email confirmation minimum)

4. Only then proceed with scanning

Scanning without proper authorization is a **federal crime** under the CFAA.

## 🧪 Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run tests
make test
# or
pytest tests/ -v --cov=src/recon_bounty_stack

# Run linting
make lint
# or
ruff check src/ tests/

# Format code
make format
# or
black src/ tests/
```

## 📚 Documentation

- [Installation Guide](docs/installation.md)
- [Quick Start Tutorial](docs/quickstart.md)
- [Architecture Overview](docs/architecture.md)
- [API Reference](docs/api-reference.md)
- [Contributing Guide](docs/contributing.md)

## 🤝 Contributing

Contributions are welcome! Please read our [Contributing Guide](docs/contributing.md) for details.

## 📄 License

This software is proprietary and confidential. See [LICENSE](LICENSE) for details.

## ⚠️ Disclaimer

This tool is designed for authorized security testing only. Users are responsible for ensuring they have proper authorization before scanning any targets. The authors are not responsible for any misuse of this tool.

---

**Copyright © 2025 DoctorMen. All Rights Reserved.**
