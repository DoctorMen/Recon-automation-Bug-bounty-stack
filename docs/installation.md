# Installation Guide

This guide covers installing Recon Bounty Stack and its dependencies.

## Requirements

- Python 3.10 or higher
- Go 1.19+ (for external security tools)
- Linux, macOS, or Windows with WSL

## Python Package Installation

### From Source (Recommended for Development)

```bash
# Clone the repository
git clone https://github.com/DoctorMen/Recon-automation-Bug-bounty-stack.git
cd Recon-automation-Bug-bounty-stack

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"
```

### Production Installation

```bash
pip install -e .
```

## External Security Tools

The following tools are required for scanning operations:

### Subfinder (Subdomain Enumeration)

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
```

### httpx (HTTP Probing)

```bash
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### Nuclei (Vulnerability Scanning)

```bash
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Update templates
nuclei -update-templates
```

### DNSx (DNS Resolution) - Optional

```bash
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
```

### Amass (Extended Subdomain Enumeration) - Optional

```bash
go install github.com/owasp-amass/amass/v4/...@master
```

## Verifying Installation

```bash
# Check CLI is available
recon-bounty --version

# Check Python package
python -c "from recon_bounty_stack import Pipeline; print('OK')"

# Check external tools
subfinder -version
httpx -version
nuclei -version
```

## Configuration

1. Copy the environment template:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` with your settings:
   ```bash
   # API Keys (optional)
   HACKERONE_API_KEY=your_key_here
   
   # Tool paths (if not in PATH)
   NUCLEI_PATH=/path/to/nuclei
   
   # Output directory
   OUTPUT_DIR=./output
   ```

## Troubleshooting

### Tools Not Found

If tools are not found, ensure your Go bin directory is in PATH:

```bash
export PATH=$PATH:$(go env GOPATH)/bin
```

Add this to your shell profile (~/.bashrc or ~/.zshrc).

### Permission Denied

Make sure scripts are executable:

```bash
chmod +x scripts/*.sh
```

### Python Version

Ensure you're using Python 3.10+:

```bash
python --version
```

## Next Steps

- Follow the [Quick Start Guide](quickstart.md) for your first scan
- Read the [Architecture Overview](architecture.md) to understand the system
