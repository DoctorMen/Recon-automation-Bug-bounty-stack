#!/usr/bin/env python3
"""
Recon Bounty Stack - Golden Path Demo Script

Demonstrates the core functionality of the reconnaissance automation
framework in a safe, simulated environment.

Usage:
    python scripts/demo.py --help
    python scripts/demo.py --dry-run
    python scripts/demo.py --simulate
"""

import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

# Add src to path for development
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

try:
    import click
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
except ImportError:
    print("Error: Required packages not installed.")
    print("Run: pip install click rich")
    sys.exit(1)


console = Console()


def create_sample_output(output_dir: Path) -> dict:
    """Create sample output data for demonstration."""
    # Sample subdomains
    subdomains = [
        "www.example.com",
        "api.example.com",
        "mail.example.com",
        "dev.example.com",
        "staging.example.com",
    ]

    # Sample HTTP endpoints
    http_endpoints = [
        {
            "url": "https://www.example.com",
            "status-code": 200,
            "title": "Example Domain",
            "tech": ["nginx", "PHP"],
        },
        {
            "url": "https://api.example.com",
            "status-code": 200,
            "title": "API Gateway",
            "tech": ["nginx", "Node.js"],
        },
        {
            "url": "https://dev.example.com",
            "status-code": 401,
            "title": "Development Server",
            "tech": ["Apache"],
        },
    ]

    # Sample findings
    findings = [
        {
            "template-id": "missing-x-frame-options",
            "host": "https://www.example.com",
            "matched-at": "https://www.example.com",
            "timestamp": datetime.now().isoformat(),
            "info": {
                "name": "Missing X-Frame-Options Header",
                "severity": "medium",
                "description": "The X-Frame-Options header is missing, which may allow clickjacking attacks.",
                "tags": ["headers", "security", "owasp"],
            },
        },
        {
            "template-id": "ssl-weak-cipher",
            "host": "https://api.example.com",
            "matched-at": "https://api.example.com",
            "timestamp": datetime.now().isoformat(),
            "info": {
                "name": "Weak SSL Cipher Detected",
                "severity": "high",
                "description": "The server supports weak SSL ciphers that may be vulnerable.",
                "tags": ["ssl", "tls", "crypto"],
            },
        },
        {
            "template-id": "exposed-debug-endpoint",
            "host": "https://dev.example.com",
            "matched-at": "https://dev.example.com/debug",
            "timestamp": datetime.now().isoformat(),
            "info": {
                "name": "Exposed Debug Endpoint",
                "severity": "critical",
                "description": "A debug endpoint is exposed that may leak sensitive information.",
                "tags": ["exposure", "debug", "sensitive"],
            },
        },
    ]

    return {
        "subdomains": subdomains,
        "http_endpoints": http_endpoints,
        "findings": findings,
    }


def simulate_pipeline(output_dir: Path) -> dict:
    """Simulate a pipeline run with sample data."""
    output_dir.mkdir(parents=True, exist_ok=True)
    sample_data = create_sample_output(output_dir)

    # Write subdomains
    subs_file = output_dir / "subs.txt"
    subs_file.write_text("\n".join(sample_data["subdomains"]))
    console.print(f"✅ Created {subs_file}")

    # Write HTTP endpoints
    http_file = output_dir / "http.json"
    with open(http_file, "w") as f:
        json.dump(sample_data["http_endpoints"], f, indent=2)
    console.print(f"✅ Created {http_file}")

    # Write findings
    findings_file = output_dir / "nuclei-findings.json"
    with open(findings_file, "w") as f:
        json.dump(sample_data["findings"], f, indent=2)
    console.print(f"✅ Created {findings_file}")

    # Triage findings
    triaged = []
    for finding in sample_data["findings"]:
        triaged_finding = finding.copy()
        severity = finding["info"]["severity"]
        score = {"critical": 9, "high": 7, "medium": 5, "low": 3, "info": 1}.get(severity, 1)
        triaged_finding["triage"] = {
            "exploitability_score": score,
            "cvss_score": score * 1.1,
            "priority": "high" if score >= 7 else "medium" if score >= 4 else "low",
        }
        triaged.append(triaged_finding)

    # Write triaged findings
    triage_file = output_dir / "triage.json"
    with open(triage_file, "w") as f:
        json.dump(triaged, f, indent=2)
    console.print(f"✅ Created {triage_file}")

    return sample_data


@click.command()
@click.option(
    "--dry-run",
    is_flag=True,
    help="Show what would be done without executing",
)
@click.option(
    "--simulate",
    is_flag=True,
    help="Create sample output data for demonstration",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(),
    default="./demo_output",
    help="Output directory",
)
def main(dry_run: bool, simulate: bool, output: str) -> None:
    """Recon Bounty Stack - Demo Script

    This script demonstrates the core functionality of the reconnaissance
    automation framework. Use --simulate to create sample output data.

    Examples:

        # Show what would happen
        python scripts/demo.py --dry-run

        # Create sample output data
        python scripts/demo.py --simulate

        # Specify custom output directory
        python scripts/demo.py --simulate --output ./my_output
    """
    output_dir = Path(output)

    console.print(
        Panel.fit(
            "[bold blue]Recon Bounty Stack Demo[/bold blue]\n"
            "Automated Bug Bounty Reconnaissance",
            border_style="blue",
        )
    )
    console.print()

    if dry_run:
        console.print("[yellow]DRY RUN MODE[/yellow]")
        console.print()
        console.print("This demo would:")
        console.print("  1. Create sample subdomain data")
        console.print("  2. Generate HTTP endpoint results")
        console.print("  3. Produce vulnerability findings")
        console.print("  4. Triage and prioritize findings")
        console.print("  5. Generate summary report")
        console.print()
        console.print(f"Output would be written to: {output_dir}")
        return

    if simulate:
        console.print("[green]SIMULATION MODE[/green]")
        console.print(f"Creating sample output in: {output_dir}")
        console.print()

        sample_data = simulate_pipeline(output_dir)

        console.print()
        console.print("[bold]Summary:[/bold]")

        # Create summary table
        table = Table(title="Scan Results")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("Subdomains", str(len(sample_data["subdomains"])))
        table.add_row("HTTP Endpoints", str(len(sample_data["http_endpoints"])))
        table.add_row("Findings", str(len(sample_data["findings"])))

        # Count by severity
        severity_counts = {}
        for finding in sample_data["findings"]:
            sev = finding["info"]["severity"]
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in severity_counts:
                emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "ℹ️"}.get(sev, "")
                table.add_row(f"  {emoji} {sev.capitalize()}", str(severity_counts[sev]))

        console.print(table)

        console.print()
        console.print("[green]✅ Demo complete![/green]")
        console.print(f"Output files are in: {output_dir}")
        return

    # Default: Show help
    console.print("Use --simulate to run the demo with sample data.")
    console.print("Use --dry-run to see what would happen without executing.")
    console.print()
    console.print("For more options, run: python scripts/demo.py --help")


if __name__ == "__main__":
    main()
