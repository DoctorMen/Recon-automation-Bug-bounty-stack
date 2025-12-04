#!/usr/bin/env python3
"""
Full pipeline example for Recon Bounty Stack.

This example demonstrates running a complete reconnaissance
workflow with all stages.
"""

import json
from pathlib import Path

from recon_bounty_stack import Pipeline, Config
from recon_bounty_stack.utils.legal import LegalAuthorizationShield


def setup_authorization(target: str, config: Config) -> bool:
    """Create authorization for the target."""
    shield = LegalAuthorizationShield(str(config.auth_dir))
    
    # Check if already authorized
    authorized, _, _ = shield.check_authorization(target)
    if authorized:
        print(f"✅ {target} is already authorized")
        return True
    
    # Create template
    print(f"Creating authorization template for {target}...")
    auth_file = shield.create_authorization_template(target, "Demo Client")
    
    print(f"⚠️  Please edit {auth_file} with proper authorization")
    print("   then run this script again.")
    return False


def main():
    """Run full pipeline example."""
    # Configuration
    config = Config.from_env()
    config.output_dir = Path("./full_pipeline_output")
    config.auth_dir = Path("./authorizations")
    
    # Ensure directories exist
    config.ensure_directories()
    
    # Target to scan (change to your authorized target)
    target = "example.com"
    
    # Check authorization
    if not setup_authorization(target, config):
        return
    
    # Create pipeline
    pipeline = Pipeline(config=config)
    
    # Run full pipeline
    print("\n" + "=" * 60)
    print("Running Full Pipeline")
    print("=" * 60)
    
    results = pipeline.run(
        targets=[target],
        resume=False,
    )
    
    # Handle errors
    if "error" in results:
        print(f"\n❌ Error: {results['error']}")
        return
    
    # Print summary
    print("\n" + "=" * 60)
    print("Pipeline Complete!")
    print("=" * 60)
    
    summary = results.get("summary", {})
    print(f"\nStatistics:")
    print(f"  Subdomains: {summary.get('subdomains', 0)}")
    print(f"  HTTP Endpoints: {summary.get('http_endpoints', 0)}")
    print(f"  Raw Findings: {summary.get('raw_findings', 0)}")
    print(f"  Triaged Findings: {summary.get('triaged_findings', 0)}")
    
    # Severity breakdown
    for sev in ["critical", "high", "medium", "low", "info"]:
        key = f"severity_{sev}"
        count = summary.get(key, 0)
        if count > 0:
            print(f"    - {sev.capitalize()}: {count}")
    
    print(f"\nOutput files in: {config.output_dir}")


if __name__ == "__main__":
    main()
