#!/usr/bin/env python3
"""
Basic scan example for Recon Bounty Stack.

This example demonstrates how to run a simple scan
using the Python API.
"""

from pathlib import Path

from recon_bounty_stack import Pipeline, Config


def main():
    """Run a basic scan example."""
    # Create configuration
    config = Config.from_env()
    config.output_dir = Path("./example_output")
    
    # Ensure authorization exists (create template if needed)
    config.auth_dir.mkdir(parents=True, exist_ok=True)
    
    # Create pipeline
    pipeline = Pipeline(config=config, dry_run=True)  # dry_run=True for demo
    
    # Define targets (must be authorized)
    targets = ["example.com"]
    
    # Run scan
    print("Starting basic scan...")
    results = pipeline.run(
        targets=targets,
        skip_auth=True,  # Only for demo - never skip in production!
    )
    
    # Print results
    print("\nScan Results:")
    print(f"  Duration: {results.get('duration_seconds', 0):.1f}s")
    print(f"  Stages completed: {results['summary'].get('stages_completed', 0)}")
    
    for stage_name, stage_data in results.get("stages", {}).items():
        status = "✅" if stage_data.get("completed") else "❌"
        print(f"  {status} {stage_name}: {stage_data.get('duration', 0):.1f}s")


if __name__ == "__main__":
    main()
