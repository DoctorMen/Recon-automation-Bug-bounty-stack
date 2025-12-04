#!/usr/bin/env python3
"""
Custom scanner example for Recon Bounty Stack.

This example demonstrates how to extend the BaseScanner
class to create custom scanning functionality.
"""

import json
from pathlib import Path
from typing import Any

from recon_bounty_stack.core.config import Config
from recon_bounty_stack.scanners.base import BaseScanner


class CustomPortScanner(BaseScanner):
    """Example custom scanner for port scanning.
    
    This is a demonstration of how to extend the BaseScanner
    class. In production, you would integrate with a real
    port scanning tool.
    """
    
    # Common ports to check
    COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 8080]
    
    def __init__(self, config: Config | None = None):
        """Initialize the custom scanner.
        
        Args:
            config: Configuration object
        """
        super().__init__(config=config, tool_name="nmap")
    
    def scan(self, targets: list[str]) -> dict[str, Any]:
        """Perform port scanning on targets.
        
        Args:
            targets: List of hostnames or IPs to scan
            
        Returns:
            Dictionary containing scan results
        """
        self.logger.info(f"Starting port scan for {len(targets)} target(s)")
        
        # Ensure output directory exists
        self.config.output_dir.mkdir(parents=True, exist_ok=True)
        
        results = []
        
        for target in targets:
            self.logger.info(f"Scanning {target}...")
            
            # This is a simulation - in production, you would:
            # 1. Run the actual port scanner
            # 2. Parse the output
            # 3. Return structured results
            
            result = {
                "target": target,
                "ports": self._simulate_port_scan(target),
                "scan_time": "simulated",
            }
            results.append(result)
        
        # Write results to file
        output_file = self.config.output_dir / "port-scan.json"
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)
        
        # Calculate statistics
        total_open = sum(len(r["ports"]) for r in results)
        
        self.logger.info(f"Found {total_open} open ports across {len(targets)} targets")
        
        return {
            "results": results,
            "targets_scanned": len(targets),
            "total_open_ports": total_open,
            "output_file": str(output_file),
        }
    
    def _simulate_port_scan(self, target: str) -> list[dict]:
        """Simulate port scanning results.
        
        In production, this would actually scan the target.
        """
        # Simulated results for demo
        import random
        
        open_ports = []
        for port in random.sample(self.COMMON_PORTS, random.randint(2, 5)):
            service = {
                21: "ftp",
                22: "ssh",
                23: "telnet",
                25: "smtp",
                53: "dns",
                80: "http",
                110: "pop3",
                143: "imap",
                443: "https",
                993: "imaps",
                995: "pop3s",
                3306: "mysql",
                8080: "http-proxy",
            }.get(port, "unknown")
            
            open_ports.append({
                "port": port,
                "service": service,
                "state": "open",
            })
        
        return open_ports


def main():
    """Run custom scanner example."""
    # Create configuration
    config = Config.from_env()
    config.output_dir = Path("./custom_scan_output")
    config.ensure_directories()
    
    # Create custom scanner
    scanner = CustomPortScanner(config=config)
    
    # Run scan
    print("Running custom port scanner...")
    print("(This is a simulation for demonstration)")
    print()
    
    results = scanner.scan(["example.com", "test.example.com"])
    
    # Print results
    print(f"Targets scanned: {results['targets_scanned']}")
    print(f"Total open ports: {results['total_open_ports']}")
    print(f"Results saved to: {results['output_file']}")
    
    print("\nSample output:")
    for result in results["results"]:
        print(f"\n  {result['target']}:")
        for port_info in result["ports"]:
            print(f"    - Port {port_info['port']}/{port_info['service']}: {port_info['state']}")


if __name__ == "__main__":
    main()
