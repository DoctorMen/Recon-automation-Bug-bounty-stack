#!/usr/bin/env python3
"""
Copyright (c) 2025 YOUR_NAME_HERE
Proprietary and Confidential
All Rights Reserved

This software is proprietary and confidential.
Unauthorized copying, modification, or distribution is prohibited.

System ID: BB_20251102_5946
Owner: YOUR_NAME_HERE
"""

"""
Speed Optimization Module
Optimizes scanning for high-speed connections while maintaining OPSEC safety
"""

import subprocess
import time
import os
from typing import Dict, Any, Optional
from pathlib import Path

class SpeedOptimizer:
    """
    Optimizes scanning speed based on connection speed
    Maintains OPSEC safety and idempotency
    """
    
    # Speed tiers (Mbps)
    SPEED_TIERS = {
        "slow": {"min": 0, "max": 10, "label": "Slow (<10 Mbps)"},
        "medium": {"min": 10, "max": 50, "label": "Medium (10-50 Mbps)"},
        "fast": {"min": 50, "max": 100, "label": "Fast (50-100 Mbps)"},
        "very_fast": {"min": 100, "max": 500, "label": "Very Fast (100-500 Mbps)"},
        "ethernet": {"min": 500, "max": 10000, "label": "Ethernet/Gigabit (500+ Mbps)"}
    }
    
    # Optimal configurations per speed tier
    SPEED_CONFIGS = {
        "slow": {
            "httpx_rate_limit": 10,
            "httpx_threads": 20,
            "nuclei_rate_limit": 20,
            "nuclei_concurrency": 25,
            "parallel_domains": 1,
            "timeout_multiplier": 1.5
        },
        "medium": {
            "httpx_rate_limit": 25,
            "httpx_threads": 50,
            "nuclei_rate_limit": 30,
            "nuclei_concurrency": 50,
            "parallel_domains": 2,
            "timeout_multiplier": 1.2
        },
        "fast": {
            "httpx_rate_limit": 50,
            "httpx_threads": 100,
            "nuclei_rate_limit": 50,
            "nuclei_concurrency": 100,
            "parallel_domains": 3,
            "timeout_multiplier": 1.0
        },
        "very_fast": {
            "httpx_rate_limit": 100,
            "httpx_threads": 200,
            "nuclei_rate_limit": 75,
            "nuclei_concurrency": 150,
            "parallel_domains": 5,
            "timeout_multiplier": 0.8
        },
        "ethernet": {
            "httpx_rate_limit": 200,  # Still OPSEC-safe (max 200 req/s)
            "httpx_threads": 500,
            "nuclei_rate_limit": 100,
            "nuclei_concurrency": 200,
            "parallel_domains": 10,
            "timeout_multiplier": 0.6
        }
    }
    
    @staticmethod
    def detect_connection_speed() -> Optional[str]:
        """
        Detect connection speed using speed test or estimation
        Returns speed tier or None if detection fails
        """
        # Method 1: Try to detect via ping time to fast servers
        try:
            servers = [
                "8.8.8.8",  # Google DNS
                "1.1.1.1",  # Cloudflare DNS
                "208.67.222.222"  # OpenDNS
            ]
            
            min_latency = float('inf')
            for server in servers:
                try:
                    result = subprocess.run(
                        ["ping", "-c", "3", server],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    if result.returncode == 0:
                        # Parse average latency
                        for line in result.stdout.split('\n'):
                            if 'avg' in line.lower() or 'average' in line.lower():
                                # Extract latency (format varies)
                                import re
                                match = re.search(r'(\d+\.?\d*)/', line)
                                if match:
                                    latency = float(match.group(1))
                                    min_latency = min(min_latency, latency)
                except:
                    continue
            
            # Estimate speed from latency (rough approximation)
            if min_latency < 10:
                return "ethernet"  # Very low latency = likely fast connection
            elif min_latency < 30:
                return "very_fast"
            elif min_latency < 50:
                return "fast"
            elif min_latency < 100:
                return "medium"
            else:
                return "slow"
        except:
            pass
        
        # Method 2: Check if on ethernet (Linux)
        try:
            result = subprocess.run(
                ["ip", "link", "show"],
                capture_output=True,
                text=True,
                timeout=3
            )
            if result.returncode == 0:
                if "ethernet" in result.stdout.lower() or "eth" in result.stdout.lower():
                    # Likely ethernet - assume fast
                    return "ethernet"
        except:
            pass
        
        # Method 3: Default to fast if detection fails
        return "fast"  # Assume decent connection
    
    @staticmethod
    def get_optimized_config(speed_tier: Optional[str] = None, force_tier: Optional[str] = None) -> Dict[str, Any]:
        """
        Get optimized configuration based on connection speed
        """
        if force_tier:
            speed_tier = force_tier
        elif not speed_tier:
            speed_tier = SpeedOptimizer.detect_connection_speed()
        
        if speed_tier not in SpeedOptimizer.SPEED_CONFIGS:
            speed_tier = "fast"  # Default to fast
        
        config = SpeedOptimizer.SPEED_CONFIGS[speed_tier].copy()
        config["speed_tier"] = speed_tier
        config["speed_label"] = SpeedOptimizer.SPEED_TIERS[speed_tier]["label"]
        
        # Add OPSEC safety limits (never exceed these)
        config["opsec_limits"] = {
            "max_rate_limit": 200,  # Never exceed 200 req/s (OPSEC safe)
            "max_threads": 500,  # Reasonable max threads
            "min_delay": 0.005,  # Minimum 5ms between requests (OPSEC)
            "burst_limit": 1000  # Max burst requests
        }
        
        # Ensure we don't exceed OPSEC limits
        config["httpx_rate_limit"] = min(config["httpx_rate_limit"], config["opsec_limits"]["max_rate_limit"])
        config["httpx_threads"] = min(config["httpx_threads"], config["opsec_limits"]["max_threads"])
        
        return config
    
    @staticmethod
    def optimize_for_speed(config: Dict[str, Any], maintain_opsec: bool = True) -> Dict[str, Any]:
        """
        Optimize configuration for speed while maintaining OPSEC
        """
        optimized = config.copy()
        
        if maintain_opsec:
            # Apply OPSEC-safe optimizations
            optimized["parallel_processing"] = True
            optimized["batch_processing"] = True
            optimized["concurrent_scans"] = min(config.get("parallel_domains", 1), 10)  # Max 10 parallel
            
            # Optimize timeouts based on speed
            timeout_multiplier = config.get("timeout_multiplier", 1.0)
            optimized["httpx_timeout"] = max(5, int(10 * timeout_multiplier))
            optimized["nuclei_timeout"] = max(5, int(10 * timeout_multiplier))
            
            # Parallel subdomain enumeration
            optimized["parallel_recon"] = True
            optimized["recon_concurrency"] = min(config.get("parallel_domains", 1), 5)
            
            # Batch HTTP probing
            optimized["batch_size"] = 1000  # Process in batches
            
            # Parallel vulnerability scanning
            optimized["parallel_nuclei"] = True
            optimized["nuclei_workers"] = config.get("nuclei_concurrency", 50)
        
        return optimized
    
    @staticmethod
    def apply_speed_config(config: Dict[str, Any]):
        """
        Apply speed configuration to environment variables
        """
        import os
        
        # Set environment variables for tools
        os.environ["HTTPX_RATE_LIMIT"] = str(config["httpx_rate_limit"])
        os.environ["HTTPX_THREADS"] = str(config["httpx_threads"])
        os.environ["NUCLEI_RATE_LIMIT"] = str(config["nuclei_rate_limit"])
        os.environ["NUCLEI_CONCURRENCY"] = str(config["nuclei_concurrency"])
        
        # Store config for later use
        os.environ["SPEED_TIER"] = config.get("speed_tier", "fast")
        os.environ["SPEED_OPTIMIZED"] = "true"
        
        return config


# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
