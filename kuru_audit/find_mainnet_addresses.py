#!/usr/bin/env python3
"""
Find Kuru mainnet addresses from partial addresses in bug bounty scope
"""

import requests
import json

RPC = "https://rpc.monad.xyz"

# Partial addresses from bug bounty scope
PARTIAL_ADDRESSES = {
    "KuruFlowEntrypoint": ("0xb3", "13cb"),  # 0xb3...13cb
    "KuruFlowRouter": ("0x46", "7040"),       # 0x46...7040
    "KuruAMMVaultImpl": ("0xDC", "70F4"),     # 0xDC...70F4
    "KuruForwarder": ("0x97", "3FAA"),        # 0x97...3FAA
    "KuruForwarderImpl": ("0xbf", "Fe2A"),    # 0xbf...Fe2A
    "KuruUtils": ("0xD8", "27f6"),            # 0xD8...27f6
    "MarginAccount": ("0x2A", "90c5"),        # 0x2A...90c5
    "MarginAccountImpl": ("0x57", "0ca7"),    # 0x57...0ca7
    "MonadDeployer": ("0xe2", "7D1E"),        # 0xe2...7D1E
    "OrderBookImpl": ("0xea", "23CD"),        # 0xea...23CD
    "Router": ("0xd6", "95CC"),               # 0xd6...95CC
    "RouterImpl": ("0x0F", "A9CD"),           # 0x0F...A9CD
}

def check_address_has_code(address):
    """Check if address has contract code"""
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getCode",
        "params": [address, "latest"],
        "id": 1
    }
    try:
        r = requests.post(RPC, json=payload, timeout=10)
        result = r.json().get("result", "0x")
        return len(result) > 2
    except:
        return False

def brute_force_address(prefix, suffix):
    """
    Try to find full address by brute forcing middle bytes
    This is computationally expensive but can work for short gaps
    """
    # Address format: 0x + 40 hex chars
    # prefix like "0xb3" = 4 chars (including 0x)
    # suffix like "13cb" = 4 chars
    # Need to find 40 - 2 (prefix without 0x) - 4 (suffix) = 34 middle chars
    # This is too many to brute force!
    
    # Instead, let's try common patterns or scan recent transactions
    pass

def scan_recent_deployments():
    """Scan recent blocks for contract deployments"""
    print("Scanning recent blocks for contract creations...")
    
    # Get latest block
    payload = {"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1}
    r = requests.post(RPC, json=payload, timeout=10)
    latest_block = int(r.json().get("result", "0x0"), 16)
    
    print(f"Latest block: {latest_block}")
    
    # This would require scanning many blocks which is slow
    # Better to use an indexer or block explorer API
    return []

def try_known_patterns():
    """Try common address patterns based on partial info"""
    print("="*70)
    print("ATTEMPTING TO RECONSTRUCT MAINNET ADDRESSES")
    print("="*70)
    print()
    
    # The partial addresses suggest a pattern
    # Let's see if we can find any by trying known deployment patterns
    
    found_addresses = {}
    
    for name, (prefix, suffix) in PARTIAL_ADDRESSES.items():
        print(f"Searching for {name}: {prefix}...{suffix}")
        
        # Without a block explorer API, we can't efficiently search
        # But we can document what we need
        
        found_addresses[name] = {
            "prefix": prefix,
            "suffix": suffix,
            "status": "NEEDS_BLOCK_EXPLORER"
        }
    
    return found_addresses

def main():
    print()
    print("="*70)
    print("  KURU MAINNET ADDRESS FINDER")
    print("="*70)
    print()
    
    print("Bug bounty scope shows these partial mainnet addresses:")
    print()
    
    for name, (prefix, suffix) in PARTIAL_ADDRESSES.items():
        print(f"  {name}: {prefix}...{suffix}")
    
    print()
    print("="*70)
    print("PROBLEM: Cannot brute force 34 hex characters")
    print("="*70)
    print()
    print("Options to find full addresses:")
    print("  1. Use Monad block explorer (monadscan.com) - search by partial")
    print("  2. Request addresses via Cantina bug bounty platform")
    print("  3. Contact Kuru team directly")
    print("  4. Find deployment transactions in block explorer")
    print()
    
    # Output addresses for manual lookup
    print("="*70)
    print("MANUAL LOOKUP INSTRUCTIONS")
    print("="*70)
    print()
    print("Go to https://monadscan.com and search for contracts matching:")
    print()
    
    for name, (prefix, suffix) in PARTIAL_ADDRESSES.items():
        # Format for search
        print(f"{name}:")
        print(f"  Starts with: {prefix}")
        print(f"  Ends with: {suffix}")
        print()
    
    # Save partial addresses for reference
    output = {
        "note": "Partial addresses from Kuru bug bounty scope",
        "network": "Monad Mainnet",
        "rpc": RPC,
        "addresses": PARTIAL_ADDRESSES,
        "instructions": "Use monadscan.com to find full addresses"
    }
    
    with open("kuru_audit/partial_addresses.json", "w") as f:
        json.dump(output, f, indent=2)
    
    print("Saved partial addresses to kuru_audit/partial_addresses.json")

if __name__ == "__main__":
    main()
