#!/usr/bin/env python3
"""Check if Kuru contracts are deployed on Monad mainnet"""

import requests

RPC = "https://rpc.monad.xyz"

# Addresses from bug bounty scope (need full addresses)
# The scope shows partial addresses, we need to find full ones

addresses_to_check = {
    # From our previous testing
    "Router_test": "0x1f5A250c4A506DA4cE584173c6ed1890B1bf7187",
    "MarginAccount_test": "0xdDDaBd30785bA8b45e434a1f134BDf304d6125d9",
    "OrderBook_test": "0xa21ca7b4e308e9E2dC4C60620572792634EA21a0",
    "MonadDeployer_test": "0x1D90616Ad479c3D814021b1f4C43b1a2fFf87626",
    "KuruUtils_test": "0xDdAEdbc015fEe6BE50c69Fbf5d771A4563C996B3",
}

def check_contract(name, address):
    """Check if contract has code deployed"""
    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getCode",
        "params": [address, "latest"],
        "id": 1
    }
    try:
        r = requests.post(RPC, json=payload, timeout=10)
        result = r.json().get("result", "0x")
        has_code = len(result) > 2
        code_size = (len(result) - 2) // 2  # Convert hex chars to bytes
        return has_code, code_size
    except Exception as e:
        return False, str(e)

def main():
    print("=" * 60)
    print("KURU CONTRACT DEPLOYMENT CHECK - MONAD MAINNET")
    print("=" * 60)
    print()
    
    deployed = []
    not_deployed = []
    
    for name, addr in addresses_to_check.items():
        has_code, size = check_contract(name, addr)
        if has_code:
            print(f"✅ {name}")
            print(f"   Address: {addr}")
            print(f"   Code size: {size} bytes")
            deployed.append(name)
        else:
            print(f"❌ {name}")
            print(f"   Address: {addr}")
            print(f"   Status: No code deployed")
            not_deployed.append(name)
        print()
    
    print("=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"Deployed: {len(deployed)}")
    print(f"Not deployed: {len(not_deployed)}")
    print()
    
    if not_deployed:
        print("NOTE: Contracts may be deployed at different addresses on mainnet.")
        print("      Check Cantina/docs for updated mainnet addresses.")
        print()
        print("The bug bounty scope mentions these mainnet contracts:")
        print("  - KuruFlowEntrypoint: 0xb3...13cb")
        print("  - KuruFlowRouter: 0x46...7040")
        print("  - KuruAMMVaultImpl: 0xDC...70F4")
        print("  - MarginAccount: 0x2A...90c5")
        print("  - Router: 0xd6...95CC")

if __name__ == "__main__":
    main()
