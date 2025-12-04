#!/bin/bash
# Kuru DEX Foundry Fork Setup Script

set -e

echo "=================================="
echo "  KURU DEX FOUNDRY FORK SETUP"
echo "=================================="
echo ""

# Check if forge is installed
if ! command -v forge &> /dev/null; then
    echo "Installing Foundry..."
    curl -L https://foundry.paradigm.xyz | bash
    source ~/.bashrc
    foundryup
fi

echo "Forge version:"
forge --version

# Initialize if needed
if [ ! -f "lib/forge-std/src/Test.sol" ]; then
    echo ""
    echo "Installing forge-std..."
    forge install foundry-rs/forge-std --no-git --no-commit
fi

# Build
echo ""
echo "Building contracts..."
forge build

# Run tests against Monad fork
echo ""
echo "=================================="
echo "  RUNNING FORK TESTS"
echo "=================================="
echo ""

echo "Testing MarginAccount Access Control..."
forge test --fork-url https://rpc.monad.xyz --match-test test_CreditUser_AccessControl -vvv 2>&1 || true

echo ""
echo "Testing DebitUser Access Control..."
forge test --fork-url https://rpc.monad.xyz --match-test test_DebitUser_AccessControl -vvv 2>&1 || true

echo ""
echo "Testing UpdateMarkets Access Control..."
forge test --fork-url https://rpc.monad.xyz --match-test test_UpdateMarkets_AccessControl -vvv 2>&1 || true

echo ""
echo "Testing Array Mismatch..."
forge test --fork-url https://rpc.monad.xyz --match-test test_AnyToAnySwap_ArrayMismatch -vvv 2>&1 || true

echo ""
echo "Testing Flip Order Price Bounds..."
forge test --fork-url https://rpc.monad.xyz --match-test test_FlipOrder_ExtremePriceBounds -vvv 2>&1 || true

echo ""
echo "=================================="
echo "  FORK TESTS COMPLETE"
echo "=================================="
echo ""
echo "Check output above for CRITICAL findings!"
echo "If any test shows '!!! CRITICAL !!!', we found a vulnerability."
