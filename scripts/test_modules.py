#!/usr/bin/env python3
"""Test all modules import correctly"""
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
sys.path.insert(0, str(SCRIPT_DIR))

try:
    from bug_verifier import BugVerifier
    print("✅ BugVerifier imported")
except Exception as e:
    print(f"❌ BugVerifier failed: {e}")
    sys.exit(1)

try:
    from advanced_duplicate_filter import AdvancedDuplicateFilter
    print("✅ AdvancedDuplicateFilter imported")
except Exception as e:
    print(f"❌ AdvancedDuplicateFilter failed: {e}")
    sys.exit(1)

try:
    from high_quality_report_generator import HighQualityReportGenerator
    print("✅ HighQualityReportGenerator imported")
except Exception as e:
    print(f"❌ HighQualityReportGenerator failed: {e}")
    sys.exit(1)

try:
    from crypto_vulnerability_scanner import CryptoVulnerabilityScanner
    print("✅ CryptoVulnerabilityScanner imported")
except Exception as e:
    print(f"❌ CryptoVulnerabilityScanner failed: {e}")
    sys.exit(1)

try:
    from process_findings_for_submission import process_findings
    print("✅ process_findings imported")
except Exception as e:
    print(f"❌ process_findings failed: {e}")
    sys.exit(1)

print("\n✅ All modules imported successfully!")

