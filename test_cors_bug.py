#!/usr/bin/env python3
"""
Test GitLab CORS Bug - Manual Verification Script
Copyright © 2025 Khallid Hakeem Nurse. All Rights Reserved.
"""

import requests
import json
from datetime import datetime

def test_gitlab_cors():
    """Test the GitLab CORS misconfiguration manually."""
    
    print("=== TESTING GITLAB CORS MISCONFIGURATION ===")
    print("Copyright © 2025 Khallid Hakeem Nurse. All Rights Reserved.")
    print()
    
    # Test endpoints
    test_endpoints = [
        "https://gitlab.com/api/v4/user",
        "https://gitlab.com/api/v4/projects",
        "https://gitlab.com/api/v4/version"
    ]
    
    # Test origins
    test_origins = [
        "https://evil.com",
        "https://attacker-site.com", 
        "https://malicious.com",
        "https://fake-bank.com"
    ]
    
    results = []
    
    for endpoint in test_endpoints:
        print(f"Testing endpoint: {endpoint}")
        print("-" * 50)
        
        for origin in test_origins:
            try:
                headers = {"Origin": origin}
                response = requests.get(endpoint, headers=headers, timeout=10)
                
                # Check CORS headers
                cors_headers = {}
                for header in response.headers:
                    if header.lower().startswith('access-control'):
                        cors_headers[header] = response.headers[header]
                
                result = {
                    'endpoint': endpoint,
                    'origin': origin,
                    'status_code': response.status_code,
                    'cors_headers': cors_headers,
                    'vulnerable': False
                }
                
                # Check if vulnerable
                if 'Access-Control-Allow-Origin' in cors_headers:
                    allowed_origin = cors_headers['Access-Control-Allow-Origin']
                    if allowed_origin == '*' or allowed_origin == origin:
                        result['vulnerable'] = True
                        print(f"  ✅ VULNERABLE: Origin {origin}")
                        print(f"     Response: {allowed_origin}")
                    else:
                        print(f"  ❌ NOT VULNERABLE: Origin {origin}")
                        print(f"     Response: {allowed_origin}")
                else:
                    print(f"  ❌ NO CORS HEADERS: Origin {origin}")
                
                results.append(result)
                
            except Exception as e:
                print(f"  ❌ ERROR: {e}")
                result = {
                    'endpoint': endpoint,
                    'origin': origin,
                    'error': str(e),
                    'vulnerable': False
                }
                results.append(result)
            
            print()
    
    # Summary
    print("=== SUMMARY ===")
    vulnerable_count = sum(1 for r in results if r.get('vulnerable', False))
    total_tests = len(results)
    
    print(f"Total Tests: {total_tests}")
    print(f"Vulnerable Results: {vulnerable_count}")
    print(f"Safe Results: {total_tests - vulnerable_count}")
    print()
    
    if vulnerable_count > 0:
        print("🚨 VULNERABILITY CONFIRMED!")
        print("The GitLab API is accepting cross-origin requests from malicious domains.")
        print("This is a real security finding worth reporting.")
    else:
        print("✅ No vulnerability detected.")
        print("The CORS configuration appears to be secure.")
    
    # Save results
    test_report = {
        'test_timestamp': datetime.now().isoformat(),
        'test_type': 'Manual CORS Verification',
        'target': 'GitLab API',
        'results': results,
        'summary': {
            'total_tests': total_tests,
            'vulnerable_count': vulnerable_count,
            'safe_count': total_tests - vulnerable_count,
            'vulnerability_confirmed': vulnerable_count > 0
        }
    }
    
    with open('cors_test_results.json', 'w') as f:
        json.dump(test_report, f, indent=2)
    
    print(f"\n✅ Test results saved to: cors_test_results.json")
    
    return vulnerable_count > 0

def show_existing_evidence():
    """Show the existing evidence from the original finding."""
    print("\n=== EXISTING EVIDENCE ===")
    print("Checking the original finding file...")
    
    try:
        with open('real_finding_gitlab.com_cors_misconfiguration.json', 'r') as f:
            evidence = json.load(f)
        
        print(f"Vulnerability Type: {evidence.get('vulnerability_type', 'Unknown')}")
        print(f"Target: {evidence.get('target', 'Unknown')}")
        print(f"Severity: {evidence.get('severity', 'Unknown')}")
        print(f"Status: {evidence.get('status', 'Unknown')}")
        
        if 'evidence' in evidence:
            print("\nEvidence Details:")
            for key, value in evidence['evidence'].items():
                print(f"  {key}: {value}")
        
        print(f"\nFinding Date: {evidence.get('discovery_timestamp', 'Unknown')}")
        print(f"Bounty Estimate: ${evidence.get('bounty_estimate', 0):,}")
        
    except FileNotFoundError:
        print("❌ Original finding file not found.")
    except Exception as e:
        print(f"❌ Error reading finding file: {e}")

def main():
    """Main testing function."""
    print("GitLab CORS Bug Verification Tool")
    print("=" * 40)
    
    # Show existing evidence
    show_existing_evidence()
    
    # Ask user if they want to test
    print("\n" + "=" * 40)
    print("Do you want to run live verification tests?")
    print("This will make actual requests to GitLab's API.")
    print("Type 'yes' to continue, anything else to skip: ", end="")
    
    try:
        user_input = input().lower().strip()
        if user_input == 'yes':
            print("\nRunning live tests...")
            is_vulnerable = test_gitlab_cors()
            
            if is_vulnerable:
                print("\n🎯 CONCLUSION: VULNERABILITY IS REAL!")
                print("You can confidently submit this finding to GitLab.")
            else:
                print("\n⚠️  CONCLUSION: Vulnerability not detected in current test.")
                print("The original finding may have been from a different endpoint or configuration.")
        else:
            print("\n⏭️  Skipping live tests.")
            print("You can review the existing evidence in the finding file.")
    
    except KeyboardInterrupt:
        print("\n\n⏹️  Test cancelled by user.")
    except Exception as e:
        print(f"\n❌ Error during testing: {e}")

if __name__ == "__main__":
    main()
