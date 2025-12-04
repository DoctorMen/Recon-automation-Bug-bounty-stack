#!/usr/bin/env python3
"""
PowerShell curl Syntax Fix for GitLab CORS Testing
Copyright © 2025 Khallid Hakeem Nurse. All Rights Reserved.
"""

def get_powershell_fix():
    """Get PowerShell curl syntax correction."""
    
    fix = """
=== POWERSHELL CURL SYNTAX FIX ===

THE ISSUE:
PowerShell's "curl" is actually Invoke-WebRequest, not real curl.
It requires different syntax for headers.

CORRECT POWERSHELL SYNTAX:

METHOD 1 - Using Invoke-WebRequest (PowerShell curl):
```powershell
curl -Headers @{"Origin"="https://evil.com"} https://gitlab.com/api/v4/user
curl -Headers @{"Origin"="https://attacker-site.com"} https://gitlab.com/api/v4/projects
curl -Headers @{"Origin"="https://malicious.com"} https://gitlab.com/api/v4/version
curl -Headers @{"Origin"="https://fake-bank.com"} https://gitlab.com/api/v4/user
```

METHOD 2 - Using Invoke-RestMethod (better for APIs):
```powershell
curl -Method Get -Headers @{"Origin"="https://evil.com"} https://gitlab.com/api/v4/user
curl -Method Get -Headers @{"Origin"="https://attacker-site.com"} https://gitlab.com/api/v4/projects
curl -Method Get -Headers @{"Origin"="https://malicious.com"} https://gitlab.com/api/v4/version
curl -Method Get -Headers @{"Origin"="https://fake-bank.com"} https://gitlab.com/api/v4/user
```

METHOD 3 - Use real curl through WSL (recommended):
```powershell
wsl curl -H "Origin: https://evil.com" https://gitlab.com/api/v4/user
wsl curl -H "Origin: https://attacker-site.com" https://gitlab.com/api/v4/projects
wsl curl -H "Origin: https://malicious.com" https://gitlab.com/api/v4/version
wsl curl -H "Origin: https://fake-bank.com" https://gitlab.com/api/v4/user
```

METHOD 4 - Use real curl directly (if installed):
```powershell
curl.exe -H "Origin: https://evil.com" https://gitlab.com/api/v4/user
curl.exe -H "Origin: https://attacker-site.com" https://gitlab.com/api/v4/projects
curl.exe -H "Origin: https://malicious.com" https://gitlab.com/api/v4/version
curl.exe -H "Origin: https://fake-bank.com" https://gitlab.com/api/v4/user
```

TO SEE RESPONSE HEADERS IN POWERSHELL:

Method 1 - Using Invoke-WebRequest:
```powershell
$response = curl -Headers @{"Origin"="https://evil.com"} https://gitlab.com/api/v4/user
$response.Headers
```

Method 2 - Using WSL curl (recommended):
```powershell
wsl curl -I -H "Origin: https://evil.com" https://gitlab.com/api/v4/user
```

EXPECTED RESULT:
You should see "Access-Control-Allow-Origin: *" in the response headers.

WHY THE ERROR OCCURRED:
- PowerShell curl = Invoke-WebRequest
- -H parameter expects a hashtable, not a string
- Real curl expects -H "Header: Value" format
- Different tools, different syntax

RECOMMENDED APPROACH:
Use WSL curl for exact syntax as shown in the submission template:
```powershell
wsl curl -H "Origin: https://evil.com" https://gitlab.com/api/v4/user
```

This will give you the exact output format shown in the HackerOne submission.
"""
    
    return fix

def get_test_commands():
    """Get ready-to-use PowerShell test commands."""
    
    commands = """
=== READY-TO-USE POWERSHELL COMMANDS ===

COPY AND PASTE THESE INTO POWERSHELL:

# Test 1 - evil.com
wsl curl -H "Origin: https://evil.com" https://gitlab.com/api/v4/user

# Test 2 - attacker-site.com
wsl curl -H "Origin: https://attacker-site.com" https://gitlab.com/api/v4/projects

# Test 3 - malicious.com
wsl curl -H "Origin: https://malicious.com" https://gitlab.com/api/v4/version

# Test 4 - fake-bank.com
wsl curl -H "Origin: https://fake-bank.com" https://gitlab.com/api/v4/user

# To see headers clearly:
wsl curl -I -H "Origin: https://evil.com" https://gitlab.com/api/v4/user

# Alternative if WSL not available:
curl.exe -H "Origin: https://evil.com" https://gitlab.com/api/v4/user

# PowerShell native method:
curl -Headers @{"Origin"="https://evil.com"} https://gitlab.com/api/v4/user
"""
    
    return commands

def main():
    """Main function to display PowerShell curl fix."""
    print("=== POWERSHELL CURL SYNTAX FIX ===")
    print("Copyright © 2025 Khallid Hakeem Nurse. All Rights Reserved.")
    print()
    
    print(get_powershell_fix())
    
    print("\n" + "=" * 60)
    print(get_test_commands())
    
    print("\n" + "=" * 60)
    print("TESTING TIPS:")
    print("=" * 60)
    print("✅ Use WSL curl for exact submission format")
    print("✅ Look for 'Access-Control-Allow-Origin: *' in response")
    print("✅ All 4 tests should show the same vulnerable response")
    print("✅ Copy the output for your HackerOne evidence")

if __name__ == "__main__":
    main()
