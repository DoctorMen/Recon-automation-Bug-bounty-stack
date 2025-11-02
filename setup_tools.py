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
Auto-Download and Setup Tools
Downloads all required recon tools directly into the workspace
No host machine installation needed!
"""

import os
import sys
import json
import urllib.request
import zipfile
import tarfile
import shutil
import platform
from pathlib import Path

REPO_ROOT = Path(__file__).parent.absolute()
TOOLS_DIR = REPO_ROOT / "tools"
TOOLS_BIN_DIR = TOOLS_DIR / "bin"

# Detect platform
SYSTEM = platform.system().lower()
ARCH = platform.machine().lower()
if ARCH in ["x86_64", "amd64"]:
    ARCH = "amd64"

# Tool definitions - platform-specific
if SYSTEM == "windows":
    TOOLS = {
        "subfinder": {
            "repo": "projectdiscovery/subfinder",
            "asset_pattern": f"subfinder_*_windows_{ARCH}.zip",
            "exe_name": "subfinder.exe",
            "extract_type": "zip"
        },
        "amass": {
            "repo": "owasp-amass/amass",
            "asset_pattern": f"amass_*_windows_{ARCH}.zip",
            "exe_name": "amass.exe",
            "extract_type": "zip"
        },
        "dnsx": {
            "repo": "projectdiscovery/dnsx",
            "asset_pattern": f"dnsx_*_windows_{ARCH}.zip",
            "exe_name": "dnsx.exe",
            "extract_type": "zip"
        },
        "httpx": {
            "repo": "projectdiscovery/httpx",
            "asset_pattern": f"httpx_*_windows_{ARCH}.zip",
            "exe_name": "httpx.exe",
            "extract_type": "zip"
        },
        "nuclei": {
            "repo": "projectdiscovery/nuclei",
            "asset_pattern": f"nuclei_*_windows_{ARCH}.zip",
            "exe_name": "nuclei.exe",
            "extract_type": "zip"
        }
    }
else:
    # Linux/WSL
    TOOLS = {
        "subfinder": {
            "repo": "projectdiscovery/subfinder",
            "asset_pattern": f"subfinder_*_linux_{ARCH}.zip",
            "exe_name": "subfinder",
            "extract_type": "zip"
        },
        "amass": {
            "repo": "owasp-amass/amass",
            "asset_pattern": f"amass_*_linux_{ARCH}.zip",
            "exe_name": "amass",
            "extract_type": "zip"
        },
        "dnsx": {
            "repo": "projectdiscovery/dnsx",
            "asset_pattern": f"dnsx_*_linux_{ARCH}.zip",
            "exe_name": "dnsx",
            "extract_type": "zip"
        },
        "httpx": {
            "repo": "projectdiscovery/httpx",
            "asset_pattern": f"httpx_*_linux_{ARCH}.zip",
            "exe_name": "httpx",
            "extract_type": "zip"
        },
        "nuclei": {
            "repo": "projectdiscovery/nuclei",
            "asset_pattern": f"nuclei_*_linux_{ARCH}.zip",
            "exe_name": "nuclei",
            "extract_type": "zip"
        }
    }

def log(message):
    print(f"[*] {message}")

def get_latest_release(repo):
    """Get latest release info from GitHub API"""
    api_url = f"https://api.github.com/repos/{repo}/releases/latest"
    try:
        with urllib.request.urlopen(api_url) as response:
            data = json.loads(response.read())
            return data
    except Exception as e:
        log(f"Error fetching release for {repo}: {e}")
        return None

def download_file(url, dest_path):
    """Download a file with progress"""
    try:
        log(f"Downloading {url}...")
        with urllib.request.urlopen(url) as response:
            total_size = int(response.headers.get('Content-Length', 0))
            downloaded = 0
            block_size = 8192
            
            with open(dest_path, 'wb') as f:
                while True:
                    chunk = response.read(block_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total_size > 0:
                        percent = (downloaded / total_size) * 100
                        print(f"\r  Progress: {percent:.1f}%", end='', flush=True)
        print()  # New line after progress
        return True
    except Exception as e:
        log(f"Error downloading {url}: {e}")
        return False

def extract_zip(zip_path, extract_to, exe_name):
    """Extract specific exe from zip"""
    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            # Find the exe in the zip
            for name in zip_ref.namelist():
                if name.endswith(exe_name) or name.endswith(f"/{exe_name}"):
                    # Extract to bin directory
                    source = zip_ref.open(name)
                    target_path = extract_to / exe_name
                    with open(target_path, 'wb') as target:
                        shutil.copyfileobj(source, target)
                    # Make executable (Linux/WSL)
                    if SYSTEM != "windows":
                        os.chmod(target_path, 0o755)
                    log(f"Extracted {exe_name}")
                    return True
        log(f"Could not find {exe_name} in zip")
        return False
    except Exception as e:
        log(f"Error extracting {zip_path}: {e}")
        return False

def setup_tool(tool_name, tool_info):
    """Download and setup a single tool"""
    log(f"\nSetting up {tool_name}...")
    
    exe_path = TOOLS_BIN_DIR / tool_info["exe_name"]
    
    # Check if already installed
    if exe_path.exists():
        log(f"{tool_name} already exists, skipping...")
        return True
    
    # Get latest release
    release = get_latest_release(tool_info["repo"])
    if not release:
        log(f"Failed to get release info for {tool_name}")
        return False
    
    # Find matching asset
    asset = None
    pattern_base = tool_info["asset_pattern"].replace("*", "").replace(f"_{SYSTEM}_{ARCH}", "").replace(".zip", "")
    for a in release.get("assets", []):
        if pattern_base in a["name"] and SYSTEM in a["name"] and ARCH in a["name"]:
            asset = a
            break
    
    if not asset:
        log(f"Could not find {SYSTEM} {ARCH} binary for {tool_name}")
        log(f"Looking for pattern: {pattern_base}")
        return False
    
    # Download
    archive_ext = ".zip" if tool_info["extract_type"] == "zip" else ".tar.gz"
    archive_path = TOOLS_DIR / f"{tool_name}{archive_ext}"
    if not download_file(asset["browser_download_url"], archive_path):
        return False
    
    # Extract
    if tool_info["extract_type"] == "zip":
        if not extract_zip(archive_path, TOOLS_BIN_DIR, tool_info["exe_name"]):
            return False
    else:
        log(f"Unsupported archive type: {tool_info['extract_type']}")
        return False
    
    # Cleanup archive
    if archive_path.exists():
        archive_path.unlink()
    
    log(f"✓ {tool_name} installed successfully")
    return True

def main():
    print("=" * 60)
    print("Self-Contained Tool Setup")
    print("Downloads tools directly to workspace - no host installation!")
    print("=" * 60)
    print()
    print(f"Platform: {SYSTEM} ({ARCH})")
    print()
    
    # Create directories
    TOOLS_DIR.mkdir(exist_ok=True)
    TOOLS_BIN_DIR.mkdir(exist_ok=True)
    
    log(f"Tools will be installed to: {TOOLS_BIN_DIR}")
    print()
    
    # Setup each tool
    results = {}
    for tool_name, tool_info in TOOLS.items():
        results[tool_name] = setup_tool(tool_name, tool_info)
    
    # Summary
    print()
    print("=" * 60)
    print("Setup Summary")
    print("=" * 60)
    
    success_count = sum(1 for v in results.values() if v)
    total_count = len(results)
    
    for tool_name, success in results.items():
        status = "✓" if success else "✗"
        print(f"{status} {tool_name}")
    
    print()
    if success_count == total_count:
        print(f"✓ All {total_count} tools installed successfully!")
        print()
        print(f"Tools location: {TOOLS_BIN_DIR}")
        print()
        print("All scripts will automatically use these local tools.")
        print("No need to add anything to PATH!")
    else:
        print(f"⚠ {success_count}/{total_count} tools installed")
        print("Some tools failed to install. Check errors above.")
    
    print()
    print("You can now run:")
    print("  python run_pipeline.py")

if __name__ == "__main__":
    main()


# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
