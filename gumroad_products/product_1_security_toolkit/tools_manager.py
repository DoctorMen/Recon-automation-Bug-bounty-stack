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
Tools Manager - Finds and uses local tools
All scripts import this to get tool paths
"""

from pathlib import Path
import sys

REPO_ROOT = Path(__file__).parent.absolute()
TOOLS_BIN_DIR = REPO_ROOT / "tools" / "bin"

def get_tool_path(tool_name):
    """
    Get path to a tool executable.
    First checks local tools/, then system PATH.
    Returns full path or tool_name if not found.
    """
    # Check local tools first
    local_exe = TOOLS_BIN_DIR / f"{tool_name}.exe"
    if local_exe.exists():
        return str(local_exe)
    
    # Check without .exe (for Linux/WSL compatibility)
    local_exe_no_ext = TOOLS_BIN_DIR / tool_name
    if local_exe_no_ext.exists():
        return str(local_exe_no_ext)
    
    # Fall back to system PATH (tool_name will work if in PATH)
    return tool_name

def check_tool(tool_name):
    """Check if tool exists (local or system)"""
    local_exe = TOOLS_BIN_DIR / f"{tool_name}.exe"
    local_exe_no_ext = TOOLS_BIN_DIR / tool_name
    return local_exe.exists() or local_exe_no_ext.exists()

def list_tools():
    """List all available local tools"""
    if not TOOLS_BIN_DIR.exists():
        return []
    
    tools = []
    for exe in TOOLS_BIN_DIR.glob("*"):
        if exe.is_file():
            tools.append(exe.name)
    return tools


# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
