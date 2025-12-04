#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Find and open the System Transformation Breakdown chart
"""
import os
import sys
import webbrowser
from pathlib import Path

def find_breakdown_chart():
    """Find the breakdown chart HTML file"""
    current_dir = Path.cwd()
    
    # Look for the file in current directory and subdirectories
    chart_files = []
    
    for file_path in current_dir.rglob("SYSTEM_TRANSFORMATION_BREAKDOWN.html"):
        chart_files.append(file_path)
    
    if chart_files:
        print("🎯 Found breakdown chart(s):")
        for i, file_path in enumerate(chart_files, 1):
            print(f"  {i}. {file_path}")
        
        # Open the first one found
        chart_path = chart_files[0]
        print(f"\n🚀 Opening: {chart_path}")
        
        try:
            # Open in default browser
            webbrowser.open(f"file://{chart_path.absolute()}")
            print("✅ Breakdown chart opened in your browser!")
        except Exception as e:
            print(f"❌ Error opening file: {e}")
            print(f"📁 Manual path: {chart_path.absolute()}")
            
    else:
        print("❌ Breakdown chart not found in current directory")
        print("💡 Make sure you're in the system folder")
        print(f"📁 Current directory: {current_dir}")

if __name__ == "__main__":
    find_breakdown_chart()
