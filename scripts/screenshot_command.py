#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
# -*- coding: utf-8 -*-
"""
Screenshot Command Handler
Integrates screenshot analysis with polymorphic command system
"""

import sys
from pathlib import Path
from screenshot_analyzer import ScreenshotAnalyzer

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 screenshot_command.py <screenshot_path>")
        print("\nThis will:")
        print("  1. Analyze the screenshot")
        print("  2. Extract job details")
        print("  3. Generate proposal automatically")
        print("  4. Handle errors gracefully")
        sys.exit(1)
    
    image_path = sys.argv[1]
    analyzer = ScreenshotAnalyzer()
    
    print("🤖 Analyzing Upwork job post from screenshot...")
    print("="*60)
    
    result = analyzer.analyze_and_execute(image_path)
    
    print("\n" + "="*60)
    print("📊 RESULT:")
    print("="*60)
    print(result)
    
    # Show learned patterns
    if analyzer.memory.get("success_patterns"):
        print("\n💡 Learned Patterns:")
        for pattern, data in list(analyzer.memory["success_patterns"].items())[:5]:
            print(f"  • {pattern}: {data.get('count', 0)} successful uses")


if __name__ == "__main__":
    main()

