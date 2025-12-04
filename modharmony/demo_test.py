#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
ModHarmony™ - Demo Test
Demonstrates the software working with simulated mod data
"""

import os
import json
from mod_scanner import ModScanner, ModDatabase

def create_demo_mods():
    """Create demo mod directories with sample files"""
    print("Creating demo mod directories...")
    
    demo_dir = "demo_mods"
    os.makedirs(demo_dir, exist_ok=True)
    
    # Create SkyUI demo
    skyui_dir = os.path.join(demo_dir, "skyui")
    os.makedirs(skyui_dir, exist_ok=True)
    os.makedirs(os.path.join(skyui_dir, "Interface"), exist_ok=True)
    
    with open(os.path.join(skyui_dir, "Interface", "skyui_cfg.txt"), 'w') as f:
        f.write("# SkyUI Configuration\nversion=5.2\n")
    
    with open(os.path.join(skyui_dir, "Interface", "skyui_menu.swf"), 'w') as f:
        f.write("FAKE_SWF_DATA_SKYUI")
    
    # Create USSEP demo
    ussep_dir = os.path.join(demo_dir, "ussep")
    os.makedirs(ussep_dir, exist_ok=True)
    os.makedirs(os.path.join(ussep_dir, "Scripts"), exist_ok=True)
    
    with open(os.path.join(ussep_dir, "Scripts", "patch_script.pex"), 'w') as f:
        f.write("FAKE_SCRIPT_DATA_USSEP")
    
    # Create Frostfall demo (with conflict!)
    frostfall_dir = os.path.join(demo_dir, "frostfall")
    os.makedirs(frostfall_dir, exist_ok=True)
    os.makedirs(os.path.join(frostfall_dir, "Interface"), exist_ok=True)
    os.makedirs(os.path.join(frostfall_dir, "Scripts"), exist_ok=True)
    
    # This file conflicts with SkyUI!
    with open(os.path.join(frostfall_dir, "Interface", "skyui_cfg.txt"), 'w') as f:
        f.write("# Frostfall modified SkyUI config\nversion=5.2\nfrostfall_enabled=true\n")
    
    with open(os.path.join(frostfall_dir, "Scripts", "frostfall_main.pex"), 'w') as f:
        f.write("FAKE_SCRIPT_DATA_FROSTFALL")
    
    print("[OK] Demo mods created")
    return {
        "SkyUI": skyui_dir,
        "USSEP": ussep_dir,
        "Frostfall": frostfall_dir
    }

def run_demo():
    """Run a complete demo of ModHarmony"""
    print("\n" + "=" * 60)
    print("  ModHarmony™ - Live Demo")
    print("=" * 60 + "\n")
    
    # Create demo mods
    mods = create_demo_mods()
    
    # Initialize scanner
    print("\nInitializing ModHarmony scanner...")
    scanner = ModScanner()
    
    # Scan mods
    print("\nScanning mods for conflicts...")
    print("-" * 60)
    
    scan_results = scanner.scan_multiple_mods(mods)
    
    for mod_name, result in scan_results.items():
        if "error" not in result:
            print(f"[OK] {mod_name}: {result['file_count']} files, {result['total_size']} bytes")
        else:
            print(f"[X] {mod_name}: {result['error']}")
    
    # Analyze compatibility
    print("\n" + "-" * 60)
    print("Analyzing compatibility...")
    print("-" * 60 + "\n")
    
    report = scanner.analyze_compatibility()
    
    # Display results
    print(f"Status: {report['status'].upper()}")
    print(f"Mods Scanned: {report['mods_scanned']}")
    print(f"Total Conflicts: {report['total_conflicts']}")
    print(f"Critical Conflicts: {report['critical_conflicts']}")
    print(f"Warnings: {report['warnings']}")
    print(f"Info: {report['info']}")
    
    # Show recommendations
    print("\nRecommendations:")
    for rec in report['recommendations']:
        print(f"  {rec}")
    
    # Show conflicts
    if report['conflicts']:
        print("\nDetected Conflicts:")
        for i, conflict in enumerate(report['conflicts'], 1):
            print(f"\n  Conflict #{i}:")
            print(f"    File: {conflict['file']}")
            print(f"    Type: {conflict['conflict_type']}")
            print(f"    Severity: {conflict['severity']}")
            print(f"    Mods: {', '.join(conflict['mods'])}")
    
    # Export report
    print("\n" + "-" * 60)
    report_file = scanner.export_report("demo_compatibility_report.json")
    print(f"[OK] Full report saved to: {report_file}")
    
    # Test database
    print("\n" + "-" * 60)
    print("Testing compatibility database...")
    print("-" * 60 + "\n")
    
    db = ModDatabase("demo_mod_compatibility.json")
    db.add_compatibility_test(
        list(mods.keys()),
        report['status'],
        report['conflicts']
    )
    
    print("[OK] Test results saved to database")
    
    # Quick check
    compat = db.check_known_compatibility("SkyUI", "Frostfall")
    print(f"\nQuick Check: SkyUI + Frostfall")
    print(f"  Compatible: {compat['compatible']}")
    print(f"  Tests: {compat['tests']}")
    
    print("\n" + "=" * 60)
    print("  Demo Complete!")
    print("=" * 60)
    print("\nFiles created:")
    print("  - demo_mods/ (sample mod directories)")
    print("  - demo_compatibility_report.json (full report)")
    print("  - demo_mod_compatibility.json (database)")
    print("\nTo view the report:")
    print("  cat demo_compatibility_report.json | python -m json.tool")
    print("\nTo start the web interface:")
    print("  python web_app.py")
    print("\n" + "=" * 60 + "\n")

if __name__ == "__main__":
    run_demo()
