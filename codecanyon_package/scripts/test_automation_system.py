#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
🧪 Automation System Test Suite
Verify all grunt work elimination and value creation systems work properly.
"""

import os
import sys
import subprocess
import time
from pathlib import Path

def test_script_exists(script_path):
    """Test if a script exists and is executable"""
    if not Path(script_path).exists():
        return False, f"Script not found: {script_path}"
    
    if not os.access(script_path, os.R_OK):
        return False, f"Script not readable: {script_path}"
    
    return True, f"Script exists: {script_path}"

def test_script_execution(script_path, args="--help"):
    """Test if a script can be executed"""
    try:
        cmd = f"python3 {script_path} {args}"
        result = subprocess.run(cmd.split(), capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            return True, f"Script executes successfully: {script_path}"
        else:
            return False, f"Script execution failed: {script_path}\nError: {result.stderr[:200]}"
    
    except subprocess.TimeoutExpired:
        return False, f"Script execution timed out: {script_path}"
    except Exception as e:
        return False, f"Script execution error: {script_path}\nError: {str(e)}"

def run_automation_tests():
    """Run comprehensive automation system tests"""
    print("🧪 AUTOMATION SYSTEM TEST SUITE")
    print("=" * 40)
    
    base_dir = Path(__file__).parent.parent
    
    # Test scripts to verify
    test_scripts = [
        {
            "name": "Grunt Work Eliminator",
            "path": base_dir / "scripts/grunt_work_eliminator.py",
            "test_args": "status"
        },
        {
            "name": "Value Creation Focus",
            "path": base_dir / "scripts/value_creation_focus.py",
            "test_args": "focus-metrics"
        },
        {
            "name": "Auto Workflow Orchestrator",
            "path": base_dir / "scripts/auto_workflow_orchestrator.py",
            "test_args": "status"
        },
        {
            "name": "Multi Platform Domination",
            "path": base_dir / "scripts/multi_platform_domination.py",
            "test_args": "recommend"
        },
        {
            "name": "Money Making Toolkit",
            "path": base_dir / "scripts/money_making_toolkit.py",
            "test_args": "potential"
        }
    ]
    
    # Test results
    passed = 0
    failed = 0
    
    print("🔍 TESTING SCRIPT EXISTENCE:")
    print("-" * 30)
    
    for script in test_scripts:
        success, message = test_script_exists(script["path"])
        status = "✅ PASS" if success else "❌ FAIL"
        print(f"{status} {script['name']}: {message}")
        
        if success:
            passed += 1
        else:
            failed += 1
    
    print(f"\n🔍 TESTING SCRIPT EXECUTION:")
    print("-" * 30)
    
    for script in test_scripts:
        if Path(script["path"]).exists():
            success, message = test_script_execution(script["path"], script["test_args"])
            status = "✅ PASS" if success else "❌ FAIL"
            print(f"{status} {script['name']}: {message}")
            
            if success:
                passed += 1
            else:
                failed += 1
    
    # Test automation integration
    print(f"\n🔍 TESTING AUTOMATION INTEGRATION:")
    print("-" * 30)
    
    integration_tests = [
        {
            "name": "Grunt Work Status Check",
            "command": f"python3 {base_dir}/scripts/grunt_work_eliminator.py status"
        },
        {
            "name": "Value Creation Metrics",
            "command": f"python3 {base_dir}/scripts/value_creation_focus.py focus-metrics"
        },
        {
            "name": "Workflow Status Check",
            "command": f"python3 {base_dir}/scripts/auto_workflow_orchestrator.py status"
        }
    ]
    
    for test in integration_tests:
        try:
            result = subprocess.run(test["command"].split(), capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                print(f"✅ PASS {test['name']}: Integration working")
                passed += 1
            else:
                print(f"❌ FAIL {test['name']}: {result.stderr[:100]}")
                failed += 1
        
        except Exception as e:
            print(f"❌ FAIL {test['name']}: {str(e)[:100]}")
            failed += 1
    
    # Test data directory creation
    print(f"\n🔍 TESTING DATA DIRECTORIES:")
    print("-" * 30)
    
    data_dirs = [
        base_dir / "automation_data",
        base_dir / "value_creation_data", 
        base_dir / "automated_workflows"
    ]
    
    for data_dir in data_dirs:
        if data_dir.exists():
            print(f"✅ PASS Data directory exists: {data_dir.name}")
            passed += 1
        else:
            print(f"❌ FAIL Data directory missing: {data_dir.name}")
            failed += 1
    
    # Summary
    print(f"\n📊 TEST RESULTS SUMMARY:")
    print("=" * 30)
    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {failed}")
    print(f"📈 Success Rate: {(passed/(passed+failed)*100):.1f}%")
    
    if failed == 0:
        print(f"\n🎉 ALL TESTS PASSED!")
        print(f"🚀 Automation system is fully operational")
        print(f"🎯 Ready for value creation mode")
    else:
        print(f"\n⚠️  Some tests failed - check errors above")
        print(f"🔧 Fix issues before using automation system")
    
    return passed, failed

def demonstrate_automation():
    """Demonstrate automation capabilities"""
    print("\n🚀 AUTOMATION DEMONSTRATION")
    print("=" * 30)
    
    base_dir = Path(__file__).parent.parent
    
    demos = [
        {
            "name": "Grunt Work Elimination Demo",
            "description": "Show how grunt work is eliminated",
            "command": f"python3 {base_dir}/scripts/grunt_work_eliminator.py status"
        },
        {
            "name": "Value Creation Focus Demo", 
            "description": "Show value creation opportunities",
            "command": f"python3 {base_dir}/scripts/value_creation_focus.py focus-strategy"
        },
        {
            "name": "Workflow Orchestration Demo",
            "description": "Show available automated workflows",
            "command": f"python3 {base_dir}/scripts/auto_workflow_orchestrator.py list-workflows"
        }
    ]
    
    for demo in demos:
        print(f"\n🎯 {demo['name']}:")
        print(f"   {demo['description']}")
        print(f"   Command: {demo['command']}")
        
        try:
            result = subprocess.run(demo["command"].split(), capture_output=True, text=True, timeout=20)
            
            if result.returncode == 0:
                print(f"✅ Demo successful")
                # Show first few lines of output
                output_lines = result.stdout.split('\n')[:5]
                for line in output_lines:
                    if line.strip():
                        print(f"   {line}")
            else:
                print(f"❌ Demo failed: {result.stderr[:100]}")
        
        except Exception as e:
            print(f"❌ Demo error: {str(e)[:100]}")

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        demonstrate_automation()
    else:
        passed, failed = run_automation_tests()
        
        if failed == 0:
            print(f"\n🎯 NEXT STEPS:")
            print(f"1. Run: python3 scripts/grunt_work_eliminator.py full-automation")
            print(f"2. Run: python3 scripts/value_creation_focus.py value-creation-mode")
            print(f"3. Run: python3 scripts/auto_workflow_orchestrator.py execute money_making_blitz")
            print(f"4. Focus 80%+ time on strategic thinking and relationships")
            
            demonstrate_automation()

if __name__ == "__main__":
    main()
