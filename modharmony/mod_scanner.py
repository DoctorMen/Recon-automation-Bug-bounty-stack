#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
ModHarmony™ - Mod Conflict Detection Engine
Core module for scanning and detecting mod conflicts
"""

import os
import json
import hashlib
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Set, Tuple
import re

class ModScanner:
    """Scans mod directories and detects file conflicts"""
    
    def __init__(self):
        self.file_map = defaultdict(list)
        self.conflicts = []
        self.mod_metadata = {}
        
    def scan_mod_directory(self, mod_name: str, mod_path: str) -> Dict:
        """
        Scan a single mod directory and catalog all files
        
        Args:
            mod_name: Name of the mod
            mod_path: Path to mod directory
            
        Returns:
            Dictionary with mod metadata and file list
        """
        if not os.path.exists(mod_path):
            return {"error": f"Mod path not found: {mod_path}"}
        
        files = []
        total_size = 0
        
        for root, dirs, filenames in os.walk(mod_path):
            for filename in filenames:
                full_path = os.path.join(root, filename)
                rel_path = os.path.relpath(full_path, mod_path)
                
                # Get file info
                file_size = os.path.getsize(full_path)
                file_hash = self._get_file_hash(full_path)
                
                file_info = {
                    "path": rel_path,
                    "size": file_size,
                    "hash": file_hash,
                    "extension": os.path.splitext(filename)[1]
                }
                
                files.append(file_info)
                total_size += file_size
                
                # Track for conflict detection
                self.file_map[rel_path].append({
                    "mod": mod_name,
                    "hash": file_hash,
                    "size": file_size
                })
        
        metadata = {
            "name": mod_name,
            "path": mod_path,
            "file_count": len(files),
            "total_size": total_size,
            "files": files
        }
        
        self.mod_metadata[mod_name] = metadata
        return metadata
    
    def scan_multiple_mods(self, mods: Dict[str, str]) -> Dict:
        """
        Scan multiple mods at once
        
        Args:
            mods: Dictionary of {mod_name: mod_path}
            
        Returns:
            Summary of all scanned mods
        """
        results = {}
        
        for mod_name, mod_path in mods.items():
            print(f"Scanning {mod_name}...")
            results[mod_name] = self.scan_mod_directory(mod_name, mod_path)
        
        return results
    
    def detect_file_conflicts(self) -> List[Dict]:
        """
        Detect file conflicts between mods
        
        Returns:
            List of conflicts with details
        """
        conflicts = []
        
        for file_path, mod_list in self.file_map.items():
            if len(mod_list) > 1:
                # Multiple mods modify the same file
                conflict = {
                    "file": file_path,
                    "conflict_type": "file_overlap",
                    "severity": self._calculate_severity(mod_list),
                    "mods": [m["mod"] for m in mod_list],
                    "details": mod_list
                }
                
                # Check if files are identical (same hash)
                hashes = [m["hash"] for m in mod_list]
                if len(set(hashes)) == 1:
                    conflict["conflict_type"] = "duplicate_file"
                    conflict["severity"] = "low"
                else:
                    conflict["conflict_type"] = "file_overwrite"
                    conflict["severity"] = "high"
                
                conflicts.append(conflict)
        
        self.conflicts = conflicts
        return conflicts
    
    def detect_plugin_conflicts(self, plugin_files: List[str]) -> List[Dict]:
        """
        Detect conflicts in plugin load order (.esp, .esm files)
        
        Args:
            plugin_files: List of plugin file paths
            
        Returns:
            List of plugin conflicts
        """
        conflicts = []
        masters = defaultdict(list)
        
        for plugin in plugin_files:
            # Parse plugin headers (simplified - real implementation needs proper ESP parser)
            plugin_name = os.path.basename(plugin)
            
            # Check for master dependencies
            # This is a placeholder - real implementation would parse ESP/ESM headers
            if plugin_name.endswith('.esp'):
                # ESPs typically depend on ESMs
                conflicts.append({
                    "plugin": plugin_name,
                    "type": "load_order",
                    "severity": "medium",
                    "message": f"{plugin_name} may have load order dependencies"
                })
        
        return conflicts
    
    def analyze_compatibility(self) -> Dict:
        """
        Run full compatibility analysis
        
        Returns:
            Complete compatibility report
        """
        file_conflicts = self.detect_file_conflicts()
        
        # Categorize conflicts
        critical = [c for c in file_conflicts if c["severity"] == "high"]
        warnings = [c for c in file_conflicts if c["severity"] == "medium"]
        info = [c for c in file_conflicts if c["severity"] == "low"]
        
        report = {
            "status": "compatible" if len(critical) == 0 else "conflicts_detected",
            "total_conflicts": len(file_conflicts),
            "critical_conflicts": len(critical),
            "warnings": len(warnings),
            "info": len(info),
            "conflicts": file_conflicts,
            "mods_scanned": len(self.mod_metadata),
            "recommendations": self._generate_recommendations(file_conflicts)
        }
        
        return report
    
    def _get_file_hash(self, file_path: str) -> str:
        """Calculate MD5 hash of file"""
        hash_md5 = hashlib.md5()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
        except:
            return "error"
    
    def _calculate_severity(self, mod_list: List[Dict]) -> str:
        """Calculate conflict severity based on file differences"""
        if len(mod_list) <= 1:
            return "none"
        
        # Check if files are identical
        hashes = [m["hash"] for m in mod_list]
        if len(set(hashes)) == 1:
            return "low"  # Same file, just duplicate
        
        # Check file sizes
        sizes = [m["size"] for m in mod_list]
        size_diff = max(sizes) - min(sizes)
        
        if size_diff > 10000:  # More than 10KB difference
            return "high"
        elif size_diff > 1000:
            return "medium"
        else:
            return "low"
    
    def _generate_recommendations(self, conflicts: List[Dict]) -> List[str]:
        """Generate recommendations based on conflicts"""
        recommendations = []
        
        if not conflicts:
            recommendations.append("[OK] No conflicts detected! All mods are compatible.")
            return recommendations
        
        critical = [c for c in conflicts if c["severity"] == "high"]
        
        if critical:
            recommendations.append(f"[WARNING] {len(critical)} critical conflicts detected")
            recommendations.append("Recommendation: Review load order or disable conflicting mods")
            
            # Suggest which mods to prioritize
            for conflict in critical[:3]:  # Top 3 conflicts
                mods = conflict["mods"]
                recommendations.append(f"  - Conflict between: {', '.join(mods)}")
        
        return recommendations
    
    def export_report(self, output_file: str = "compatibility_report.json"):
        """Export compatibility report to JSON"""
        report = self.analyze_compatibility()
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"Report exported to {output_file}")
        return output_file


class ModDatabase:
    """Database for storing known mod compatibility data"""
    
    def __init__(self, db_file: str = "mod_compatibility.json"):
        self.db_file = db_file
        self.data = self._load_database()
    
    def _load_database(self) -> Dict:
        """Load compatibility database"""
        if os.path.exists(self.db_file):
            with open(self.db_file, 'r') as f:
                return json.load(f)
        return {"mods": {}, "compatibility": {}, "tests": []}
    
    def add_compatibility_test(self, mod_list: List[str], result: str, conflicts: List[Dict]):
        """Record a compatibility test result"""
        test_id = hashlib.md5(json.dumps(sorted(mod_list)).encode()).hexdigest()
        
        test_record = {
            "id": test_id,
            "mods": sorted(mod_list),
            "result": result,
            "conflicts": len(conflicts),
            "timestamp": self._get_timestamp()
        }
        
        self.data["tests"].append(test_record)
        
        # Update compatibility matrix
        for i, mod1 in enumerate(mod_list):
            for mod2 in mod_list[i+1:]:
                key = f"{mod1}|{mod2}"
                if key not in self.data["compatibility"]:
                    self.data["compatibility"][key] = {
                        "compatible": result == "compatible",
                        "tests": 1
                    }
                else:
                    self.data["compatibility"][key]["tests"] += 1
        
        self._save_database()
    
    def check_known_compatibility(self, mod1: str, mod2: str) -> Dict:
        """Check if two mods have known compatibility data"""
        key = f"{mod1}|{mod2}"
        reverse_key = f"{mod2}|{mod1}"
        
        if key in self.data["compatibility"]:
            return self.data["compatibility"][key]
        elif reverse_key in self.data["compatibility"]:
            return self.data["compatibility"][reverse_key]
        
        return {"compatible": None, "tests": 0}
    
    def _save_database(self):
        """Save database to file"""
        with open(self.db_file, 'w') as f:
            json.dump(self.data, f, indent=2)
    
    def _get_timestamp(self) -> str:
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().isoformat()


if __name__ == "__main__":
    # Example usage
    print("ModHarmony™ - Mod Conflict Detection Engine")
    print("=" * 50)
    
    scanner = ModScanner()
    
    # Example: Scan demo mods (you'd replace with actual mod paths)
    demo_mods = {
        "SkyUI": "./demo_mods/skyui",
        "USSEP": "./demo_mods/ussep",
        "Frostfall": "./demo_mods/frostfall"
    }
    
    print("\nNote: This is a demo. Replace paths with actual mod directories.")
    print("\nUsage:")
    print("  scanner = ModScanner()")
    print("  scanner.scan_multiple_mods({'ModName': '/path/to/mod'})")
    print("  report = scanner.analyze_compatibility()")
    print("  scanner.export_report('report.json')")
