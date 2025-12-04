#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
Cascade Snapshot System™

This software is proprietary and confidential.
Unauthorized copying, modification, or distribution is prohibited.

Patent Pending | Trademark: ParallelProfit™
"""
"""
🚀 CASCADE SNAPSHOT SYSTEM
Captures and restores Windsurf/Cascade state for instant processing
Dramatically reduces context loading time and improves response speed

FEATURES:
- Instant state restoration
- Context preservation
- Process caching
- Knowledge indexing
- Fast retrieval
"""

import json
import hashlib
import pickle
import gzip
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
import sys

class CascadeSnapshotSystem:
    """
    Snapshot system for Cascade AI state management
    Enables instant context restoration and faster processing
    """
    
    def __init__(self):
        self.base_dir = Path(__file__).parent
        self.snapshot_dir = self.base_dir / ".cascade_snapshots"
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)
        
        # Snapshot metadata
        self.current_snapshot = None
        self.snapshot_index = self.load_snapshot_index()
        
        print("📸 Cascade Snapshot System Initialized")
    
    def load_snapshot_index(self) -> Dict:
        """Load snapshot index for fast lookup"""
        index_file = self.snapshot_dir / "snapshot_index.json"
        if index_file.exists():
            with open(index_file, 'r') as f:
                return json.load(f)
        return {
            "snapshots": {},
            "latest": None,
            "total_snapshots": 0
        }
    
    def save_snapshot_index(self):
        """Save snapshot index"""
        index_file = self.snapshot_dir / "snapshot_index.json"
        with open(index_file, 'w') as f:
            json.dump(self.snapshot_index, f, indent=2)
    
    # ========================================
    # SNAPSHOT CREATION
    # ========================================
    
    def create_snapshot(self, name: str = None, description: str = "") -> str:
        """
        Create a complete snapshot of current state
        Returns snapshot ID for fast restoration
        """
        snapshot_id = name or f"snapshot_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        print(f"📸 Creating snapshot: {snapshot_id}")
        
        # Capture current state
        snapshot_data = {
            "id": snapshot_id,
            "timestamp": datetime.now().isoformat(),
            "description": description,
            "context": self.capture_context(),
            "file_state": self.capture_file_state(),
            "process_state": self.capture_process_state(),
            "knowledge_base": self.capture_knowledge_base(),
            "metrics": self.capture_metrics()
        }
        
        # Save snapshot (compressed)
        snapshot_file = self.snapshot_dir / f"{snapshot_id}.snapshot.gz"
        with gzip.open(snapshot_file, 'wb') as f:
            pickle.dump(snapshot_data, f)
        
        # Update index
        self.snapshot_index["snapshots"][snapshot_id] = {
            "timestamp": snapshot_data["timestamp"],
            "description": description,
            "file": str(snapshot_file),
            "size": snapshot_file.stat().st_size,
            "hash": self.calculate_hash(snapshot_file)
        }
        self.snapshot_index["latest"] = snapshot_id
        self.snapshot_index["total_snapshots"] = len(self.snapshot_index["snapshots"])
        self.save_snapshot_index()
        
        print(f"✅ Snapshot created: {snapshot_id}")
        print(f"   Size: {snapshot_file.stat().st_size / 1024:.2f} KB")
        
        return snapshot_id
    
    def capture_context(self) -> Dict:
        """Capture current conversation context"""
        return {
            "working_directory": str(Path.cwd()),
            "repository_root": str(self.base_dir),
            "active_files": self.get_active_files(),
            "recent_commands": self.get_recent_commands(),
            "conversation_state": "active"
        }
    
    def capture_file_state(self) -> Dict:
        """Capture state of all important files"""
        file_state = {}
        
        # Key files to track
        important_patterns = [
            "*.py",
            "*.md",
            "*.sh",
            "*.json",
            "*.html"
        ]
        
        for pattern in important_patterns:
            for file_path in self.base_dir.rglob(pattern):
                if ".git" not in str(file_path) and ".snapshot" not in str(file_path):
                    try:
                        rel_path = str(file_path.relative_to(self.base_dir))
                        file_state[rel_path] = {
                            "size": file_path.stat().st_size,
                            "modified": file_path.stat().st_mtime,
                            "hash": self.calculate_file_hash(file_path)
                        }
                    except:
                        pass
        
        return file_state
    
    def capture_process_state(self) -> Dict:
        """Capture current process/workflow state"""
        state_files = [
            "output/money_master/state.json",
            "output/.pipeline_status"
        ]
        
        process_state = {}
        for state_file in state_files:
            file_path = self.base_dir / state_file
            if file_path.exists():
                try:
                    with open(file_path, 'r') as f:
                        process_state[state_file] = json.load(f) if state_file.endswith('.json') else f.read()
                except:
                    pass
        
        return process_state
    
    def capture_knowledge_base(self) -> Dict:
        """Capture knowledge base for fast retrieval"""
        knowledge = {
            "documentation_files": [],
            "key_concepts": {},
            "file_index": {}
        }
        
        # Index all markdown files
        for md_file in self.base_dir.rglob("*.md"):
            if ".git" not in str(md_file):
                rel_path = str(md_file.relative_to(self.base_dir))
                knowledge["documentation_files"].append(rel_path)
                
                # Extract key concepts from filename
                concepts = md_file.stem.lower().split('_')
                for concept in concepts:
                    if concept not in knowledge["key_concepts"]:
                        knowledge["key_concepts"][concept] = []
                    knowledge["key_concepts"][concept].append(rel_path)
        
        return knowledge
    
    def capture_metrics(self) -> Dict:
        """Capture current system metrics"""
        return {
            "total_files": len(list(self.base_dir.rglob("*"))),
            "python_files": len(list(self.base_dir.rglob("*.py"))),
            "markdown_files": len(list(self.base_dir.rglob("*.md"))),
            "scripts": len(list((self.base_dir / "scripts").glob("*"))) if (self.base_dir / "scripts").exists() else 0,
            "snapshot_time": datetime.now().isoformat()
        }
    
    # ========================================
    # SNAPSHOT RESTORATION
    # ========================================
    
    def restore_snapshot(self, snapshot_id: str = None) -> bool:
        """
        Restore from snapshot for instant context
        If no ID provided, restores latest
        """
        if snapshot_id is None:
            snapshot_id = self.snapshot_index.get("latest")
        
        if snapshot_id not in self.snapshot_index["snapshots"]:
            print(f"❌ Snapshot not found: {snapshot_id}")
            return False
        
        print(f"⚡ Restoring snapshot: {snapshot_id}")
        
        snapshot_file = Path(self.snapshot_index["snapshots"][snapshot_id]["file"])
        
        # Load snapshot
        with gzip.open(snapshot_file, 'rb') as f:
            snapshot_data = pickle.load(f)
        
        self.current_snapshot = snapshot_data
        
        print(f"✅ Snapshot restored: {snapshot_id}")
        print(f"   Timestamp: {snapshot_data['timestamp']}")
        print(f"   Files tracked: {len(snapshot_data['file_state'])}")
        print(f"   Knowledge base: {len(snapshot_data['knowledge_base']['documentation_files'])} docs")
        
        return True
    
    def get_context(self) -> Optional[Dict]:
        """Get current context from snapshot"""
        if self.current_snapshot:
            return self.current_snapshot["context"]
        return None
    
    def get_file_state(self, file_path: str) -> Optional[Dict]:
        """Get file state from snapshot"""
        if self.current_snapshot:
            return self.current_snapshot["file_state"].get(file_path)
        return None
    
    def get_knowledge(self, concept: str) -> List[str]:
        """Fast knowledge retrieval from snapshot"""
        if self.current_snapshot:
            kb = self.current_snapshot["knowledge_base"]
            return kb["key_concepts"].get(concept.lower(), [])
        return []
    
    # ========================================
    # DIFFERENTIAL SNAPSHOTS
    # ========================================
    
    def create_differential_snapshot(self, base_snapshot_id: str, name: str = None) -> str:
        """
        Create differential snapshot (only changes)
        Much faster and smaller than full snapshot
        """
        if base_snapshot_id not in self.snapshot_index["snapshots"]:
            print(f"❌ Base snapshot not found: {base_snapshot_id}")
            return None
        
        # Load base snapshot
        base_file = Path(self.snapshot_index["snapshots"][base_snapshot_id]["file"])
        with gzip.open(base_file, 'rb') as f:
            base_data = pickle.load(f)
        
        # Capture current state
        current_file_state = self.capture_file_state()
        
        # Calculate differences
        changes = {
            "added": {},
            "modified": {},
            "deleted": []
        }
        
        # Find added and modified files
        for file_path, current_state in current_file_state.items():
            if file_path not in base_data["file_state"]:
                changes["added"][file_path] = current_state
            elif current_state["hash"] != base_data["file_state"][file_path]["hash"]:
                changes["modified"][file_path] = current_state
        
        # Find deleted files
        for file_path in base_data["file_state"]:
            if file_path not in current_file_state:
                changes["deleted"].append(file_path)
        
        # Create differential snapshot
        diff_id = name or f"diff_{base_snapshot_id}_{datetime.now().strftime('%H%M%S')}"
        diff_data = {
            "id": diff_id,
            "type": "differential",
            "base": base_snapshot_id,
            "timestamp": datetime.now().isoformat(),
            "changes": changes,
            "process_state": self.capture_process_state()
        }
        
        # Save differential
        diff_file = self.snapshot_dir / f"{diff_id}.diff.gz"
        with gzip.open(diff_file, 'wb') as f:
            pickle.dump(diff_data, f)
        
        # Update index
        self.snapshot_index["snapshots"][diff_id] = {
            "timestamp": diff_data["timestamp"],
            "type": "differential",
            "base": base_snapshot_id,
            "file": str(diff_file),
            "size": diff_file.stat().st_size,
            "changes": {
                "added": len(changes["added"]),
                "modified": len(changes["modified"]),
                "deleted": len(changes["deleted"])
            }
        }
        self.save_snapshot_index()
        
        print(f"✅ Differential snapshot created: {diff_id}")
        print(f"   Added: {len(changes['added'])}")
        print(f"   Modified: {len(changes['modified'])}")
        print(f"   Deleted: {len(changes['deleted'])}")
        print(f"   Size: {diff_file.stat().st_size / 1024:.2f} KB")
        
        return diff_id
    
    # ========================================
    # FAST QUERY SYSTEM
    # ========================================
    
    def query_snapshots(self, query: str) -> List[Dict]:
        """Fast query across all snapshots"""
        results = []
        
        for snapshot_id, snapshot_info in self.snapshot_index["snapshots"].items():
            # Load snapshot
            snapshot_file = Path(snapshot_info["file"])
            with gzip.open(snapshot_file, 'rb') as f:
                snapshot_data = pickle.load(f)
            
            # Search in knowledge base
            if "knowledge_base" in snapshot_data:
                kb = snapshot_data["knowledge_base"]
                if query.lower() in kb["key_concepts"]:
                    results.append({
                        "snapshot_id": snapshot_id,
                        "timestamp": snapshot_info["timestamp"],
                        "files": kb["key_concepts"][query.lower()]
                    })
        
        return results
    
    # ========================================
    # UTILITY FUNCTIONS
    # ========================================
    
    def calculate_hash(self, file_path: Path) -> str:
        """Calculate file hash for change detection"""
        return hashlib.md5(file_path.read_bytes()).hexdigest()
    
    def calculate_file_hash(self, file_path: Path) -> str:
        """Calculate hash of file content"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except:
            return ""
    
    def get_active_files(self) -> List[str]:
        """Get list of recently modified files"""
        recent_files = []
        for file_path in self.base_dir.rglob("*"):
            if file_path.is_file() and ".git" not in str(file_path):
                try:
                    # Files modified in last hour
                    if (datetime.now().timestamp() - file_path.stat().st_mtime) < 3600:
                        recent_files.append(str(file_path.relative_to(self.base_dir)))
                except:
                    pass
        return recent_files
    
    def get_recent_commands(self) -> List[str]:
        """Get recent command history"""
        # Placeholder - would integrate with shell history
        return []
    
    def list_snapshots(self):
        """List all available snapshots"""
        print("\n📸 Available Snapshots:")
        print("=" * 80)
        
        for snapshot_id, info in sorted(
            self.snapshot_index["snapshots"].items(),
            key=lambda x: x[1]["timestamp"],
            reverse=True
        ):
            print(f"\n🔹 {snapshot_id}")
            print(f"   Timestamp: {info['timestamp']}")
            print(f"   Size: {info['size'] / 1024:.2f} KB")
            if "description" in info:
                print(f"   Description: {info['description']}")
            if info.get("type") == "differential":
                print(f"   Type: Differential (base: {info['base']})")
                print(f"   Changes: +{info['changes']['added']} ~{info['changes']['modified']} -{info['changes']['deleted']}")
        
        print("\n" + "=" * 80)
        print(f"Total snapshots: {self.snapshot_index['total_snapshots']}")
        print(f"Latest: {self.snapshot_index.get('latest', 'None')}")
    
    def cleanup_old_snapshots(self, keep_count: int = 10):
        """Clean up old snapshots, keep only recent ones"""
        if len(self.snapshot_index["snapshots"]) <= keep_count:
            print(f"✅ Only {len(self.snapshot_index['snapshots'])} snapshots, no cleanup needed")
            return
        
        # Sort by timestamp
        sorted_snapshots = sorted(
            self.snapshot_index["snapshots"].items(),
            key=lambda x: x[1]["timestamp"],
            reverse=True
        )
        
        # Keep only recent ones
        to_delete = sorted_snapshots[keep_count:]
        
        for snapshot_id, info in to_delete:
            snapshot_file = Path(info["file"])
            if snapshot_file.exists():
                snapshot_file.unlink()
            del self.snapshot_index["snapshots"][snapshot_id]
        
        self.save_snapshot_index()
        print(f"✅ Cleaned up {len(to_delete)} old snapshots")

def main():
    """CLI interface for snapshot system"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Cascade Snapshot System")
    parser.add_argument("action", choices=["create", "restore", "list", "query", "diff", "cleanup"],
                       help="Action to perform")
    parser.add_argument("--name", help="Snapshot name")
    parser.add_argument("--description", help="Snapshot description")
    parser.add_argument("--base", help="Base snapshot for differential")
    parser.add_argument("--query", help="Query string")
    parser.add_argument("--keep", type=int, default=10, help="Number of snapshots to keep")
    
    args = parser.parse_args()
    
    system = CascadeSnapshotSystem()
    
    if args.action == "create":
        system.create_snapshot(args.name, args.description or "")
    
    elif args.action == "restore":
        system.restore_snapshot(args.name)
    
    elif args.action == "list":
        system.list_snapshots()
    
    elif args.action == "query":
        if not args.query:
            print("❌ --query required")
            return
        results = system.query_snapshots(args.query)
        print(f"\n🔍 Query results for '{args.query}':")
        for result in results:
            print(f"\n📸 {result['snapshot_id']} ({result['timestamp']})")
            for file in result['files']:
                print(f"   - {file}")
    
    elif args.action == "diff":
        if not args.base:
            print("❌ --base required for differential snapshot")
            return
        system.create_differential_snapshot(args.base, args.name)
    
    elif args.action == "cleanup":
        system.cleanup_old_snapshots(args.keep)

if __name__ == "__main__":
    main()
