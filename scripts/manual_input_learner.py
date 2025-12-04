#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
# -*- coding: utf-8 -*-
"""
Manual Input Learning System
Captures and learns from all manual inputs to improve the system
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

class ManualInputLearner:
    def __init__(self):
        self.base_dir = Path(__file__).parent.parent
        self.manual_inputs_file = self.base_dir / "output" / "manual_inputs.json"
        self.knowledge_base_file = self.base_dir / "AI_UPWORK_MASTER_KNOWLEDGE_BASE.md"
        self.learned_patterns_file = self.base_dir / "output" / "learned_patterns.json"
        
        # Load existing manual inputs
        self.manual_inputs = self.load_manual_inputs()
        self.learned_patterns = self.load_learned_patterns()
        
    def load_manual_inputs(self) -> List[Dict]:
        """Load stored manual inputs"""
        if self.manual_inputs_file.exists():
            with open(self.manual_inputs_file, 'r') as f:
                return json.load(f)
        return []
    
    def load_learned_patterns(self) -> Dict:
        """Load learned patterns from manual inputs"""
        if self.learned_patterns_file.exists():
            with open(self.learned_patterns_file, 'r') as f:
                return json.load(f)
        return {
            "upwork_patterns": {},
            "workflow_patterns": {},
            "preferences": {},
            "improvements": []
        }
    
    def save_manual_inputs(self):
        """Save manual inputs to file"""
        self.manual_inputs_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.manual_inputs_file, 'w') as f:
            json.dump(self.manual_inputs, f, indent=2)
    
    def save_learned_patterns(self):
        """Save learned patterns"""
        self.learned_patterns_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.learned_patterns_file, 'w') as f:
            json.dump(self.learned_patterns, f, indent=2)
    
    def capture_manual_input(self, 
                            input_type: str,
                            content: str,
                            context: Optional[str] = None,
                            result: Optional[str] = None,
                            success: bool = True):
        """
        Capture a manual input from the user
        
        Args:
            input_type: Type of input (upwork_proposal, workflow_change, correction, etc.)
            content: The actual input content
            context: Context about when/why this input was made
            result: What happened as a result
            success: Whether this input led to success
        """
        entry = {
            "timestamp": datetime.now().isoformat(),
            "type": input_type,
            "content": content,
            "context": context,
            "result": result,
            "success": success
        }
        
        self.manual_inputs.append(entry)
        self.save_manual_inputs()
        
        # Learn from this input
        self.learn_from_input(entry)
        
        return entry
    
    def learn_from_input(self, entry: Dict):
        """Extract patterns and learn from manual input"""
        input_type = entry.get("type", "")
        content = entry.get("content", "")
        
        if input_type == "upwork_proposal":
            self.learn_upwork_pattern(content)
        elif input_type == "workflow_change":
            self.learn_workflow_pattern(content)
        elif input_type == "correction":
            self.learn_correction_pattern(content)
        elif input_type == "preference":
            self.learn_preference(content)
        elif input_type == "improvement":
            self.learn_improvement(content)
        
        # Update knowledge base if significant
        if entry.get("success") and self.is_significant_input(entry):
            self.update_knowledge_base(entry)
    
    def learn_upwork_pattern(self, content: str):
        """Learn patterns from Upwork proposals"""
        if "upwork_patterns" not in self.learned_patterns:
            self.learned_patterns["upwork_patterns"] = {}
        
        # Extract pricing patterns
        import re
        price_matches = re.findall(r'\$(\d+)', content)
        if price_matches:
            prices = [int(p) for p in price_matches]
            avg_price = sum(prices) / len(prices)
            if "average_price" not in self.learned_patterns["upwork_patterns"]:
                self.learned_patterns["upwork_patterns"]["average_price"] = []
            self.learned_patterns["upwork_patterns"]["average_price"].append(avg_price)
        
        # Extract common phrases
        if "common_phrases" not in self.learned_patterns["upwork_patterns"]:
            self.learned_patterns["upwork_patterns"]["common_phrases"] = []
        
        # Extract key value propositions
        value_props = re.findall(r'✅\s*(.+?)(?:\n|$)', content)
        if value_props:
            self.learned_patterns["upwork_patterns"]["common_phrases"].extend(value_props)
        
        self.save_learned_patterns()
    
    def learn_workflow_pattern(self, content: str):
        """Learn patterns from workflow changes"""
        if "workflow_patterns" not in self.learned_patterns:
            self.learned_patterns["workflow_patterns"] = []
        
        pattern = {
            "description": content,
            "timestamp": datetime.now().isoformat()
        }
        
        self.learned_patterns["workflow_patterns"].append(pattern)
        self.save_learned_patterns()
    
    def learn_correction_pattern(self, content: str):
        """Learn from corrections"""
        if "corrections" not in self.learned_patterns:
            self.learned_patterns["corrections"] = []
        
        correction = {
            "issue": content,
            "timestamp": datetime.now().isoformat()
        }
        
        self.learned_patterns["corrections"].append(correction)
        self.save_learned_patterns()
    
    def learn_preference(self, content: str):
        """Learn user preferences"""
        if "preferences" not in self.learned_patterns:
            self.learned_patterns["preferences"] = {}
        
        # Extract preference key-value pairs
        # This is a simple implementation - can be enhanced
        self.learned_patterns["preferences"][datetime.now().isoformat()] = content
        self.save_learned_patterns()
    
    def learn_improvement(self, content: str):
        """Learn from improvement suggestions"""
        if "improvements" not in self.learned_patterns:
            self.learned_patterns["improvements"] = []
        
        improvement = {
            "suggestion": content,
            "timestamp": datetime.now().isoformat(),
            "implemented": False
        }
        
        self.learned_patterns["improvements"].append(improvement)
        self.save_learned_patterns()
    
    def is_significant_input(self, entry: Dict) -> bool:
        """Determine if input is significant enough to update knowledge base"""
        # Significant if:
        # - Successful input
        # - Has result/outcome
        # - Type is important (not just preference)
        significant_types = ["upwork_proposal", "workflow_change", "correction", "improvement"]
        return (
            entry.get("success") and
            entry.get("type") in significant_types and
            entry.get("result") is not None
        )
    
    def update_knowledge_base(self, entry: Dict):
        """Update master knowledge base with learned patterns"""
        if not self.knowledge_base_file.exists():
            return
        
        # Read current knowledge base
        with open(self.knowledge_base_file, 'r') as f:
            kb_content = f.read()
        
        # Append learned pattern section if not exists
        if "## 📚 LEARNED FROM MANUAL INPUTS" not in kb_content:
            kb_content += "\n\n## 📚 LEARNED FROM MANUAL INPUTS\n\n"
            kb_content += "### Patterns Learned from User Inputs:\n\n"
        
        # Add new pattern
        pattern_entry = f"""
### Pattern Learned: {entry.get('type', 'unknown')}

**Input:** {entry.get('content', '')[:200]}

**Context:** {entry.get('context', 'N/A')}

**Result:** {entry.get('result', 'N/A')}

**Date:** {entry.get('timestamp', 'N/A')}

---
"""
        kb_content += pattern_entry
        
        # Write back
        with open(self.knowledge_base_file, 'w') as f:
            f.write(kb_content)
    
    def get_learned_patterns(self) -> Dict:
        """Get all learned patterns"""
        return self.learned_patterns
    
    def get_manual_inputs(self, input_type: Optional[str] = None) -> List[Dict]:
        """Get manual inputs, optionally filtered by type"""
        if input_type:
            return [inp for inp in self.manual_inputs if inp.get("type") == input_type]
        return self.manual_inputs
    
    def show_summary(self) -> str:
        """Show summary of learned patterns"""
        summary = f"""
📚 Manual Input Learning Summary

Total Manual Inputs: {len(self.manual_inputs)}
Learned Patterns: {len(self.learned_patterns)}

Input Types:
"""
        type_counts = {}
        for inp in self.manual_inputs:
            inp_type = inp.get("type", "unknown")
            type_counts[inp_type] = type_counts.get(inp_type, 0) + 1
        
        for inp_type, count in type_counts.items():
            summary += f"  - {inp_type}: {count}\n"
        
        summary += f"\nRecent Successful Inputs: {sum(1 for inp in self.manual_inputs[-10:] if inp.get('success'))}\n"
        
        return summary


def main():
    """CLI interface for manual input learner"""
    import sys
    
    learner = ManualInputLearner()
    
    if len(sys.argv) < 2:
        print(learner.show_summary())
        print("\nUsage:")
        print("  python3 manual_input_learner.py capture <type> <content> [context] [result]")
        print("  python3 manual_input_learner.py show [type]")
        print("  python3 manual_input_learner.py patterns")
        return
    
    command = sys.argv[1]
    
    if command == "capture":
        if len(sys.argv) < 4:
            print("Usage: capture <type> <content> [context] [result]")
            return
        
        input_type = sys.argv[2]
        content = sys.argv[3]
        context = sys.argv[4] if len(sys.argv) > 4 else None
        result = sys.argv[5] if len(sys.argv) > 5 else None
        
        entry = learner.capture_manual_input(input_type, content, context, result)
        print(f"✅ Captured: {entry['type']} at {entry['timestamp']}")
    
    elif command == "show":
        input_type = sys.argv[2] if len(sys.argv) > 2 else None
        inputs = learner.get_manual_inputs(input_type)
        
        print(f"\n📚 Manual Inputs ({len(inputs)}):\n")
        for inp in inputs[-10:]:  # Show last 10
            print(f"[{inp['timestamp']}] {inp['type']}: {inp['content'][:100]}...")
    
    elif command == "patterns":
        patterns = learner.get_learned_patterns()
        print(json.dumps(patterns, indent=2))
    
    elif command == "summary":
        print(learner.show_summary())


if __name__ == "__main__":
    main()

