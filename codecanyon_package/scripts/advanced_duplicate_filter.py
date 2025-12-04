#!/usr/bin/env python3
#!/usr/bin/env python3
"""
Copyright © 2025 DoctorMen. All Rights Reserved.
"""
"""
Advanced Duplicate Filter
Intelligently filters duplicates and consolidates similar bugs
"""

import json
from typing import List, Dict, Any, Set, Optional
from urllib.parse import urlparse
import hashlib

class AdvancedDuplicateFilter:
    """
    Intelligently filters duplicates and consolidates similar bugs
    Focuses on unique, high-value bugs
    """
    
    def __init__(self):
        self.seen_endpoints = set()
        self.seen_patterns = set()
        self.unique_findings = []
    
    def filter_duplicates(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Filter duplicates and consolidate similar bugs
        Returns unique, high-value findings
        """
        unique = []
        seen_signatures = set()
        
        for finding in findings:
            # Create signature for duplicate detection
            signature = self._create_signature(finding)
            
            if signature not in seen_signatures:
                seen_signatures.add(signature)
                unique.append(finding)
            else:
                # Check if this is a better version (higher value, better proof)
                existing_idx = self._find_existing(unique, signature)
                if existing_idx is not None:
                    # Replace if this finding is better
                    if self._is_better(finding, unique[existing_idx]):
                        unique[existing_idx] = finding
        
        return unique
    
    def _create_signature(self, finding: Dict[str, Any]) -> str:
        """Create unique signature for duplicate detection"""
        endpoint = finding.get("endpoint", "")
        test_type = finding.get("test_case", "")
        
        # Normalize endpoint
        parsed = urlparse(endpoint)
        normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        # Create signature
        signature_data = f"{normalized}:{test_type}"
        signature = hashlib.md5(signature_data.encode()).hexdigest()
        
        return signature
    
    def _find_existing(self, findings: List[Dict[str, Any]], signature: str) -> Optional[int]:
        """Find existing finding with same signature"""
        for idx, finding in enumerate(findings):
            if self._create_signature(finding) == signature:
                return idx
        return None
    
    def _is_better(self, new_finding: Dict[str, Any], existing_finding: Dict[str, Any]) -> bool:
        """Check if new finding is better than existing"""
        new_value = new_finding.get("value", 0)
        existing_value = existing_finding.get("value", 0)
        
        new_confidence = new_finding.get("verification", {}).get("confidence", 0)
        existing_confidence = existing_finding.get("verification", {}).get("confidence", 0)
        
        # Better if higher value or higher confidence
        return new_value > existing_value or new_confidence > existing_confidence
    
    def consolidate_similar(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Consolidate similar bugs (e.g., multiple swagger endpoints)"""
        consolidated = []
        grouped = {}
        
        for finding in findings:
            endpoint = finding.get("endpoint", "")
            test_type = finding.get("test_case", "")
            
            # Group by domain and test type
            parsed = urlparse(endpoint)
            domain = parsed.netloc
            group_key = f"{domain}:{test_type}"
            
            if group_key not in grouped:
                grouped[group_key] = []
            grouped[group_key].append(finding)
        
        # Consolidate groups
        for group_key, group_findings in grouped.items():
            if len(group_findings) == 1:
                consolidated.append(group_findings[0])
            else:
                # Multiple similar bugs - consolidate
                best_finding = max(group_findings, key=lambda f: f.get("value", 0))
                
                # Update description to mention multiple endpoints
                endpoints = [f.get("endpoint", "") for f in group_findings]
                best_finding["consolidated"] = True
                best_finding["similar_endpoints"] = endpoints
                best_finding["count"] = len(group_findings)
                
                consolidated.append(best_finding)
        
        return consolidated
    
    def prioritize_high_value(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Prioritize high-value bugs (auth bypass, IDOR, critical)"""
        high_value = []
        medium_value = []
        low_value = []
        
        for finding in findings:
            test_type = finding.get("test_case", "")
            value = finding.get("value", 0)
            impact = finding.get("verification", {}).get("impact", "low")
            
            if "auth_bypass" in test_type or "idor" in test_type or value >= 3000 or impact == "high":
                high_value.append(finding)
            elif value >= 1000 or impact == "medium":
                medium_value.append(finding)
            else:
                low_value.append(finding)
        
        # Return prioritized list
        return high_value + medium_value + low_value

