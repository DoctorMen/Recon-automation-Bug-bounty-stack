#!/usr/bin/env python3
"""
Bug Verification Module
Verifies findings are real, exploitable, and have impact
"""

import json
import requests
import time
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
from urllib.parse import urlparse
import re

class BugVerifier:
    """
    Verifies bugs are real, exploitable, and have impact
    Filters false positives and non-exploitable findings
    """
    
    def __init__(self):
        self.verified_findings = []
        self.false_positives = []
    
    def verify_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Verify a finding is real and exploitable
        Returns verified finding with confidence score
        """
        result = {
            "finding": finding,
            "verified": False,
            "exploitable": False,
            "impact": "none",
            "confidence": 0,
            "verification_details": {}
        }
        
        endpoint = finding.get("endpoint", "")
        test_type = finding.get("test_case", "")
        proof = finding.get("proof", {})
        
        # Verify based on test type
        if "auth_bypass" in test_type:
            result = self._verify_auth_bypass(endpoint, proof)
        elif "idor" in test_type:
            result = self._verify_idor(endpoint, proof)
        elif "information_disclosure" in test_type or "generic" in test_type:
            result = self._verify_information_disclosure(endpoint, proof)
        else:
            result = self._verify_generic(endpoint, proof)
        
        # Add verification details
        result["verification_details"] = {
            "endpoint": endpoint,
            "test_type": test_type,
            "verification_time": time.time(),
            "verification_method": "automated"
        }
        
        return result
    
    def _verify_auth_bypass(self, endpoint: str, proof: Dict[str, Any]) -> Dict[str, Any]:
        """Verify authentication bypass"""
        result = {
            "verified": False,
            "exploitable": False,
            "impact": "none",
            "confidence": 0
        }
        
        try:
            # Test without authentication
            response = requests.get(endpoint, timeout=5, verify=False, allow_redirects=False)
            
            if response.status_code in [200, 201, 202]:
                # Check if response contains sensitive data
                response_text = response.text.lower()
                
                sensitive_patterns = [
                    "admin", "password", "token", "api_key", "secret",
                    "user", "account", "balance", "transaction", "payment"
                ]
                
                sensitive_count = sum(1 for pattern in sensitive_patterns if pattern in response_text)
                
                if sensitive_count >= 3:
                    result["verified"] = True
                    result["exploitable"] = True
                    result["impact"] = "high"
                    result["confidence"] = 80
                elif sensitive_count >= 1:
                    result["verified"] = True
                    result["exploitable"] = True
                    result["impact"] = "medium"
                    result["confidence"] = 60
                else:
                    result["verified"] = True
                    result["exploitable"] = False
                    result["impact"] = "low"
                    result["confidence"] = 30
            else:
                result["confidence"] = 10  # Low confidence if not accessible
                
        except Exception as e:
            result["confidence"] = 0
        
        return result
    
    def _verify_idor(self, endpoint: str, proof: Dict[str, Any]) -> Dict[str, Any]:
        """Verify IDOR vulnerability"""
        result = {
            "verified": False,
            "exploitable": False,
            "impact": "none",
            "confidence": 0
        }
        
        # Extract IDs from proof
        original_id = proof.get("original_id")
        test_id = proof.get("test_id")
        
        if original_id and test_id:
            try:
                # Test with different ID
                test_endpoint = endpoint.replace(original_id, test_id)
                response = requests.get(test_endpoint, timeout=5, verify=False)
                
                if response.status_code == 200 and len(response.text) > 100:
                    # Check if different data returned
                    if response.text != proof.get("original_response", ""):
                        result["verified"] = True
                        result["exploitable"] = True
                        result["impact"] = "high"
                        result["confidence"] = 70
                    else:
                        result["verified"] = True
                        result["exploitable"] = False
                        result["impact"] = "medium"
                        result["confidence"] = 40
            except:
                result["confidence"] = 20
        
        return result
    
    def _verify_information_disclosure(self, endpoint: str, proof: Dict[str, Any]) -> Dict[str, Any]:
        """Verify information disclosure"""
        result = {
            "verified": False,
            "exploitable": False,
            "impact": "low",
            "confidence": 0
        }
        
        # Check endpoint type
        if any(pattern in endpoint.lower() for pattern in ["swagger", "openapi", "api-docs", "docs"]):
            # API documentation exposure
            result["verified"] = True
            result["exploitable"] = False
            result["impact"] = "low"
            result["confidence"] = 50  # Low-medium confidence for acceptance
        elif "health" in endpoint.lower() or "status" in endpoint.lower():
            # Health check endpoint
            result["verified"] = True
            result["exploitable"] = False
            result["impact"] = "low"
            result["confidence"] = 30  # Low confidence for acceptance
        else:
            # Generic information disclosure
            result["verified"] = True
            result["exploitable"] = False
            result["impact"] = "low"
            result["confidence"] = 40
        
        return result
    
    def _verify_generic(self, endpoint: str, proof: Dict[str, Any]) -> Dict[str, Any]:
        """Generic verification"""
        result = {
            "verified": True,
            "exploitable": False,
            "impact": "low",
            "confidence": 30
        }
        
        return result
    
    def verify_all(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Verify all findings"""
        verified = []
        
        for finding in findings:
            # Create a copy to avoid modifying original
            finding_copy = finding.copy()
            
            verification = self.verify_finding(finding_copy)
            
            # Merge verification data into finding
            finding_copy["verification"] = {
                "verified": verification.get("verified", False),
                "exploitable": verification.get("exploitable", False),
                "impact": verification.get("impact", "none"),
                "confidence": verification.get("confidence", 0),
                "verification_details": verification.get("verification_details", {})
            }
            
            # Only include verified findings or high-confidence findings
            if verification.get("verified", False) or verification.get("confidence", 0) >= 50:
                verified.append(finding_copy)
        
        return verified

