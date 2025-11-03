#!/usr/bin/env python3
"""
Client Tracking System
Simple CSV-based CRM for tracking clients, payments, and scans
"""

import csv
import sys
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional

# Paths
SCRIPT_DIR = Path(__file__).parent
REPO_ROOT = SCRIPT_DIR.parent
DATA_DIR = REPO_ROOT / "client_data"
CLIENTS_FILE = DATA_DIR / "clients.csv"
SCANS_FILE = DATA_DIR / "scans.csv"
PAYMENTS_FILE = DATA_DIR / "payments.csv"


def ensure_data_dir():
    """Ensure data directory and files exist"""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    
    # Create clients.csv if it doesn't exist
    if not CLIENTS_FILE.exists():
        with open(CLIENTS_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "client_id", "business_name", "contact_name", "email", "phone",
                "website", "status", "created_date", "notes"
            ])
    
    # Create scans.csv if it doesn't exist
    if not SCANS_FILE.exists():
        with open(SCANS_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "scan_id", "client_id", "website", "scan_date", "scan_type",
                "findings_count", "critical_count", "high_count", "medium_count",
                "low_count", "security_score", "report_path", "status"
            ])
    
    # Create payments.csv if it doesn't exist
    if not PAYMENTS_FILE.exists():
        with open(PAYMENTS_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "payment_id", "client_id", "scan_id", "amount", "payment_method",
                "payment_date", "payment_type", "status", "notes"
            ])


def add_client(
    business_name: str,
    contact_name: str,
    email: str,
    phone: str,
    website: str,
    notes: str = ""
) -> str:
    """Add a new client"""
    ensure_data_dir()
    
    # Generate client ID
    client_id = f"CLI-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    
    with open(CLIENTS_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            client_id,
            business_name,
            contact_name,
            email,
            phone,
            website,
            "active",
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            notes
        ])
    
    return client_id


def add_scan(
    client_id: str,
    website: str,
    scan_type: str = "emergency",
    findings_count: int = 0,
    critical_count: int = 0,
    high_count: int = 0,
    medium_count: int = 0,
    low_count: int = 0,
    security_score: int = 10,
    report_path: str = "",
    status: str = "completed"
) -> str:
    """Add a scan record"""
    ensure_data_dir()
    
    # Generate scan ID
    scan_id = f"ES-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    
    with open(SCANS_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            scan_id,
            client_id,
            website,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            scan_type,
            findings_count,
            critical_count,
            high_count,
            medium_count,
            low_count,
            security_score,
            report_path,
            status
        ])
    
    return scan_id


def add_payment(
    client_id: str,
    scan_id: str,
    amount: float,
    payment_method: str,
    payment_type: str = "emergency_scan",
    status: str = "completed",
    notes: str = ""
) -> str:
    """Add a payment record"""
    ensure_data_dir()
    
    # Generate payment ID
    payment_id = f"PAY-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    
    with open(PAYMENTS_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            payment_id,
            client_id,
            scan_id,
            amount,
            payment_method,
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            payment_type,
            status,
            notes
        ])
    
    return payment_id


def get_client(client_id: str) -> Optional[Dict[str, Any]]:
    """Get client by ID"""
    ensure_data_dir()
    
    with open(CLIENTS_FILE, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row["client_id"] == client_id:
                return row
    return None


def list_clients(status: str = "active") -> List[Dict[str, Any]]:
    """List all clients"""
    ensure_data_dir()
    
    clients = []
    with open(CLIENTS_FILE, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if not status or row["status"] == status:
                clients.append(row)
    return clients


def get_client_stats(client_id: str) -> Dict[str, Any]:
    """Get statistics for a client"""
    ensure_data_dir()
    
    # Count scans
    scans = []
    with open(SCANS_FILE, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row["client_id"] == client_id:
                scans.append(row)
    
    # Count payments
    payments = []
    total_revenue = 0.0
    with open(PAYMENTS_FILE, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if row["client_id"] == client_id and row["status"] == "completed":
                payments.append(row)
                total_revenue += float(row["amount"])
    
    return {
        "client_id": client_id,
        "total_scans": len(scans),
        "total_payments": len(payments),
        "total_revenue": total_revenue,
        "is_monthly_client": any(p.get("payment_type") == "monthly_service" for p in payments)
    }


def print_summary():
    """Print summary of all clients"""
    ensure_data_dir()
    
    clients = list_clients()
    
    print("\n" + "=" * 80)
    print("CLIENT TRACKING SUMMARY")
    print("=" * 80)
    print(f"\nTotal Active Clients: {len(clients)}")
    
    total_revenue = 0.0
    monthly_clients = 0
    
    for client in clients:
        stats = get_client_stats(client["client_id"])
        total_revenue += stats["total_revenue"]
        if stats["is_monthly_client"]:
            monthly_clients += 1
    
    print(f"Total Revenue: ${total_revenue:,.2f}")
    print(f"Monthly Service Clients: {monthly_clients}")
    print(f"Emergency Scan Clients: {len(clients) - monthly_clients}")
    print("\n" + "=" * 80 + "\n")


def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Client Tracking System")
    subparsers = parser.add_subparsers(dest="command", help="Command")
    
    # Add client command
    add_client_parser = subparsers.add_parser("add-client", help="Add a new client")
    add_client_parser.add_argument("--name", required=True, help="Business name")
    add_client_parser.add_argument("--contact", required=True, help="Contact name")
    add_client_parser.add_argument("--email", required=True, help="Email address")
    add_client_parser.add_argument("--phone", required=True, help="Phone number")
    add_client_parser.add_argument("--website", required=True, help="Website URL")
    add_client_parser.add_argument("--notes", default="", help="Notes")
    
    # Add scan command
    add_scan_parser = subparsers.add_parser("add-scan", help="Add a scan record")
    add_scan_parser.add_argument("--client-id", required=True, help="Client ID")
    add_scan_parser.add_argument("--website", required=True, help="Website URL")
    add_scan_parser.add_argument("--type", default="emergency", help="Scan type")
    add_scan_parser.add_argument("--findings", type=int, default=0, help="Total findings")
    add_scan_parser.add_argument("--critical", type=int, default=0, help="Critical findings")
    add_scan_parser.add_argument("--high", type=int, default=0, help="High findings")
    add_scan_parser.add_argument("--medium", type=int, default=0, help="Medium findings")
    add_scan_parser.add_argument("--low", type=int, default=0, help="Low findings")
    add_scan_parser.add_argument("--score", type=int, default=10, help="Security score")
    add_scan_parser.add_argument("--report", default="", help="Report path")
    
    # Add payment command
    add_payment_parser = subparsers.add_parser("add-payment", help="Add a payment record")
    add_payment_parser.add_argument("--client-id", required=True, help="Client ID")
    add_payment_parser.add_argument("--scan-id", required=True, help="Scan ID")
    add_payment_parser.add_argument("--amount", type=float, required=True, help="Payment amount")
    add_payment_parser.add_argument("--method", required=True, help="Payment method (PayPal/Venmo/Zelle)")
    add_payment_parser.add_argument("--type", default="emergency_scan", help="Payment type")
    add_payment_parser.add_argument("--notes", default="", help="Notes")
    
    # List clients command
    subparsers.add_parser("list", help="List all clients")
    
    # Summary command
    subparsers.add_parser("summary", help="Show summary statistics")
    
    args = parser.parse_args()
    
    if args.command == "add-client":
        client_id = add_client(
            business_name=args.name,
            contact_name=args.contact,
            email=args.email,
            phone=args.phone,
            website=args.website,
            notes=args.notes
        )
        print(f"✅ Client added: {client_id}")
    
    elif args.command == "add-scan":
        scan_id = add_scan(
            client_id=args.client_id,
            website=args.website,
            scan_type=args.type,
            findings_count=args.findings,
            critical_count=args.critical,
            high_count=args.high,
            medium_count=args.medium,
            low_count=args.low,
            security_score=args.score,
            report_path=args.report
        )
        print(f"✅ Scan added: {scan_id}")
    
    elif args.command == "add-payment":
        payment_id = add_payment(
            client_id=args.client_id,
            scan_id=args.scan_id,
            amount=args.amount,
            payment_method=args.method,
            payment_type=args.type,
            notes=args.notes
        )
        print(f"✅ Payment added: {payment_id}")
    
    elif args.command == "list":
        clients = list_clients()
        print("\nClients:")
        for client in clients:
            print(f"  {client['client_id']}: {client['business_name']} ({client['email']})")
    
    elif args.command == "summary":
        print_summary()
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

