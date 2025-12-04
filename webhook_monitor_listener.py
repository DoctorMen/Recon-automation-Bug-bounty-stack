#!/usr/bin/env python3
"""
Webhook Monitor Listener
Receives real-time program updates via webhook and triggers fast checks.
Replaces polling with event-driven monitoring.

Usage:
1. Start listener: python3 webhook_monitor_listener.py
2. Configure platforms to send webhooks to http://localhost:8080/webhook
3. Listener triggers fast checks on new assets automatically.
"""

import json
import subprocess
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from datetime import datetime
import urllib.parse

class WebhookHandler(BaseHTTPRequestHandler):
    def _set_response(self, status_code=200, content_type="application/json"):
        self.send_response(status_code)
        self.send_header("Content-type", content_type)
        self.end_headers()

    def do_POST(self):
        content_length = int(self.headers["Content-Length"])
        post_data = self.rfile.read(content_length)
        try:
            data = json.loads(post_data.decode("utf-8"))
        except json.JSONDecodeError:
            self._set_response(400)
            self.wfile.write(b'{"error": "Invalid JSON"}')
            return

        # Parse webhook payload (platform-specific)
        event_type = self.headers.get("X-Event-Type", "unknown")
        print(f"[*] Received webhook event: {event_type}")
        print(f"    Data: {json.dumps(data, indent=2)}")

        # Trigger fast check if new asset detected
        if self._is_new_asset_event(data, event_type):
            self._trigger_fast_check(data)

        # Acknowledge receipt
        self._set_response(200)
        response = {"status": "received", "timestamp": datetime.utcnow().isoformat() + "Z"}
        self.wfile.write(json.dumps(response).encode())

    def do_GET(self):
        # Simple health check
        self._set_response(200, "text/plain")
        self.wfile.write(b"Webhook listener is running")

    def _is_new_asset_event(self, data, event_type):
        """
        Determine if webhook represents a new asset or scope change.
        Customize for each platform (HackerOne, Bugcrowd, etc.).
        """
        # Example: HackerOne program update
        if event_type == "program.updated" and "program" in data:
            program = data["program"]
            # Check if scope changed
            if "scope" in program.get("changes", {}):
                return True
        # Example: New domain added
        if event_type == "asset.added" and "asset" in data:
            return True
        # Generic: if payload contains "new_assets" key
        if "new_assets" in data:
            return True
        return False

    def _trigger_fast_check(self, data):
        """Parse data and run fast check on new assets."""
        # Extract program name and new assets
        program_name = data.get("program", {}).get("name", "unknown")
        new_assets = data.get("new_assets", [])
        if not new_assets and "asset" in data:
            new_assets = [data["asset"]]

        if not new_assets:
            print(f"[-] No new assets found in webhook for {program_name}")
            return

        print(f"[+] Triggering fast checks for {program_name} ({len(new_assets)} new assets)")
        # Run fast check in background thread
        threading.Thread(
            target=self._run_fast_check,
            args=(program_name, new_assets),
            daemon=True
        ).start()

    def _run_fast_check(self, program_name, assets):
        """Run fast check on new assets."""
        # Create temporary file with assets
        temp_file = Path(f"webhook_assets_{program_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump({"program": program_name, "assets": assets}, f, indent=2)

        # Use your existing fast check logic (e.g., check_live.py)
        results = []
        for asset in assets:
            host = asset.get("host", "")
            path = asset.get("path", "")
            if not host:
                continue
            try:
                # Simple liveness check
                result = subprocess.run(
                    ["python3", "check_live.py"],
                    input=f"{host}{path}\n",
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                alive = result.returncode == 0 and result.stdout.strip()
                results.append({
                    "host": host,
                    "path": path,
                    "alive": alive,
                    "checked_at": datetime.utcnow().isoformat() + "Z"
                })
            except Exception as e:
                print(f"[!] Fast check failed for {host}{path}: {e}")
                results.append({
                    "host": host,
                    "path": path,
                    "alive": False,
                    "error": str(e),
                    "checked_at": datetime.utcnow().isoformat() + "Z"
                })

        # Save results
        results_file = Path(f"webhook_fast_checks_{program_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        with open(results_file, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        print(f"[+] Saved webhook fast check results to {results_file}")

        # Clean up temp file
        temp_file.unlink(missing_ok=True)

    def log_message(self, format, *args):
        # Suppress default server logging
        pass

def run_server(port=8080):
    """Run webhook listener server."""
    server_address = ("", port)
    httpd = HTTPServer(server_address, WebhookHandler)
    print(f"[*] Webhook listener started on http://localhost:{port}")
    print("[*] Configure platforms to send webhooks to /webhook")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped by user")

if __name__ == "__main__":
    run_server()
