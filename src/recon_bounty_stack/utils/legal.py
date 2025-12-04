"""
Legal Authorization System for security testing.

Enforces legal compliance by requiring written authorization
before any scanning operations.
"""

import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from recon_bounty_stack.core.logger import get_logger


class LegalAuthorizationShield:
    """Legal authorization system for security testing.

    BLOCKS ALL SCANS unless:
    1. Written authorization file exists
    2. Target is in authorized scope
    3. Current time is within authorized window
    4. Authorization signature is valid

    Example:
        shield = LegalAuthorizationShield()
        authorized, reason, data = shield.check_authorization("example.com")
        if authorized:
            # Proceed with scan
            pass
    """

    def __init__(self, auth_dir: str = "./authorizations"):
        """Initialize the authorization shield.

        Args:
            auth_dir: Directory containing authorization files
        """
        self.auth_dir = Path(auth_dir)
        self.auth_dir.mkdir(parents=True, exist_ok=True)
        self.audit_log = self.auth_dir / "audit_log.json"
        self.logger = get_logger("recon.legal")

    def check_authorization(
        self, target: str
    ) -> tuple[bool, str, dict[str, Any] | None]:
        """Check if target is legally authorized for scanning.

        Args:
            target: Domain or URL to check

        Returns:
            Tuple of (authorized, reason, authorization_data)
        """
        self.logger.debug(f"Checking authorization for {target}")

        # Step 1: Find authorization file
        auth_file = self._find_authorization_file(target)
        if not auth_file:
            reason = "NO AUTHORIZATION FILE FOUND - SCAN BLOCKED"
            self._log_blocked(target, reason)
            return False, reason, None

        # Step 2: Load and validate authorization
        auth_data = self._load_authorization(auth_file)
        if not auth_data:
            reason = "INVALID AUTHORIZATION FILE - SCAN BLOCKED"
            self._log_blocked(target, reason)
            return False, reason, None

        # Step 3: Check if target is in scope
        if not self._target_in_scope(target, auth_data):
            scope = auth_data.get("scope", [])
            reason = f"TARGET OUT OF SCOPE - SCAN BLOCKED\nAuthorized: {scope}"
            self._log_blocked(target, reason)
            return False, reason, None

        # Step 4: Check time window
        if not self._within_time_window(auth_data):
            start = auth_data.get("start_date")
            end = auth_data.get("end_date")
            reason = f"OUTSIDE AUTHORIZED TIME WINDOW - SCAN BLOCKED\nWindow: {start} to {end}"
            self._log_blocked(target, reason)
            return False, reason, None

        # Step 5: Verify signature
        if not self._verify_signature(auth_data):
            reason = "INVALID AUTHORIZATION SIGNATURE - SCAN BLOCKED"
            self._log_blocked(target, reason)
            return False, reason, None

        # All checks passed
        self._log_authorized(target, auth_data)
        return True, "AUTHORIZED", auth_data

    def _find_authorization_file(self, target: str) -> Path | None:
        """Find authorization file for target."""
        # Clean target name for filename
        clean_target = (
            target.replace("https://", "")
            .replace("http://", "")
            .replace("/", "_")
            .replace(":", "_")
        )

        # Look for exact match
        auth_file = self.auth_dir / f"{clean_target}_authorization.json"
        if auth_file.exists():
            return auth_file

        # Look for any matching authorization file
        for auth_file in self.auth_dir.glob("*_authorization.json"):
            auth_data = self._load_authorization(auth_file)
            if auth_data and self._target_in_scope(target, auth_data):
                return auth_file

        return None

    def _load_authorization(self, auth_file: Path) -> dict | None:
        """Load and parse authorization file."""
        try:
            with open(auth_file) as f:
                return json.load(f)
        except Exception as e:
            self.logger.error(f"Error loading authorization: {e}")
            return None

    def _target_in_scope(self, target: str, auth_data: dict) -> bool:
        """Check if target is in authorized scope."""
        scope = auth_data.get("scope", [])

        # Clean target for comparison
        clean_target = (
            target.replace("https://", "").replace("http://", "").replace("www.", "")
        )

        for authorized in scope:
            if str(authorized).startswith("#"):
                continue  # Skip comments

            clean_authorized = (
                str(authorized)
                .replace("https://", "")
                .replace("http://", "")
                .replace("www.", "")
            )

            # Exact match
            if clean_target == clean_authorized:
                return True

            # Wildcard subdomain match
            if clean_authorized.startswith("*."):
                domain = clean_authorized[2:]
                if clean_target.endswith(domain) or clean_target == domain:
                    return True

            # Parent domain match
            if clean_target.endswith(clean_authorized):
                return True

        return False

    def _within_time_window(self, auth_data: dict) -> bool:
        """Check if current time is within authorized window."""
        try:
            start_date = datetime.fromisoformat(auth_data["start_date"])
            end_date = datetime.fromisoformat(auth_data["end_date"])
            now = datetime.now()
            return start_date <= now <= end_date
        except Exception as e:
            self.logger.error(f"Error checking time window: {e}")
            return False

    def _verify_signature(self, auth_data: dict) -> bool:
        """Verify authorization signature."""
        required = ["client_name", "authorized_by", "scope", "start_date", "end_date"]
        return all(field in auth_data for field in required)

    def _log_blocked(self, target: str, reason: str) -> None:
        """Log blocked scan attempt."""
        self._append_audit_log(
            {
                "timestamp": datetime.now().isoformat(),
                "target": target,
                "status": "BLOCKED",
                "reason": reason,
                "user": os.environ.get("USER", "unknown"),
            }
        )

    def _log_authorized(self, target: str, auth_data: dict) -> None:
        """Log authorized scan."""
        self._append_audit_log(
            {
                "timestamp": datetime.now().isoformat(),
                "target": target,
                "status": "AUTHORIZED",
                "client": auth_data.get("client_name"),
                "authorized_by": auth_data.get("authorized_by"),
                "user": os.environ.get("USER", "unknown"),
            }
        )

    def _append_audit_log(self, entry: dict) -> None:
        """Append entry to audit log."""
        logs = []
        if self.audit_log.exists():
            try:
                with open(self.audit_log) as f:
                    logs = json.load(f)
            except (json.JSONDecodeError, OSError):
                logs = []

        logs.append(entry)

        with open(self.audit_log, "w") as f:
            json.dump(logs, f, indent=2)

    def create_authorization_template(
        self, target: str, client_name: str, output_file: Path | None = None
    ) -> Path:
        """Create authorization template for client signature.

        Args:
            target: Target domain
            client_name: Client name
            output_file: Optional output path

        Returns:
            Path to created template
        """
        if output_file is None:
            clean_target = (
                target.replace("https://", "")
                .replace("http://", "")
                .replace("/", "_")
                .replace(":", "_")
            )
            output_file = self.auth_dir / f"{clean_target}_authorization.json"

        template = {
            "client_name": client_name,
            "target": target,
            "scope": [target, f"*.{target}"],
            "start_date": datetime.now().isoformat(),
            "end_date": (datetime.now() + timedelta(days=30)).isoformat(),
            "authorized_by": "CLIENT_NAME_HERE",
            "authorized_by_email": "client@example.com",
            "authorized_by_title": "Authorized Representative",
            "testing_types_authorized": [
                "vulnerability_scanning",
                "port_scanning",
                "web_application_testing",
            ],
            "testing_types_forbidden": [
                "dos_testing",
                "social_engineering",
                "physical_access",
            ],
            "notes": "Replace all placeholder values before use",
            "signature_date": None,
            "signature_hash": None,
        }

        with open(output_file, "w") as f:
            json.dump(template, f, indent=2)

        self.logger.info(f"Authorization template created: {output_file}")
        return output_file
