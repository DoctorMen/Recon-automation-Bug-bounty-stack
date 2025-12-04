"""
Tests for utility modules.

Tests helper functions, safety checks, and legal authorization.
"""

import json
from datetime import datetime, timedelta
from pathlib import Path

from recon_bounty_stack.core.config import Config
from recon_bounty_stack.utils.helpers import (
    format_timestamp,
    parse_target,
    sanitize_filename,
    severity_to_emoji,
    truncate_string,
)
from recon_bounty_stack.utils.legal import LegalAuthorizationShield
from recon_bounty_stack.utils.safety import SafetyChecker


class TestHelpers:
    """Tests for helper functions."""

    def test_sanitize_filename_simple(self):
        """Test sanitizing a simple filename."""
        result = sanitize_filename("test-file.txt")
        assert result == "test-file.txt"

    def test_sanitize_filename_special_chars(self):
        """Test sanitizing filename with special characters."""
        result = sanitize_filename("test/file:name?")
        assert "/" not in result
        assert ":" not in result
        assert "?" not in result

    def test_sanitize_filename_max_length(self):
        """Test sanitizing filename respects max length."""
        long_name = "a" * 300
        result = sanitize_filename(long_name, max_length=100)
        assert len(result) <= 100

    def test_format_timestamp_iso(self):
        """Test formatting ISO timestamp."""
        ts = "2024-01-15T10:30:00"
        result = format_timestamp(ts)
        assert "2024-01-15" in result

    def test_format_timestamp_with_z(self):
        """Test formatting timestamp with Z suffix."""
        ts = "2024-01-15T10:30:00Z"
        result = format_timestamp(ts)
        assert "2024-01-15" in result

    def test_format_timestamp_invalid(self):
        """Test formatting invalid timestamp."""
        ts = "invalid"
        result = format_timestamp(ts)
        assert result == "invalid"  # Returns original on error

    def test_parse_target_domain(self):
        """Test parsing a domain name."""
        result = parse_target("example.com")
        assert result["domain"] == "example.com"
        assert result["scheme"] == "https"

    def test_parse_target_url(self):
        """Test parsing a full URL."""
        result = parse_target("https://example.com/path")
        assert result["domain"] == "example.com"
        assert result["path"] == "/path"

    def test_severity_to_emoji_critical(self):
        """Test emoji for critical severity."""
        assert severity_to_emoji("critical") == "🔴"

    def test_severity_to_emoji_high(self):
        """Test emoji for high severity."""
        assert severity_to_emoji("high") == "🟠"

    def test_severity_to_emoji_unknown(self):
        """Test emoji for unknown severity."""
        result = severity_to_emoji("unknown")
        assert result == "❓"

    def test_truncate_string_short(self):
        """Test truncating a short string."""
        result = truncate_string("short", max_length=10)
        assert result == "short"

    def test_truncate_string_long(self):
        """Test truncating a long string."""
        result = truncate_string("this is a long string", max_length=10)
        assert len(result) == 10
        assert result.endswith("...")


class TestLegalAuthorizationShield:
    """Tests for LegalAuthorizationShield class."""

    def test_shield_creation(self, temp_dir: Path):
        """Test creating an authorization shield."""
        shield = LegalAuthorizationShield(str(temp_dir))
        assert shield.auth_dir == temp_dir

    def test_check_unauthorized_target(self, temp_dir: Path):
        """Test checking an unauthorized target."""
        shield = LegalAuthorizationShield(str(temp_dir))
        authorized, reason, data = shield.check_authorization("unauthorized.com")

        assert not authorized
        assert "NO AUTHORIZATION FILE" in reason
        assert data is None

    def test_check_authorized_target(self, valid_authorization: Path):
        """Test checking an authorized target."""
        shield = LegalAuthorizationShield(str(valid_authorization.parent))
        authorized, reason, data = shield.check_authorization("example.com")

        assert authorized
        assert reason == "AUTHORIZED"
        assert data is not None
        assert data["client_name"] == "Test Client"

    def test_check_subdomain_in_scope(self, valid_authorization: Path):
        """Test checking a subdomain that's in scope."""
        shield = LegalAuthorizationShield(str(valid_authorization.parent))
        # Wildcard *.example.com should match sub.example.com
        authorized, reason, data = shield.check_authorization("sub.example.com")

        assert authorized

    def test_check_out_of_scope_target(self, valid_authorization: Path):
        """Test checking a target that's out of scope."""
        shield = LegalAuthorizationShield(str(valid_authorization.parent))
        authorized, reason, data = shield.check_authorization("other.com")

        assert not authorized
        assert "OUT OF SCOPE" in reason or "NO AUTHORIZATION" in reason

    def test_create_authorization_template(self, temp_dir: Path):
        """Test creating an authorization template."""
        shield = LegalAuthorizationShield(str(temp_dir))
        output_file = shield.create_authorization_template("test.com", "Test Corp")

        assert output_file.exists()
        with open(output_file) as f:
            data = json.load(f)
        assert data["client_name"] == "Test Corp"
        assert data["target"] == "test.com"
        assert "test.com" in data["scope"]

    def test_expired_authorization(self, temp_dir: Path):
        """Test checking an expired authorization."""
        auth_dir = temp_dir / "authorizations"
        auth_dir.mkdir(parents=True, exist_ok=True)

        # Create expired authorization
        auth_data = {
            "client_name": "Test Client",
            "target": "expired.com",
            "scope": ["expired.com"],
            "start_date": (datetime.now() - timedelta(days=60)).isoformat(),
            "end_date": (datetime.now() - timedelta(days=30)).isoformat(),
            "authorized_by": "Test User",
        }

        auth_file = auth_dir / "expired.com_authorization.json"
        with open(auth_file, "w") as f:
            json.dump(auth_data, f)

        shield = LegalAuthorizationShield(str(auth_dir))
        authorized, reason, data = shield.check_authorization("expired.com")

        assert not authorized
        assert "TIME WINDOW" in reason


class TestSafetyChecker:
    """Tests for SafetyChecker class."""

    def test_checker_creation(self, config: Config):
        """Test creating a safety checker."""
        checker = SafetyChecker(config=config)
        assert checker.config == config

    def test_verify_unauthorized_target(self, config: Config):
        """Test verifying an unauthorized target."""
        config.ensure_directories()
        checker = SafetyChecker(config=config)
        result = checker.verify_safe("unauthorized.com")

        assert not result

    def test_verify_all_unauthorized(self, config: Config):
        """Test verifying multiple unauthorized targets."""
        config.ensure_directories()
        checker = SafetyChecker(config=config)
        targets = ["target1.com", "target2.com"]
        all_safe, unsafe = checker.verify_all(targets)

        assert not all_safe
        assert len(unsafe) == 2

    def test_verify_authorized_target(self, config: Config, valid_authorization: Path):
        """Test verifying an authorized target."""
        config.auth_dir = valid_authorization.parent
        checker = SafetyChecker(config=config)
        result = checker.verify_safe("example.com")

        assert result
