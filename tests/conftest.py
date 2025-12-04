"""
Pytest fixtures for Recon Bounty Stack tests.

Provides common fixtures for testing including temporary directories,
mock configurations, and sample data.
"""

import json
import tempfile
from collections.abc import Generator
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from recon_bounty_stack.core.config import Config


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def config(temp_dir: Path) -> Config:
    """Create a test configuration."""
    return Config(
        output_dir=temp_dir / "output",
        auth_dir=temp_dir / "authorizations",
        log_level="DEBUG",
    )


@pytest.fixture
def sample_targets() -> list[str]:
    """Sample target domains for testing."""
    return ["example.com", "test.example.com"]


@pytest.fixture
def sample_subdomains() -> list[str]:
    """Sample subdomains for testing."""
    return [
        "www.example.com",
        "api.example.com",
        "mail.example.com",
        "test.example.com",
    ]


@pytest.fixture
def sample_http_endpoints() -> list[dict]:
    """Sample HTTP endpoint data."""
    return [
        {
            "url": "https://www.example.com",
            "status-code": 200,
            "title": "Example Domain",
            "tech": ["Apache"],
        },
        {
            "url": "https://api.example.com",
            "status-code": 200,
            "title": "API Gateway",
            "tech": ["nginx"],
        },
    ]


@pytest.fixture
def sample_findings() -> list[dict]:
    """Sample Nuclei findings for testing."""
    return [
        {
            "template-id": "tech-detect",
            "host": "https://example.com",
            "matched-at": "https://example.com",
            "timestamp": datetime.now().isoformat(),
            "info": {
                "name": "Technology Detection",
                "severity": "info",
                "description": "Detected web technologies",
                "tags": ["tech"],
            },
        },
        {
            "template-id": "missing-x-frame-options",
            "host": "https://example.com",
            "matched-at": "https://example.com",
            "timestamp": datetime.now().isoformat(),
            "info": {
                "name": "Missing X-Frame-Options Header",
                "severity": "medium",
                "description": "The X-Frame-Options header is not set",
                "tags": ["headers", "security"],
            },
        },
        {
            "template-id": "sql-injection",
            "host": "https://example.com/search",
            "matched-at": "https://example.com/search?q=test",
            "timestamp": datetime.now().isoformat(),
            "info": {
                "name": "SQL Injection",
                "severity": "critical",
                "description": "SQL injection vulnerability detected",
                "tags": ["sqli", "owasp"],
                "cve-id": "CVE-2021-1234",
            },
        },
    ]


@pytest.fixture
def valid_authorization(temp_dir: Path) -> Path:
    """Create a valid authorization file."""
    auth_dir = temp_dir / "authorizations"
    auth_dir.mkdir(parents=True, exist_ok=True)

    auth_data = {
        "client_name": "Test Client",
        "target": "example.com",
        "scope": ["example.com", "*.example.com"],
        "start_date": datetime.now().isoformat(),
        "end_date": (datetime.now() + timedelta(days=30)).isoformat(),
        "authorized_by": "Test User",
        "authorized_by_email": "test@example.com",
        "authorized_by_title": "Security Manager",
    }

    auth_file = auth_dir / "example.com_authorization.json"
    with open(auth_file, "w") as f:
        json.dump(auth_data, f)

    return auth_file


@pytest.fixture
def mock_env(monkeypatch, temp_dir: Path) -> None:
    """Set up mock environment variables."""
    monkeypatch.setenv("OUTPUT_DIR", str(temp_dir / "output"))
    monkeypatch.setenv("AUTH_DIR", str(temp_dir / "authorizations"))
    monkeypatch.setenv("LOG_LEVEL", "DEBUG")
