"""
Configuration management for Recon Bounty Stack.

Handles loading configuration from environment variables, .env files,
and YAML configuration files.
"""

import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from pydantic import BaseModel, Field


class ScanConfig(BaseModel):
    """Configuration for scan operations."""

    timeout: int = Field(default=1800, description="Scan timeout in seconds")
    rate_limit: int = Field(default=150, description="Requests per second")
    threads: int = Field(default=50, description="Number of concurrent threads")
    retries: int = Field(default=2, description="Number of retries on failure")
    severity_filter: str = Field(
        default="medium,high,critical", description="Severity levels to report"
    )


class ToolPaths(BaseModel):
    """Paths to external security tools."""

    nuclei: str = Field(default="nuclei", description="Path to nuclei binary")
    httpx: str = Field(default="httpx", description="Path to httpx binary")
    subfinder: str = Field(default="subfinder", description="Path to subfinder binary")
    amass: str = Field(default="amass", description="Path to amass binary")
    dnsx: str = Field(default="dnsx", description="Path to dnsx binary")


class Config(BaseModel):
    """Main configuration for Recon Bounty Stack."""

    # Directories
    output_dir: Path = Field(default=Path("./output"), description="Output directory")
    auth_dir: Path = Field(default=Path("./authorizations"), description="Authorization files")
    log_level: str = Field(default="INFO", description="Logging level")

    # Scan configuration
    scan: ScanConfig = Field(default_factory=ScanConfig)

    # Tool paths
    tools: ToolPaths = Field(default_factory=ToolPaths)

    # API Keys (optional)
    hackerone_api_key: str | None = Field(default=None, description="HackerOne API key")
    bugcrowd_api_key: str | None = Field(default=None, description="Bugcrowd API key")
    discord_webhook_url: str | None = Field(default=None, description="Discord webhook URL")

    # Performance
    max_concurrent_scans: int = Field(default=5, description="Maximum concurrent scans")

    @classmethod
    def from_env(cls, env_file: Path | None = None) -> "Config":
        """Load configuration from environment variables.

        Args:
            env_file: Optional path to .env file

        Returns:
            Config instance populated from environment
        """
        # Load .env file if it exists
        if env_file and env_file.exists():
            load_dotenv(env_file)
        else:
            load_dotenv()  # Try default locations

        # Build config from environment
        return cls(
            output_dir=Path(os.getenv("OUTPUT_DIR", "./output")),
            auth_dir=Path(os.getenv("AUTH_DIR", "./authorizations")),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            scan=ScanConfig(
                timeout=int(os.getenv("SCAN_TIMEOUT", "1800")),
                rate_limit=int(os.getenv("RATE_LIMIT", "150")),
                threads=int(os.getenv("THREADS", "50")),
                retries=int(os.getenv("RETRIES", "2")),
                severity_filter=os.getenv("NUCLEI_SEVERITY", "medium,high,critical"),
            ),
            tools=ToolPaths(
                nuclei=os.getenv("NUCLEI_PATH", "nuclei"),
                httpx=os.getenv("HTTPX_PATH", "httpx"),
                subfinder=os.getenv("SUBFINDER_PATH", "subfinder"),
                amass=os.getenv("AMASS_PATH", "amass"),
                dnsx=os.getenv("DNSX_PATH", "dnsx"),
            ),
            hackerone_api_key=os.getenv("HACKERONE_API_KEY"),
            bugcrowd_api_key=os.getenv("BUGCROWD_API_KEY"),
            discord_webhook_url=os.getenv("DISCORD_WEBHOOK_URL"),
            max_concurrent_scans=int(os.getenv("MAX_CONCURRENT_SCANS", "5")),
        )

    def ensure_directories(self) -> None:
        """Create required directories if they don't exist."""
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.auth_dir.mkdir(parents=True, exist_ok=True)

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value by key.

        Args:
            key: Configuration key (supports dot notation)
            default: Default value if key not found

        Returns:
            Configuration value or default
        """
        try:
            value = self
            for part in key.split("."):
                if hasattr(value, part):
                    value = getattr(value, part)
                else:
                    return default
            return value
        except (AttributeError, KeyError):
            return default
