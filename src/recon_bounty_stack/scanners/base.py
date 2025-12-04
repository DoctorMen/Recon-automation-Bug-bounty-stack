"""
Base scanner class for all reconnaissance scanners.

Provides common functionality for subprocess management, logging,
and result handling.
"""

import subprocess
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

from recon_bounty_stack.core.config import Config
from recon_bounty_stack.core.logger import get_logger


class BaseScanner(ABC):
    """Abstract base class for all scanners.

    Subclasses must implement the scan() method to perform
    the actual scanning operation.

    Example:
        class MyScanner(BaseScanner):
            def scan(self, targets: list[str]) -> dict:
                # Implement scanning logic
                return {"findings": [...]}
    """

    def __init__(
        self,
        config: Config | None = None,
        tool_name: str = "scanner",
    ):
        """Initialize the scanner.

        Args:
            config: Configuration object
            tool_name: Name of the external tool to use
        """
        self.config = config or Config.from_env()
        self.tool_name = tool_name
        self.logger = get_logger(f"recon.{tool_name}")

    def check_tool(self) -> bool:
        """Check if the required external tool is available.

        Returns:
            True if tool is available, False otherwise
        """
        cmd = "where" if sys.platform == "win32" else "which"
        tool_path = self.get_tool_path()
        try:
            result = subprocess.run(
                [cmd, tool_path],
                capture_output=True,
                check=False,
            )
            return result.returncode == 0
        except Exception:
            return False

    def get_tool_path(self) -> str:
        """Get the path to the external tool.

        Returns:
            Path to the tool binary
        """
        # Check config for custom path
        if self.config and hasattr(self.config.tools, self.tool_name):
            return getattr(self.config.tools, self.tool_name)
        return self.tool_name

    def run_command(
        self,
        cmd: list[str],
        timeout: int | None = None,
        capture_output: bool = True,
    ) -> subprocess.CompletedProcess:
        """Run an external command with proper error handling.

        Args:
            cmd: Command and arguments to run
            timeout: Timeout in seconds
            capture_output: Whether to capture stdout/stderr

        Returns:
            CompletedProcess instance

        Raises:
            subprocess.TimeoutExpired: If command times out
            subprocess.CalledProcessError: If command fails
        """
        self.logger.debug(f"Running: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                timeout=timeout or self.config.scan.timeout,
                capture_output=capture_output,
                text=True,
                check=False,
            )
            return result
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Command timed out after {timeout}s")
            raise
        except Exception as e:
            self.logger.error(f"Command failed: {e}")
            raise

    def write_temp_file(self, content: str, filename: str) -> Path:
        """Write content to a temporary file in the output directory.

        Args:
            content: Content to write
            filename: Name for the temp file

        Returns:
            Path to the created file
        """
        temp_path = self.config.output_dir / filename
        temp_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path.write_text(content, encoding="utf-8")
        return temp_path

    def cleanup_temp_files(self, *files: Path) -> None:
        """Remove temporary files.

        Args:
            files: Paths to files to remove
        """
        for file_path in files:
            if file_path.exists():
                try:
                    file_path.unlink()
                except OSError as e:
                    self.logger.warning(f"Failed to remove {file_path}: {e}")

    @abstractmethod
    def scan(self, targets: list[str]) -> dict[str, Any]:
        """Perform the scanning operation.

        Args:
            targets: List of targets to scan

        Returns:
            Dictionary containing scan results
        """
        pass
