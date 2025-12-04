"""
Tests for scanner modules.

Tests scanner base class and individual scanner implementations.
"""

from unittest.mock import MagicMock, patch

from recon_bounty_stack.core.config import Config
from recon_bounty_stack.scanners.base import BaseScanner
from recon_bounty_stack.scanners.httpx import HttpxScanner
from recon_bounty_stack.scanners.nuclei import NucleiScanner
from recon_bounty_stack.scanners.recon import ReconScanner


class ConcreteScanner(BaseScanner):
    """Concrete implementation of BaseScanner for testing."""

    def scan(self, targets: list[str]) -> dict:
        return {"targets": targets, "count": len(targets)}


class TestBaseScanner:
    """Tests for BaseScanner class."""

    def test_scanner_creation(self, config: Config):
        """Test creating a scanner."""
        scanner = ConcreteScanner(config=config, tool_name="test")
        assert scanner.config == config
        assert scanner.tool_name == "test"

    def test_get_tool_path_default(self, config: Config):
        """Test getting default tool path."""
        scanner = ConcreteScanner(config=config, tool_name="test")
        # For unknown tool, should return tool name
        path = scanner.get_tool_path()
        assert path == "test"

    def test_write_temp_file(self, config: Config):
        """Test writing temporary files."""
        config.ensure_directories()
        scanner = ConcreteScanner(config=config, tool_name="test")

        content = "test content\nline 2"
        temp_path = scanner.write_temp_file(content, "test.txt")

        assert temp_path.exists()
        assert temp_path.read_text() == content

    def test_cleanup_temp_files(self, config: Config):
        """Test cleaning up temporary files."""
        config.ensure_directories()
        scanner = ConcreteScanner(config=config, tool_name="test")

        # Create temp files
        file1 = scanner.write_temp_file("content1", "temp1.txt")
        file2 = scanner.write_temp_file("content2", "temp2.txt")

        assert file1.exists()
        assert file2.exists()

        # Cleanup
        scanner.cleanup_temp_files(file1, file2)

        assert not file1.exists()
        assert not file2.exists()


class TestReconScanner:
    """Tests for ReconScanner class."""

    def test_scanner_creation(self, config: Config):
        """Test creating a recon scanner."""
        scanner = ReconScanner(config=config)
        assert scanner.tool_name == "subfinder"

    @patch("shutil.which")
    @patch.object(ReconScanner, "run_command")
    def test_scan_with_mock(
        self,
        mock_run: MagicMock,
        mock_which: MagicMock,
        config: Config,
        sample_targets: list[str],
    ):
        """Test scanning with mocked external tools."""
        config.ensure_directories()
        mock_which.return_value = None  # Amass not available
        mock_run.return_value = MagicMock(returncode=0)

        scanner = ReconScanner(config=config)

        # Create mock subfinder output
        output_file = config.output_dir / "temp_subfinder.txt"
        output_file.write_text("www.example.com\napi.example.com\n")

        results = scanner.scan(sample_targets)

        assert "subdomains" in results
        assert "count" in results


class TestHttpxScanner:
    """Tests for HttpxScanner class."""

    def test_scanner_creation(self, config: Config):
        """Test creating an httpx scanner."""
        scanner = HttpxScanner(config=config)
        assert scanner.tool_name == "httpx"

    def test_scan_empty_targets(self, config: Config):
        """Test scanning with empty targets."""
        scanner = HttpxScanner(config=config)
        results = scanner.scan([])

        assert results["count"] == 0
        assert results["endpoints"] == []

    def test_scan_result_structure(self, config: Config):
        """Test the structure of scan results."""
        config.ensure_directories()
        scanner = HttpxScanner(config=config)

        # Write mock http.json output
        http_output = config.output_dir / "http.json"
        http_output.write_text("[]")

        results = scanner.scan([])

        assert "count" in results
        assert "https_count" in results


class TestNucleiScanner:
    """Tests for NucleiScanner class."""

    def test_scanner_creation(self, config: Config):
        """Test creating a nuclei scanner."""
        scanner = NucleiScanner(config=config)
        assert scanner.tool_name == "nuclei"

    def test_scan_empty_targets(self, config: Config):
        """Test scanning with empty targets."""
        scanner = NucleiScanner(config=config)
        results = scanner.scan([])

        assert results["count"] == 0
        assert results["findings"] == []

    def test_scan_result_structure(self, config: Config):
        """Test the structure of scan results."""
        config.ensure_directories()
        scanner = NucleiScanner(config=config)

        # Write mock nuclei output
        nuclei_output = config.output_dir / "nuclei-findings.json"
        nuclei_output.write_text("[]")

        results = scanner.scan([])

        assert "count" in results
        assert "severity_counts" in results
