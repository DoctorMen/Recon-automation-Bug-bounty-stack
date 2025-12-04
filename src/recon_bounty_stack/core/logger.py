"""
Centralized logging for Recon Bounty Stack.

Provides a consistent logging interface with rich formatting
for console output and optional file logging.
"""

import logging
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler

# Global console for rich output
console = Console()

# Module-level cache for loggers
_loggers: dict = {}


def get_logger(
    name: str = "recon_bounty_stack",
    level: str = "INFO",
    log_file: Path | None = None,
) -> logging.Logger:
    """Get or create a logger with the specified configuration.

    Args:
        name: Logger name (usually module name)
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Optional path to log file

    Returns:
        Configured logger instance
    """
    # Return cached logger if it exists
    cache_key = f"{name}:{level}:{log_file}"
    if cache_key in _loggers:
        return _loggers[cache_key]

    # Create new logger
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Clear existing handlers
    logger.handlers.clear()

    # Add rich console handler for pretty output
    console_handler = RichHandler(
        console=console,
        show_time=True,
        show_path=False,
        markup=True,
        rich_tracebacks=True,
    )
    console_handler.setLevel(getattr(logging, level.upper(), logging.INFO))
    console_format = logging.Formatter("%(message)s")
    console_handler.setFormatter(console_format)
    logger.addHandler(console_handler)

    # Add file handler if specified
    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)  # Always log everything to file
        file_format = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)

    # Prevent propagation to root logger
    logger.propagate = False

    # Cache the logger
    _loggers[cache_key] = logger

    return logger


def log_to_file(message: str, log_file: Path) -> None:
    """Write a log message directly to a file.

    Args:
        message: Message to log
        log_file: Path to log file
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_msg = f"[{timestamp}] {message}\n"
    log_file.parent.mkdir(parents=True, exist_ok=True)
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(log_msg)


class ScanLogger:
    """Context manager for scan-specific logging.

    Usage:
        with ScanLogger("my_scan", output_dir) as logger:
            logger.info("Starting scan...")
            # ... do scan ...
            logger.info("Scan complete!")
    """

    def __init__(self, scan_name: str, output_dir: Path, level: str = "INFO"):
        """Initialize scan logger.

        Args:
            scan_name: Name of the scan (used in log filename)
            output_dir: Directory to store log file
            level: Logging level
        """
        self.scan_name = scan_name
        self.output_dir = output_dir
        self.level = level
        self.log_file = output_dir / f"{scan_name}.log"
        self._logger: logging.Logger | None = None

    def __enter__(self) -> logging.Logger:
        """Enter context and return logger."""
        self._logger = get_logger(
            name=f"recon.{self.scan_name}",
            level=self.level,
            log_file=self.log_file,
        )
        self._logger.info(f"=== {self.scan_name.upper()} Started ===")
        return self._logger

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Exit context and log completion status."""
        if self._logger:
            if exc_type:
                self._logger.error(f"=== {self.scan_name.upper()} Failed: {exc_val} ===")
            else:
                self._logger.info(f"=== {self.scan_name.upper()} Complete ===")
