"""
Helper utilities for Recon Bounty Stack.

Common utility functions used across the package.
"""

from datetime import datetime


def sanitize_filename(name: str, max_length: int = 200) -> str:
    """Sanitize a string for use as a filename.

    Args:
        name: String to sanitize
        max_length: Maximum filename length

    Returns:
        Sanitized filename string
    """
    # Replace problematic characters
    sanitized = "".join(
        c if c.isalnum() or c in ("-", "_", ".") else "_" for c in name
    )
    return sanitized[:max_length]


def format_timestamp(timestamp: str, output_format: str = "%Y-%m-%d %H:%M:%S UTC") -> str:
    """Format ISO timestamp to readable format.

    Args:
        timestamp: ISO format timestamp string
        output_format: strftime format string

    Returns:
        Formatted timestamp string
    """
    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        return dt.strftime(output_format)
    except (ValueError, AttributeError):
        return timestamp


def parse_target(target: str) -> dict:
    """Parse a target string into components.

    Args:
        target: Domain or URL string

    Returns:
        Dictionary with parsed components
    """
    from urllib.parse import urlparse

    # Add scheme if not present
    if not target.startswith(("http://", "https://")):
        target = f"https://{target}"

    parsed = urlparse(target)
    return {
        "original": target,
        "scheme": parsed.scheme,
        "domain": parsed.netloc,
        "path": parsed.path,
        "query": parsed.query,
    }


def severity_to_color(severity: str) -> str:
    """Map severity level to terminal color code.

    Args:
        severity: Severity level (critical, high, medium, low, info)

    Returns:
        ANSI color code
    """
    colors = {
        "critical": "\033[91m",  # Red
        "high": "\033[93m",  # Yellow
        "medium": "\033[94m",  # Blue
        "low": "\033[92m",  # Green
        "info": "\033[90m",  # Gray
    }
    return colors.get(severity.lower(), "\033[0m")


def severity_to_emoji(severity: str) -> str:
    """Map severity level to emoji.

    Args:
        severity: Severity level

    Returns:
        Emoji string
    """
    emojis = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🟢",
        "info": "ℹ️",
    }
    return emojis.get(severity.lower(), "❓")


def truncate_string(s: str, max_length: int = 100, suffix: str = "...") -> str:
    """Truncate a string to a maximum length.

    Args:
        s: String to truncate
        max_length: Maximum length
        suffix: Suffix to add when truncated

    Returns:
        Truncated string
    """
    if len(s) <= max_length:
        return s
    return s[: max_length - len(suffix)] + suffix
