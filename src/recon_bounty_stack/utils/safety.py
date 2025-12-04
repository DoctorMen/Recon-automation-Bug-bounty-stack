"""
Safety checker for verifying scan authorization.

Provides validation to ensure only authorized targets are scanned.
"""


from recon_bounty_stack.core.config import Config
from recon_bounty_stack.core.logger import get_logger
from recon_bounty_stack.utils.legal import LegalAuthorizationShield


class SafetyChecker:
    """Safety checker for scan authorization.

    Verifies that targets are properly authorized before scanning.

    Example:
        checker = SafetyChecker()
        if checker.verify_safe("example.com", "full_scan"):
            # Proceed with scan
            pass
    """

    def __init__(self, config: Config | None = None):
        """Initialize the safety checker.

        Args:
            config: Configuration object
        """
        self.config = config or Config.from_env()
        self.logger = get_logger("recon.safety")
        self.legal_shield = LegalAuthorizationShield(str(self.config.auth_dir))

    def verify_safe(self, target: str, scan_type: str = "default") -> bool:
        """Verify that a target is safe to scan.

        Args:
            target: Target domain or URL
            scan_type: Type of scan being performed

        Returns:
            True if target is authorized and safe to scan
        """
        self.logger.debug(f"Checking safety for {target} ({scan_type})")

        # Check legal authorization
        authorized, reason, auth_data = self.legal_shield.check_authorization(target)

        if not authorized:
            self.logger.warning(f"Target {target} not authorized: {reason}")
            return False

        self.logger.debug(f"Target {target} is authorized")
        return True

    def verify_all(self, targets: list[str], scan_type: str = "default") -> tuple[bool, list[str]]:
        """Verify all targets are safe to scan.

        Args:
            targets: List of targets
            scan_type: Type of scan

        Returns:
            Tuple of (all_safe, list of unsafe targets)
        """
        unsafe = []
        for target in targets:
            if not self.verify_safe(target, scan_type):
                unsafe.append(target)

        return len(unsafe) == 0, unsafe
