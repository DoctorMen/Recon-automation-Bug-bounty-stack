"""
Recon Bounty Stack - Automated Bug Bounty Reconnaissance Toolkit

A professional-grade reconnaissance automation framework for authorized
security testing and bug bounty hunting.

Usage:
    from recon_bounty_stack import Pipeline

    pipeline = Pipeline()
    results = pipeline.run(targets=["example.com"])

CLI Usage:
    recon-bounty scan example.com --mode quick
    recon-bounty status
"""

__version__ = "2.0.0"
__author__ = "DoctorMen"
__license__ = "Proprietary"

from recon_bounty_stack.core.config import Config
from recon_bounty_stack.core.logger import get_logger
from recon_bounty_stack.core.pipeline import Pipeline

__all__ = [
    "Pipeline",
    "Config",
    "get_logger",
    "__version__",
]
