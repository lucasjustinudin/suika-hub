"""Suika Hunter - Async, Modular, AI-Powered Bug Bounty Scanner"""

__version__ = "2.0.0"
__author__ = "Suika Hunter Team"

from suika_hub.core.config import AuthConfig, ScanConfig
from suika_hub.core.engine import SuikaEngine
from suika_hub.core.module import BaseModule, Finding

__all__ = [
    "__version__",
    "ScanConfig",
    "AuthConfig",
    "SuikaEngine",
    "BaseModule",
    "Finding",
]
