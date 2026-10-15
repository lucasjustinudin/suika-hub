"""Suika Hub - async, modular web security scanning toolkit."""

from suika_hub._version import __version__

__author__ = "Suika Hub contributors"

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
