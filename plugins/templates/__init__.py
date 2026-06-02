"""
Suika Plugin – Template
=======================
Copy this package to create your own Suika Hunter plugin.

Usage:
  1. Rename this directory (e.g. my_xss_scanner/)
  2. Edit scanner.py – implement your logic
  3. Install:  suika install ./my_xss_scanner
  4. Run:      suika scan -t https://target.com -m my_xss_scanner
"""

__version__ = "0.1.0"
__author__ = "Your Name"

from plugins.templates.scanner import TemplateScanner

__all__ = ["TemplateScanner"]


def get_module() -> type:
    """Entry point for pip-based plugin discovery."""
    return TemplateScanner
