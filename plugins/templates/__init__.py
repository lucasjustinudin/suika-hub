"""Suika Hub plugin package - template.

Copy this directory to create your own plugin:

  1. Rename the directory (e.g. ``my_xss_scanner/``)
  2. Implement your scanner in ``scanner.py``
  3. Load it ad-hoc:
         suika-hub scan -t https://target -m <your_name> --plugin ./my_xss_scanner/
     or install it so it is discovered automatically (see ``setup_example.py``).
"""

from plugins.templates.scanner import TemplateScanner

__version__ = "0.1.0"
__all__ = ["TemplateScanner"]


def get_module() -> type:
    """Return the scanner class for directory-based discovery."""
    return TemplateScanner
