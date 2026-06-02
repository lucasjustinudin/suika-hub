"""
Suika Plugin Template
=====================
Copy this directory to create your own plugin.

Structure:
  my_plugin/
  ├── __init__.py        ← must export get_module() -> Type[BaseModule]
  ├── scanner.py         ← your scanner logic (this file)
  ├── plugin.json        ← optional manifest
  └── requirements.txt   ← optional extra deps

Quick start:
  1. Copy this directory to your project
  2. Rename and implement your scanner in scanner.py
  3. Test:  python -c "from my_plugin.scanner import MyScanner; print(MyScanner)"
  4. Install:  suika install /path/to/my_plugin/

Naming conventions:
  - Module `name` attribute: lowercase, underscores  (e.g. "xss_pro")
  - Class name: CamelCase + Scanner                   (e.g. "XSSProScanner")
"""

from typing import Dict, List

from core.module import BaseModule, Finding
from core.http import AsyncClient


class TemplateScanner(BaseModule):
    """
    Example vulnerability scanner plugin.

    Replace this docstring with your module's description.
    This text is shown in `suika list-plugins`.
    """

    name = "template"          # unique identifier, used in --module flag
    description = "Template scanner – demonstrates the plugin interface"

    async def execute(self, target: str, client: AsyncClient, config: Dict) -> List[Finding]:
        """
        Main entry point called by the Suika engine.

        Args:
            target:  Target URL or domain string
            client:  Shared async HTTP client (from core.http)
            config:  ScanConfig dict (.target, .auth, .delay, etc.)

        Returns:
            List of Finding dicts
        """
        self.reset()
        findings: List[Finding] = []

        # ── Example: probe a single endpoint ─────────────────────────────
        url = f"{target.rstrip('/')}/example"
        try:
            resp = await client.get(url)

            # Check for a vulnerability condition
            if resp.status == 200 and "secret" in resp.text.lower():
                findings.append(self.add_finding(
                    severity="HIGH",
                    title="Example vulnerability found",
                    url=url,
                    description="The /example endpoint leaks sensitive data.",
                    evidence=resp.text[:500],
                    impact="Attackers can read sensitive information.",
                    remediation="Remove sensitive data from /example response.",
                ))
        except Exception:
            pass

        # ── Example: add an informational finding ────────────────────────
        findings.append(self.add_finding(
            severity="INFO",
            title="Template scan completed",
            url=target,
            description="This is a placeholder finding from the template plugin.",
        ))

        return findings


# ── Plugin entry point ───────────────────────────────────────────────────────
# The plugin system calls get_module() to discover your scanner class.
# This is also used as the entry-point in setup.py/pyproject.toml.

def get_module() -> type:
    """Return the scanner class. Required for pip-based plugins."""
    return TemplateScanner
