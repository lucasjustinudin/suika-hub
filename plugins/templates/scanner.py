"""Suika Hub plugin template.

Copy this file (or the whole directory) and replace the scanner with your own
logic. Two ways to load it:

  1. Ad-hoc:    suika-hub scan -t https://target -m template --plugin ./my_plugin.py
  2. Installed: declare an entry point in the ``suika.plugins`` group in your
     package metadata, ``pip install .``, and it is discovered automatically.

A plugin is any class that subclasses ``BaseModule`` and implements
``async execute(target, client, config)``. The engine instantiates it and passes
a shared HTTP client.

Naming conventions:
  - Module ``name`` attribute: lowercase with underscores (e.g. "xss_pro")
  - Class name: CamelCase ending in Scanner (e.g. "XSSProScanner")
"""

from __future__ import annotations

from suika_hub.core.http import AsyncClient
from suika_hub.core.module import BaseModule, Finding


class TemplateScanner(BaseModule):
    """Example scanner demonstrating the plugin interface.

    Rename the class and set ``name`` to a unique identifier -- that value is
    what users pass to ``--module``.
    """

    name = "template"
    description = "Template scanner - demonstrates the plugin interface"

    async def execute(self, target: str, client: AsyncClient, config: dict) -> list[Finding]:
        """Run the scan.

        Args:
            target: Target URL or domain.
            client: Shared async HTTP client. ``await client.get(url)`` returns a
                dict with the keys ``url``, ``status``, ``body``, ``headers``,
                ``error`` and ``length``. It does not raise for HTTP error
                statuses, and network failures come back as ``status == 0`` with
                an ``error`` string -- so check those keys instead of catching
                exceptions. Read ``resp["status"]``, not ``resp.status``.
            config: Scan options; module-specific keys arrive here.

        Returns:
            The findings this module produced.
        """
        self.reset()

        url = f"{target.rstrip('/')}/robots.txt"
        response = await client.get(url)

        if response.get("error") is not None or response.get("status") != 200:
            # Nothing to report. Returning quietly beats emitting an
            # "unknown" finding: a finding without evidence is noise.
            return self.findings

        body = response.get("body")
        text = body if isinstance(body, str) else ""

        if "disallow" in text.lower():
            self.add_finding(
                severity="INFO",
                title="robots.txt lists disallowed paths",
                url=url,
                description="robots.txt enumerates paths the site asks crawlers not to index.",
                evidence=text[:500],
                impact="May reveal administrative or staging paths worth reviewing.",
                remediation="Confirm the listed paths do not expose sensitive functionality.",
            )

        return self.findings


def get_module() -> type[BaseModule]:
    """Return the scanner class.

    Required for file-based plugins loaded via ``--plugin``, and used as the
    entry-point target for installed plugins.
    """
    return TemplateScanner
