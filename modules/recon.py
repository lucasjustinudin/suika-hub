"""Reconnaissance scanner - subdomain enum + endpoint discovery"""
import asyncio
from typing import Dict, List
from urllib.parse import urlparse
from rich.console import Console

from core.module import BaseModule, Finding
from core.http import AsyncClient

console = Console()


class ReconScanner(BaseModule):
    """Fast passive + active reconnaissance"""

    name = "recon_scanner"
    description = "Subdomain enumeration, endpoint discovery, tech fingerprinting"

    COMMON_PATHS = [
        "/api", "/api/v1", "/api/v2", "/api/v3",
        "/graphql", "/graphiql",
        "/swagger", "/swagger.json", "/swagger-ui",
        "/docs", "/redoc", "/openapi.json",
        "/admin", "/dashboard", "/login", "/register",
        "/health", "/status", "/metrics", "/debug",
        "/.env", "/.git/config", "/robots.txt", "/sitemap.xml",
        "/wp-json", "/wp-admin",
        "/.well-known/security.txt",
    ]

    async def execute(self, target: str, client: AsyncClient, config: Dict) -> List[Finding]:
        """Run reconnaissance"""
        console.print("[bold cyan]Recon Scanner[/bold cyan] - Passive + active recon")

        domain = self._extract_domain(target)
        base_url = target if target.startswith("http") else f"https://{target}"

        # Stage 1: Subdomain enumeration (passive)
        subdomains = await self._enumerate_subdomains(domain, client)

        # Stage 2: Endpoint discovery
        await self._discover_endpoints(base_url, client)

        # Stage 3: Tech fingerprinting
        await self._fingerprint(base_url, client)

        console.print(f"  [green]Recon complete: {len(self.findings)} findings[/green]")
        return self.findings

    async def _enumerate_subdomains(self, domain: str, client: AsyncClient) -> List[str]:
        """Passive subdomain enumeration via crt.sh"""
        console.print("  [dim]Subdomain enumeration (crt.sh)[/dim]")

        resp = await client.get(f"https://crt.sh/?q=%.{domain}&output=json")

        subdomains = set()
        if resp["status"] == 200 and isinstance(resp["body"], list):
            for entry in resp["body"]:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    if sub and "*" not in sub:
                        subdomains.add(sub)

        if subdomains:
            self.add_finding(
                severity="INFO",
                title=f"Subdomain enumeration: {len(subdomains)} found",
                description="Subdomains discovered via certificate transparency",
                data={"subdomains": sorted(subdomains)[:50]},
            )
            console.print(f"  [green]Found {len(subdomains)} subdomains[/green]")

        return sorted(subdomains)

    async def _discover_endpoints(self, base_url: str, client: AsyncClient):
        """Active endpoint discovery"""
        console.print("  [dim]Endpoint discovery[/dim]")

        urls = [f"{base_url}{path}" for path in self.COMMON_PATHS]
        responses = await client.batch_get(urls)

        interesting = []
        for path, resp in zip(self.COMMON_PATHS, responses):
            if resp["status"] in (200, 301, 302, 403):
                interesting.append({
                    "path": path,
                    "status": resp["status"],
                    "length": resp.get("length", 0),
                })

                # Flag sensitive files
                if path in ("/.env", "/.git/config"):
                    self.add_finding(
                        severity="CRITICAL" if resp["status"] == 200 else "LOW",
                        title=f"Sensitive file accessible: {path}",
                        description=f"Sensitive file returned status {resp['status']}",
                        url=f"{base_url}{path}",
                        impact="Potential credential/source code exposure",
                        remediation="Block access to sensitive files via web server config",
                    )

                # Flag debug/admin endpoints
                if path in ("/debug", "/metrics", "/admin") and resp["status"] == 200:
                    self.add_finding(
                        severity="MEDIUM",
                        title=f"Debug/admin endpoint accessible: {path}",
                        url=f"{base_url}{path}",
                        impact="Information disclosure or unauthorized admin access",
                    )

        if interesting:
            self.add_finding(
                severity="INFO",
                title=f"Endpoint discovery: {len(interesting)} paths found",
                data={"endpoints": interesting},
            )

    async def _fingerprint(self, base_url: str, client: AsyncClient):
        """Technology fingerprinting from headers"""
        console.print("  [dim]Tech fingerprinting[/dim]")

        resp = await client.get(base_url)
        if resp["status"] == 0:
            return

        headers = resp.get("headers", {})
        tech = []

        # Server header
        server = headers.get("server", "")
        if server:
            tech.append(f"Server: {server}")

        # Framework detection
        powered_by = headers.get("x-powered-by", "")
        if powered_by:
            tech.append(f"Framework: {powered_by}")
            self.add_finding(
                severity="LOW",
                title=f"Server version disclosure: {powered_by}",
                url=base_url,
                description="X-Powered-By header reveals technology stack",
                remediation="Remove X-Powered-By header",
            )

        # Security headers check
        missing_security = []
        security_headers = [
            "strict-transport-security",
            "x-content-type-options",
            "x-frame-options",
            "content-security-policy",
        ]
        for h in security_headers:
            if h not in headers:
                missing_security.append(h)

        if missing_security:
            self.add_finding(
                severity="LOW",
                title=f"Missing security headers: {len(missing_security)}",
                description=f"Missing: {', '.join(missing_security)}",
                url=base_url,
                remediation="Add recommended security headers",
            )

    def _extract_domain(self, target: str) -> str:
        """Extract domain from URL or string"""
        if target.startswith("http"):
            return urlparse(target).netloc
        return target
