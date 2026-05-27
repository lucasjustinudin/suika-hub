"""API Fuzzer - smart fuzzing with mutation and injection testing"""
import asyncio
import json
from typing import Dict, List
from rich.console import Console

from core.module import BaseModule, Finding
from core.http import AsyncClient

console = Console()


class APIFuzzer(BaseModule):
    """Smart API fuzzer with injection detection"""

    name = "api_fuzzer"
    description = "API fuzzing: SQLi, NoSQL injection, parameter tampering, boundary testing"

    # Injection payloads
    SQLI = [
        "' OR '1'='1",
        "' OR '1'='1'--",
        "1' OR '1'='1",
        "' UNION SELECT NULL--",
        "'; DROP TABLE users--",
        "1; WAITFOR DELAY '0:0:5'--",
    ]

    NOSQL = [
        '{"$ne": null}',
        '{"$gt": ""}',
        '{"$regex": ".*"}',
        '{"$where": "1==1"}',
        '{"$exists": true}',
    ]

    XSS = [
        "<script>alert(1)</script>",
        '"><img src=x onerror=alert(1)>',
        "javascript:alert(1)",
        "<svg/onload=alert(1)>",
        "{{7*7}}",  # SSTI
    ]

    BOUNDARY = [
        "",           # empty
        " ",          # space
        "null",       # null string
        "undefined",  # undefined
        "-1",         # negative
        "0",          # zero
        "99999999",   # large number
        "a" * 10000,  # buffer overflow
        "../../../etc/passwd",  # path traversal
        "%00",        # null byte
    ]

    async def execute(self, target: str, client: AsyncClient, config: Dict) -> List[Finding]:
        """Execute API fuzzing"""
        console.print("[bold cyan]API Fuzzer[/bold cyan] - Smart injection testing")

        endpoints = config.get("api_endpoints", config.get("endpoints", []))
        if not endpoints:
            # Auto-discover from common patterns
            endpoints = ["/api/login", "/api/search", "/api/users"]

        # Test each endpoint
        for endpoint in endpoints:
            url = f"{target}{endpoint}"

            # SQLi testing
            await self._test_sqli(url, client)

            # NoSQL injection
            await self._test_nosql(url, client)

            # XSS testing
            await self._test_xss(url, client)

            # Boundary testing
            await self._test_boundary(url, client)

        console.print(f"  [green]Fuzzing complete: {len(self.findings)} findings[/green]")
        return self.findings

    async def _test_sqli(self, url: str, client: AsyncClient):
        """Test for SQL injection"""
        for payload in self.SQLI:
            # Test in query params
            resp = await client.get(url, params={"q": payload, "id": payload})

            if self._detect_sqli_response(resp):
                self.add_finding(
                    severity="CRITICAL",
                    title=f"SQL Injection: {url}",
                    description=f"Endpoint vulnerable to SQL injection",
                    url=url,
                    evidence=f"Payload: {payload}, Status: {resp['status']}",
                    impact="Full database access, data exfiltration",
                    remediation="Use parameterized queries, input validation",
                )
                break  # One finding per endpoint

    async def _test_nosql(self, url: str, client: AsyncClient):
        """Test for NoSQL injection"""
        for payload in self.NOSQL:
            # Test in query params (MongoDB style)
            resp = await client.get(url, params={"username": payload, "password": payload})

            if self._detect_nosql_response(resp):
                self.add_finding(
                    severity="HIGH",
                    title=f"NoSQL Injection: {url}",
                    description="Endpoint vulnerable to NoSQL operator injection",
                    url=url,
                    evidence=f"Payload: {payload}, Status: {resp['status']}",
                    impact="Authentication bypass, data access",
                    remediation="Sanitize input, reject operator characters",
                )
                break

    async def _test_xss(self, url: str, client: AsyncClient):
        """Test for reflected XSS"""
        for payload in self.XSS:
            resp = await client.get(url, params={"q": payload, "name": payload})

            if resp["status"] == 200 and isinstance(resp["body"], str):
                if payload in resp["body"]:
                    self.add_finding(
                        severity="MEDIUM",
                        title=f"Reflected XSS: {url}",
                        description="User input reflected in response without sanitization",
                        url=url,
                        evidence=f"Payload reflected: {payload[:50]}",
                        impact="Session hijacking, phishing",
                        remediation="Encode output, implement CSP",
                    )
                    break

    async def _test_boundary(self, url: str, client: AsyncClient):
        """Test boundary conditions"""
        for payload in self.BOUNDARY:
            resp = await client.get(url, params={"id": payload, "page": payload})

            # Detect interesting responses
            if resp["status"] == 500:
                self.add_finding(
                    severity="LOW",
                    title=f"Server error on boundary input: {url}",
                    description=f"Server crashes on input: '{payload[:20]}'",
                    url=url,
                    evidence=f"Payload: {payload[:50]}, Status: 500",
                    impact="Potential DoS, error-based information disclosure",
                    remediation="Implement proper input validation and error handling",
                )
                break

            # Path traversal detection
            if "root:" in str(resp.get("body", "")) or "/etc/" in str(resp.get("body", "")):
                self.add_finding(
                    severity="CRITICAL",
                    title=f"Path Traversal: {url}",
                    description="Server-side file read via path traversal",
                    url=url,
                    evidence=f"Payload: {payload}",
                    impact="Arbitrary file read, credential exposure",
                    remediation="Validate and sanitize file paths",
                )

    def _detect_sqli_response(self, resp: Dict) -> bool:
        """Detect SQL injection indicators"""
        if resp["status"] == 500:
            body = str(resp.get("body", ""))
            indicators = ["sql", "syntax", "mysql", "postgresql", "sqlite", "oracle", "mssql"]
            return any(ind in body.lower() for ind in indicators)

        # Time-based detection would need timing comparison
        return False

    def _detect_nosql_response(self, resp: Dict) -> bool:
        """Detect NoSQL injection indicators"""
        if resp["status"] == 200:
            body = resp.get("body")
            # If operator payload returns data when it shouldn't
            if isinstance(body, dict) and body.get("data"):
                return True
            if isinstance(body, list) and len(body) > 0:
                return True
        if resp["status"] == 500:
            body = str(resp.get("body", ""))
            if "mongo" in body.lower() or "bson" in body.lower():
                return True
        return False
