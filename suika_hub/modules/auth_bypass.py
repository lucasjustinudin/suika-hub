"""Authentication bypass scanner"""
from rich.console import Console

from suika_hub.core.http import AsyncClient
from suika_hub.core.module import BaseModule, Finding

console = Console()


class AuthBypassScanner(BaseModule):
    """Test authentication and authorization bypass techniques"""

    name = "auth_bypass"
    description = "Authentication bypass, privilege escalation, JWT attacks"

    # HTTP method override headers
    METHOD_OVERRIDES = [
        ("X-HTTP-Method-Override", "GET"),
        ("X-HTTP-Method", "GET"),
        ("X-Method-Override", "GET"),
    ]

    # Auth bypass headers
    BYPASS_HEADERS = [
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Forwarded-Host": "localhost"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
    ]

    # Path bypass techniques
    PATH_BYPASSES = [
        "/admin",
        "/admin/",
        "/admin/.",
        "//admin",
        "/./admin",
        "/admin%20",
        "/admin%09",
        "/admin..;/",
        "/ADMIN",
        "/admin;",
    ]

    async def execute(self, target: str, client: AsyncClient, config: dict) -> list[Finding]:
        """Execute auth bypass testing"""
        console.print("[bold cyan]Auth Bypass Scanner[/bold cyan] - Testing authentication boundaries")

        # Stage 1: Test endpoints without auth
        await self._test_no_auth(target, client, config)

        # Stage 2: Header-based bypass
        await self._test_header_bypass(target, client)

        # Stage 3: Path manipulation bypass
        await self._test_path_bypass(target, client)

        # Stage 4: Method tampering
        await self._test_method_tampering(target, client, config)

        # Stage 5: Role escalation
        await self._test_role_escalation(target, client, config)

        console.print(f"  [green]Auth bypass scan complete: {len(self.findings)} findings[/green]")
        return self.findings

    async def _test_no_auth(self, target: str, client: AsyncClient, config: dict):
        """Test endpoints without authentication"""
        console.print("  [dim]Testing unauthenticated access[/dim]")

        # Create client without auth
        no_auth = AsyncClient(cookies={}, headers={}, concurrency=3, delay=client.delay)

        endpoints = config.get("auth_endpoints", [
            "/api/admin",
            "/api/users",
            "/api/settings",
            "/api/config",
            "/api/internal",
        ])

        async with no_auth:
            for ep in endpoints:
                resp = await no_auth.get(f"{target}{ep}")

                if resp["status"] == 200 and self._has_data(resp):
                    self.add_finding(
                        severity="HIGH",
                        title=f"No authentication required: {ep}",
                        description="Endpoint returns data without any authentication",
                        url=f"{target}{ep}",
                        impact="Unauthenticated data access",
                        remediation="Require authentication for all sensitive endpoints",
                    )

    async def _test_header_bypass(self, target: str, client: AsyncClient):
        """Test header-based auth bypass"""
        console.print("  [dim]Testing header bypass[/dim]")

        for bypass_headers in self.BYPASS_HEADERS:
            resp = await client.get(
                f"{target}/admin",
                headers=bypass_headers,
            )

            if resp["status"] == 200:
                self.add_finding(
                    severity="HIGH",
                    title=f"Auth bypass via headers: {list(bypass_headers.keys())[0]}",
                    description="Authentication bypassed using special headers",
                    url=f"{target}/admin",
                    evidence=f"Headers: {bypass_headers}",
                    impact="Unauthorized admin access",
                    remediation="Do not trust client-supplied headers for authorization",
                )

    async def _test_path_bypass(self, target: str, client: AsyncClient):
        """Test path manipulation bypass"""
        console.print("  [dim]Testing path bypass[/dim]")

        # First get baseline (should be 403/401)
        baseline = await client.get(f"{target}/admin")
        if baseline["status"] == 200:
            return  # Already accessible, not a bypass

        for path in self.PATH_BYPASSES:
            resp = await client.get(f"{target}{path}")

            if resp["status"] == 200 and self._has_data(resp):
                self.add_finding(
                    severity="HIGH",
                    title=f"Path bypass: {path} returns 200",
                    description="Authentication bypassed via path manipulation",
                    url=f"{target}{path}",
                    evidence=f"Original /admin returned {baseline['status']}, bypass returned 200",
                    impact="Unauthorized access to restricted areas",
                    remediation="Normalize paths before authorization checks",
                )
                break  # One finding is enough

    async def _test_method_tampering(self, target: str, client: AsyncClient, config: dict):
        """Test HTTP method tampering"""
        console.print("  [dim]Testing method tampering[/dim]")

        endpoints = config.get("method_test_endpoints", ["/api/admin", "/api/users"])

        for ep in endpoints:
            # Try different methods
            for method in ["PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]:
                resp = await client.request(method, f"{target}{ep}")

                if resp["status"] == 200 and method in ("PUT", "PATCH", "DELETE"):
                    self.add_finding(
                        severity="MEDIUM",
                        title=f"Method tampering: {method} {ep} returns 200",
                        description=f"Endpoint accepts {method} method unexpectedly",
                        url=f"{target}{ep}",
                        impact="Potential unauthorized data modification/deletion",
                        remediation="Restrict allowed HTTP methods per endpoint",
                    )

    async def _test_role_escalation(self, target: str, client: AsyncClient, config: dict):
        """Test role/privilege escalation"""
        console.print("  [dim]Testing role escalation[/dim]")

        # Try to modify own role
        escalation_payloads = [
            {"role": "admin"},
            {"is_admin": True},
            {"privilege": "admin"},
            {"user_type": "administrator"},
            {"permissions": ["admin", "write", "delete"]},
        ]

        profile_endpoints = ["/api/user/me", "/api/profile", "/api/account"]

        for ep in profile_endpoints:
            for payload in escalation_payloads:
                resp = await client.put(
                    f"{target}{ep}",
                    json=payload,
                )

                if resp["status"] == 200:
                    body = resp.get("body", {})
                    # Check if role actually changed
                    if isinstance(body, dict) and (body.get("role") == "admin" or body.get("is_admin") is True):
                            self.add_finding(
                                severity="CRITICAL",
                                title=f"Privilege escalation: mass assignment at {ep}",
                                description="User can escalate privileges via mass assignment",
                                url=f"{target}{ep}",
                                evidence=f"Payload: {payload}, Response indicates role change",
                                impact="Full admin access, complete system compromise",
                                remediation="Whitelist allowed fields in update operations",
                            )

    def _has_data(self, resp: dict) -> bool:
        """Check if response has meaningful data"""
        body = resp.get("body")
        if isinstance(body, dict):
            return bool(body.get("data") or len(body) > 2)
        if isinstance(body, str):
            return len(body) > 100 and "not found" not in body.lower()
        return False
