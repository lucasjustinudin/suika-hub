"""RedStorm platform scanner - specialized for rswebapppltf"""
from rich.console import Console

from suika_hub.core.http import AsyncClient
from suika_hub.core.module import BaseModule, Finding

console = Console()


class RedStormScanner(BaseModule):
    """Specialized scanner for RedStorm bug bounty platform"""

    name = "redstorm_scanner"
    description = "RedStorm platform vulnerability scanner (leaderboard IDOR, program enum, endpoint testing)"

    BASE = "https://www.redstorm.io"

    # Known endpoints from previous recon
    ENDPOINTS = [
        "/api/researcher/me",
        "/api/researcher/profile",
        "/api/researcher/user",
        "/api/researcher/account",
        "/api/researcher/info",
        "/api/researcher/dashboard",
        "/api/researcher/notification",
        "/api/researcher/notifications",
        "/api/researcher/submission",
        "/api/researcher/submissions",
        "/api/researcher/halloffame",
        "/api/researcher/leaderboard",
        "/api/researcher/program-list",
        "/api/admin/program-list",
        "/api/customer/program-list",
    ]

    PROGRAM_SLUGS = [
        "admin", "test", "staging", "internal", "dev", "private",
        "demo", "honestbankweb", "honestbankapp", "xlprioritas",
        "rswebapppltf", "production", "beta", "alpha", "sandbox",
        "qa", "uat", "pentest", "security",
    ]

    async def execute(self, target: str, client: AsyncClient, config: dict) -> list[Finding]:
        """Run all RedStorm-specific tests"""
        base = target if target.startswith("http") else self.BASE

        console.print("[bold cyan]RedStorm Scanner[/bold cyan] - Starting 5-stage assessment")

        # Stage 1: Leaderboard enumeration
        usernames = await self._stage_leaderboard(base, client)

        # Stage 2: IDOR testing
        if usernames:
            await self._stage_idor(base, client, usernames)

        # Stage 3: Program slug enumeration
        await self._stage_programs(base, client)

        # Stage 4: Endpoint enumeration
        await self._stage_endpoints(base, client)

        # Stage 5: Authorization boundary testing
        await self._stage_authz(base, client)

        console.print(f"[bold green]RedStorm Scanner complete:[/bold green] {len(self.findings)} findings")
        return self.findings

    async def _stage_leaderboard(self, base: str, client: AsyncClient) -> list[str]:
        """Stage 1: Extract usernames from leaderboard"""
        console.print("  [dim]Stage 1: Leaderboard enumeration[/dim]")

        resp = await client.get(f"{base}/api/researcher/leaderboard")

        if resp["error"] == "cloudflare_challenge":
            console.print("  [yellow]Cloudflare detected - need browser mode or valid cookies[/yellow]")
            return []

        if resp["status"] != 200:
            console.print(f"  [yellow]Leaderboard returned {resp['status']}[/yellow]")
            return []

        body = resp["body"]
        if not isinstance(body, dict):
            return []

        # Extract usernames from various response shapes
        usernames = []
        leaderboard = body.get("leaderboard", body.get("data", []))

        if isinstance(leaderboard, list):
            for entry in leaderboard:
                if isinstance(entry, dict):
                    uid = entry.get("username") or entry.get("user_id") or entry.get("id") or entry.get("_id")
                    if uid:
                        usernames.append(str(uid))

                        # Check for sensitive data in leaderboard
                        sensitive = [k for k in entry.keys() if k in (
                            "email", "phone", "is_admin", "role", "token",
                            "password_hash", "api_key", "address"
                        )]
                        if sensitive:
                            self.add_finding(
                                severity="HIGH",
                                title=f"Leaderboard exposes sensitive fields: {sensitive}",
                                description="Leaderboard response contains sensitive user data",
                                url=f"{base}/api/researcher/leaderboard",
                                evidence=f"Fields: {sensitive}, Sample user: {uid}",
                                impact="User PII/credential exposure",
                                remediation="Remove sensitive fields from leaderboard response",
                            )

        if usernames:
            self.add_finding(
                severity="LOW",
                title=f"User enumeration via leaderboard: {len(usernames)} users",
                description="Leaderboard exposes user identifiers that can be used for IDOR testing",
                url=f"{base}/api/researcher/leaderboard",
                evidence=f"Sample: {usernames[:3]}",
                data={"usernames": usernames[:20]},
            )
            console.print(f"  [green]Found {len(usernames)} usernames[/green]")
        else:
            console.print("  [yellow]No usernames extracted[/yellow]")

        return usernames

    async def _stage_idor(self, base: str, client: AsyncClient, usernames: list[str]):
        """Stage 2: Test IDOR on user-specific endpoints"""
        console.print("  [dim]Stage 2: IDOR testing[/dim]")

        # Test with first 3 usernames
        targets = usernames[:3]

        idor_endpoints = [
            "/api/researcher/submission/{uid}/label_to_content/1",
            "/api/researcher/submission/{uid}/label_to_content/2",
            "/api/researcher/profile/{uid}",
            "/api/researcher/user/{uid}",
            "/api/researcher/submissions/{uid}",
            "/api/researcher/report/{uid}",
        ]

        for uid in targets:
            for pattern in idor_endpoints:
                endpoint = pattern.format(uid=uid)
                resp = await client.get(f"{base}{endpoint}")

                if resp["status"] == 200 and resp["body"]:
                    # Check if response contains actual data
                    body = resp["body"]
                    has_data = False

                    if isinstance(body, dict):
                        # Filter out empty/error responses
                        if body.get("data") or body.get("submission") or body.get("profile"):
                            has_data = True
                        # Check for sensitive fields
                        sensitive = self._find_sensitive_fields(body)
                        if sensitive:
                            has_data = True

                    if has_data:
                        self.add_finding(
                            severity="HIGH",
                            title=f"IDOR: Cross-user data access at {pattern}",
                            description="Authenticated user can access another user's data",
                            url=f"{base}{endpoint}",
                            evidence=f"Target user: {uid}, Status: 200, Has data: True",
                            impact="Unauthorized access to user submissions/profile data",
                            remediation="Implement proper authorization - verify requesting user owns the resource",
                        )
                        console.print(f"  [bold red]IDOR FOUND: {endpoint}[/bold red]")

    async def _stage_programs(self, base: str, client: AsyncClient):
        """Stage 3: Enumerate program slugs"""
        console.print("  [dim]Stage 3: Program enumeration[/dim]")

        accessible = []

        # Batch requests for speed
        urls = [f"{base}/api/researcher/program/{slug}" for slug in self.PROGRAM_SLUGS]
        responses = await client.batch_get(urls)

        for slug, resp in zip(self.PROGRAM_SLUGS, responses):
            if resp["status"] == 200:
                accessible.append(slug)

                # Check if it's a private/internal program
                body = resp["body"]
                if isinstance(body, dict):
                    is_private = body.get("is_private") or body.get("visibility") == "private"
                    if is_private or slug in ("admin", "internal", "private", "staging"):
                        self.add_finding(
                            severity="MEDIUM",
                            title=f"Private program accessible: /program/{slug}",
                            description="Internal/private program metadata is accessible",
                            url=f"{base}/api/researcher/program/{slug}",
                            evidence=f"Slug: {slug}, Status: 200",
                            impact="Information disclosure of private bug bounty programs",
                            remediation="Restrict access to private programs",
                        )

        if accessible:
            self.add_finding(
                severity="LOW",
                title=f"Program enumeration: {len(accessible)} slugs accessible",
                description="Program slugs can be enumerated via predictable paths",
                url=f"{base}/api/researcher/program/{{slug}}",
                evidence=f"Accessible: {accessible}",
            )
            console.print(f"  [green]Found {len(accessible)} accessible programs[/green]")

    async def _stage_endpoints(self, base: str, client: AsyncClient):
        """Stage 4: Test all known endpoints"""
        console.print("  [dim]Stage 4: Endpoint enumeration[/dim]")

        urls = [f"{base}{ep}" for ep in self.ENDPOINTS]
        responses = await client.batch_get(urls)

        accessible = []
        errors_502 = []

        for ep, resp in zip(self.ENDPOINTS, responses):
            if resp["status"] == 200:
                accessible.append(ep)
            elif resp["status"] == 502:
                errors_502.append(ep)

        # Check admin/customer endpoints (privilege escalation)
        admin_accessible = [ep for ep in accessible if "/admin/" in ep or "/customer/" in ep]
        if admin_accessible:
            for ep in admin_accessible:
                self.add_finding(
                    severity="HIGH",
                    title=f"Privilege escalation: {ep} accessible as researcher",
                    description="Admin/customer endpoint accessible with researcher role",
                    url=f"{base}{ep}",
                    impact="Potential privilege escalation",
                    remediation="Implement role-based access control",
                )

        if errors_502:
            self.add_finding(
                severity="INFO",
                title=f"Server errors on {len(errors_502)} endpoints",
                description="Multiple endpoints return 502 - possible WAF or backend instability",
                evidence=f"Endpoints: {errors_502[:5]}",
            )

    async def _stage_authz(self, base: str, client: AsyncClient):
        """Stage 5: Authorization boundary testing"""
        console.print("  [dim]Stage 5: Authorization boundary testing[/dim]")

        # Test accessing endpoints without auth (remove cookies temporarily)
        no_auth_client = AsyncClient(
            cookies={},
            headers={},
            concurrency=3,
            delay=client.delay,
        )

        test_endpoints = [
            "/api/researcher/leaderboard",
            "/api/researcher/program-list",
            "/api/researcher/me",
            "/api/researcher/dashboard",
        ]

        async with no_auth_client:
            for ep in test_endpoints:
                resp = await no_auth_client.get(f"{base}{ep}")

                if resp["status"] == 200 and resp["body"]:
                    body = resp["body"]
                    if isinstance(body, dict) and (body.get("data") or body.get("leaderboard")):
                        self.add_finding(
                            severity="MEDIUM",
                            title=f"No auth required: {ep}",
                            description="Endpoint accessible without authentication",
                            url=f"{base}{ep}",
                            impact="Unauthenticated access to potentially sensitive data",
                            remediation="Require authentication for all API endpoints",
                        )

    def _find_sensitive_fields(self, data: dict, path: str = "") -> list[str]:
        """Recursively find sensitive fields in response"""
        sensitive_keys = {
            "email", "phone", "address", "password", "password_hash",
            "token", "secret", "api_key", "ssn", "credit_card",
            "private_key", "session", "credential",
        }
        found = []

        if isinstance(data, dict):
            for key, value in data.items():
                full_path = f"{path}.{key}" if path else key
                if key.lower() in sensitive_keys:
                    found.append(full_path)
                if isinstance(value, (dict, list)):
                    found.extend(self._find_sensitive_fields(value, full_path))
        elif isinstance(data, list):
            for i, item in enumerate(data[:3]):  # Check first 3 items
                found.extend(self._find_sensitive_fields(item, f"{path}[{i}]"))

        return found
