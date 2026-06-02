"""Generic IDOR vulnerability scanner"""
from rich.console import Console

from suika_hub.core.http import AsyncClient
from suika_hub.core.module import BaseModule, Finding

console = Console()


class IDORScanner(BaseModule):
    """Advanced IDOR scanner with pattern detection"""

    name = "idor_scanner"
    description = "Detect Insecure Direct Object References across API endpoints"

    DEFAULT_PATTERNS = [
        "/api/user/{id}",
        "/api/users/{id}",
        "/api/profile/{id}",
        "/api/account/{id}",
        "/api/submission/{id}",
        "/api/document/{id}",
        "/api/file/{id}",
        "/api/order/{id}",
        "/api/invoice/{id}",
        "/api/report/{id}",
        "/api/message/{id}",
        "/api/notification/{id}",
    ]

    DEFAULT_IDS = [
        "1", "2", "3", "100", "999", "9999",
        "admin", "test", "root", "system",
        "00000000-0000-0000-0000-000000000001",
        "000000000000000000000001",
    ]

    async def execute(self, target: str, client: AsyncClient, config: dict) -> list[Finding]:
        """Execute IDOR testing"""
        console.print("[bold cyan]IDOR Scanner[/bold cyan] - Testing object references")

        patterns = config.get("idor_patterns", self.DEFAULT_PATTERNS)
        test_ids = config.get("test_ids", self.DEFAULT_IDS)

        # Get baseline - what does MY data look like?
        baseline = await self._get_baseline(target, client, config)

        # Test each pattern with each ID
        for pattern in patterns:
            for test_id in test_ids:
                endpoint = pattern.format(id=test_id)
                url = f"{target}{endpoint}"

                resp = await client.get(url)

                if resp["status"] == 200 and resp["body"]:
                    body = resp["body"]

                    # Skip if it's our own data (compare with baseline)
                    if self._is_own_data(body, baseline):
                        continue

                    # Check for actual data content
                    if self._has_meaningful_data(body):
                        sensitive = self._detect_sensitive(body)
                        severity = "HIGH" if sensitive else "MEDIUM"

                        self.add_finding(
                            severity=severity,
                            title=f"IDOR: {endpoint} returns data for ID '{test_id}'",
                            description="Endpoint returns data for arbitrary object IDs",
                            url=url,
                            evidence=f"Status: 200, Sensitive fields: {sensitive or 'none detected'}",
                            impact="Unauthorized access to other users' data",
                            remediation="Verify requesting user owns the requested resource",
                        )

        console.print(f"  [green]IDOR scan complete: {len(self.findings)} findings[/green]")
        return self.findings

    async def _get_baseline(self, target: str, client: AsyncClient, config: dict) -> dict:
        """Get baseline response for authenticated user"""
        resp = await client.get(f"{target}/api/user/me")
        if resp["status"] == 200:
            return resp["body"] if isinstance(resp["body"], dict) else {}
        return {}

    def _is_own_data(self, body: dict, baseline: dict) -> bool:
        """Check if response is our own data (not IDOR)"""
        if not baseline or not isinstance(body, dict):
            return False
        # Compare user IDs
        my_id = baseline.get("id") or baseline.get("_id") or baseline.get("user_id")
        their_id = body.get("id") or body.get("_id") or body.get("user_id")
        return my_id and my_id == their_id

    def _has_meaningful_data(self, body) -> bool:
        """Check if response has actual data (not empty/error)"""
        if isinstance(body, dict):
            # Skip error responses
            if body.get("error") or body.get("message") in ("not found", "unauthorized"):
                return False
            # Has actual content
            return len(body) > 1
        if isinstance(body, str):
            return len(body) > 50 and "not found" not in body.lower()
        return False

    def _detect_sensitive(self, body) -> list[str]:
        """Detect sensitive fields in response"""
        sensitive_keys = {
            "email", "phone", "address", "password", "ssn",
            "credit_card", "token", "secret", "api_key",
            "submission", "report", "bounty_amount",
        }
        found = []

        if isinstance(body, dict):
            for key in body.keys():
                if key.lower() in sensitive_keys:
                    found.append(key)

        return found
