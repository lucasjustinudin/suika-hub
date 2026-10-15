"""Tests for suika_hub.modules.jwt_scanner -- JWT forgery helpers and detection."""

import hashlib
import hmac
import json

import pytest

from suika_hub.modules.jwt_scanner import (
    COMMON_SECRETS,
    JWTScanner,
    b64url_decode,
    b64url_encode,
    decode_segment,
    forge_hs256,
    forge_none_alg,
    split_jwt,
    tamper_claim,
)


def make_token(header: dict, payload: dict, secret: str | None = "secret") -> str:
    """Build a compact JWT for tests."""
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    if secret is None:
        return f"{h}.{p}."
    sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{b64url_encode(sig)}"


SAMPLE = make_token({"alg": "HS256", "typ": "JWT"}, {"sub": "1", "role": "user"})


class TestBase64Helpers:
    def test_roundtrip(self):
        assert b64url_decode(b64url_encode(b"hello")) == b"hello"

    def test_encode_has_no_padding(self):
        assert "=" not in b64url_encode(b"any carnal pleasure")

    def test_decode_restores_padding(self):
        assert b64url_decode("aGVsbG8") == b"hello"


class TestSplitJwt:
    def test_splits_valid_token(self):
        parts = split_jwt(SAMPLE)
        assert parts is not None
        assert len(parts) == 3

    @pytest.mark.parametrize("bad", ["", "abc", "a.b", "a.b.c.d", "not-a-jwt"])
    def test_rejects_malformed(self, bad):
        assert split_jwt(bad) is None


class TestDecodeSegment:
    def test_decodes_json(self):
        seg = b64url_encode(json.dumps({"alg": "none"}).encode())
        assert decode_segment(seg) == {"alg": "none"}

    def test_non_json_returns_none(self):
        assert decode_segment(b64url_encode(b"plain text")) is None

    def test_json_array_returns_none(self):
        """A JWT segment must be a JSON object, not an array."""
        assert decode_segment(b64url_encode(b"[1,2,3]")) is None


class TestForgeNoneAlg:
    def test_sets_alg_none_and_strips_signature(self):
        forged = forge_none_alg(SAMPLE)
        assert forged is not None
        header, payload, sig = split_jwt(forged)
        assert decode_segment(header)["alg"] == "none"
        assert sig == ""

    def test_payload_preserved(self):
        forged = forge_none_alg(SAMPLE)
        assert split_jwt(forged)[1] == split_jwt(SAMPLE)[1]

    def test_malformed_returns_none(self):
        assert forge_none_alg("garbage") is None


class TestForgeHs256:
    def test_produces_verifiable_signature(self):
        forged = forge_hs256(SAMPLE, "newsecret")
        assert forged is not None
        header, payload, sig = split_jwt(forged)
        expected = hmac.new(b"newsecret", f"{header}.{payload}".encode(), hashlib.sha256).digest()
        assert b64url_decode(sig) == expected

    def test_alg_becomes_hs256(self):
        forged = forge_hs256(SAMPLE, "x")
        header, _, _ = split_jwt(forged)
        assert decode_segment(header)["alg"] == "HS256"

    def test_different_secrets_produce_different_signatures(self):
        assert forge_hs256(SAMPLE, "a") != forge_hs256(SAMPLE, "b")

    def test_malformed_returns_none(self):
        assert forge_hs256("nope", "x") is None


class TestTamperClaim:
    def test_changes_claim_value(self):
        forged = tamper_claim(SAMPLE, "role", "admin")
        assert forged is not None
        _, payload, _ = split_jwt(forged)
        assert decode_segment(payload)["role"] == "admin"

    def test_signature_unchanged(self):
        """Tampering must leave the original signature so acceptance proves non-verification."""
        forged = tamper_claim(SAMPLE, "role", "admin")
        assert split_jwt(forged)[2] == split_jwt(SAMPLE)[2]

    def test_adds_new_claim(self):
        forged = tamper_claim(SAMPLE, "is_admin", True)
        _, payload, _ = split_jwt(forged)
        assert decode_segment(payload)["is_admin"] is True

    def test_malformed_returns_none(self):
        assert tamper_claim("bad", "role", "admin") is None


class TestScannerHelpers:
    def test_find_token_from_explicit_config(self):
        scanner = JWTScanner()
        assert scanner._find_token({"jwt": "abc.def.ghi"}) == "abc.def.ghi"

    def test_find_token_strips_bearer_prefix(self):
        scanner = JWTScanner()
        config = {"auth": {"headers": {"Authorization": "Bearer tok.en.value"}}}
        assert scanner._find_token(config) == "tok.en.value"

    def test_find_token_returns_none_when_absent(self):
        assert JWTScanner()._find_token({}) is None

    def test_is_authorized_only_for_2xx(self):
        scanner = JWTScanner()
        assert scanner._is_authorized({"status": 200}) is True
        assert scanner._is_authorized({"status": 204}) is True
        assert scanner._is_authorized({"status": 401}) is False
        assert scanner._is_authorized({"status": 200, "error": "timeout"}) is False

    def test_accepted_requires_control_success(self):
        """A rejected control means the endpoint is not usable as an oracle."""
        scanner = JWTScanner()
        assert scanner._accepted({"status": 200}, {"status": 401}) is False

    def test_accepted_requires_mutated_success(self):
        scanner = JWTScanner()
        assert scanner._accepted({"status": 403}, {"status": 200}) is False

    def test_accepted_true_when_both_succeed(self):
        scanner = JWTScanner()
        assert scanner._accepted({"status": 200, "body": {"id": 1}}, {"status": 200, "body": {"id": 1}}) is True

    def test_accepted_rejects_disjoint_body_keys(self):
        """A generic 200 shell page must not read as acceptance."""
        scanner = JWTScanner()
        assert (
            scanner._accepted({"status": 200, "body": {"welcome": True}}, {"status": 200, "body": {"id": 1}}) is False
        )


class TestSecretsList:
    def test_contains_expected_defaults(self):
        for secret in ("secret", "changeme", "your-256-bit-secret"):
            assert secret in COMMON_SECRETS

    def test_no_duplicates(self):
        assert len(COMMON_SECRETS) == len(set(COMMON_SECRETS))


class TestScannerDetection:
    @pytest.mark.asyncio
    async def test_detects_alg_none_acceptance(self, mock_client_factory):
        """A server that accepts an unsigned token must produce a finding."""
        client = mock_client_factory(
            default={"url": "x", "status": 200, "body": {"id": 1}, "headers": {}, "error": None}
        )
        scanner = JWTScanner()
        findings = await scanner.execute(
            "https://example.com",
            client,
            {"jwt": SAMPLE, "jwt_endpoint": "https://example.com/api/user/me"},
        )
        assert any(f["title"].startswith("JWT accepts unsigned tokens") for f in findings)

    @pytest.mark.asyncio
    async def test_no_finding_when_endpoint_rejects_everything(self, mock_client_factory):
        """A 401 for both control and forged token must yield nothing."""
        client = mock_client_factory(default={"url": "x", "status": 401, "body": None, "headers": {}, "error": None})
        scanner = JWTScanner()
        findings = await scanner.execute(
            "https://example.com",
            client,
            {"jwt": SAMPLE, "jwt_endpoint": "https://example.com/api/user/me"},
        )
        assert findings == []

    @pytest.mark.asyncio
    async def test_no_finding_without_token(self, mock_client_factory):
        client = mock_client_factory()
        findings = await JWTScanner().execute("https://example.com", client, {})
        assert findings == []

    @pytest.mark.asyncio
    async def test_no_finding_for_non_jwt_value(self, mock_client_factory):
        client = mock_client_factory()
        findings = await JWTScanner().execute("https://example.com", client, {"jwt": "not-a-jwt"})
        assert findings == []

    @pytest.mark.asyncio
    async def test_findings_carry_required_fields(self, mock_client_factory):
        client = mock_client_factory(
            default={"url": "x", "status": 200, "body": {"id": 1}, "headers": {}, "error": None}
        )
        findings = await JWTScanner().execute(
            "https://example.com",
            client,
            {"jwt": SAMPLE, "jwt_endpoint": "https://example.com/api/user/me"},
        )
        assert findings
        for f in findings:
            for field in ("severity", "title", "description", "evidence", "impact", "remediation"):
                assert f.get(field), f"missing {field}"
            assert f["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


class TestAuthSchemeIsAppliedToEveryProbe:
    """Regression: forged tokens must carry the same auth scheme as the control.

    A forged token sent without ``Bearer`` is rejected for the wrong reason, so a
    server that genuinely accepts unsigned tokens reads as "signature verified"
    and the bypass is silently missed.
    """

    class Recorder:
        """Client that records the exact header value sent on each probe."""

        def __init__(self, header: str = "Authorization", status: int = 200):
            self.header = header
            self.status = status
            self.seen: list[str] = []

        async def get(self, url, **kwargs):
            self.seen.append((kwargs.get("headers") or {}).get(self.header, ""))
            return {"url": url, "status": self.status, "body": {"id": 1}, "headers": {}, "error": None}

    async def _run(self, recorder) -> list[str]:
        await JWTScanner().execute(
            "https://example.com",
            recorder,
            {"jwt": SAMPLE, "jwt_header": recorder.header, "jwt_endpoint": "https://example.com/api/user/me"},
        )
        return recorder.seen

    @pytest.mark.asyncio
    async def test_control_and_forgeries_all_carry_bearer(self):
        seen = await self._run(self.Recorder())
        assert seen, "no probes were sent"
        assert all(v.startswith("Bearer ") for v in seen), f"probe missing auth scheme: {seen}"

    @pytest.mark.asyncio
    async def test_forged_tokens_are_not_sent_bare(self):
        """The mutation probes specifically must keep the prefix, not just the control."""
        seen = await self._run(self.Recorder())
        for value in seen[1:]:
            assert value.startswith("Bearer ") and len(value) > len("Bearer ")

    @pytest.mark.asyncio
    async def test_custom_header_gets_no_prefix(self):
        """A non-Authorization header must not be given a Bearer prefix."""
        seen = await self._run(self.Recorder(header="X-Token"))
        assert seen
        assert all(not v.startswith("Bearer ") and v.count(".") == 2 for v in seen)
