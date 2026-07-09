"""Tests for modules.recon – ReconScanner."""
import pytest

from suika_hub.modules.recon import ReconScanner
from tests.conftest import MockAsyncClient, make_response


@pytest.fixture
def scanner():
    s = ReconScanner()
    s.reset()
    return s


class TestReconInit:
    def test_name(self, scanner):
        assert scanner.name == "recon_scanner"

    def test_has_common_paths(self, scanner):
        assert "/api" in scanner.COMMON_PATHS
        assert "/.env" in scanner.COMMON_PATHS
        assert "/admin" in scanner.COMMON_PATHS


class TestExtractDomain:
    def test_from_url(self, scanner):
        assert scanner._extract_domain("https://example.com/path") == "example.com"

    def test_from_plain_domain(self, scanner):
        assert scanner._extract_domain("example.com") == "example.com"

    def test_from_url_with_port(self, scanner):
        domain = scanner._extract_domain("https://example.com:8080/api")
        assert "example.com" in domain


class TestSubdomainEnum:
    @pytest.mark.asyncio
    async def test_subdomains_found(self, scanner):
        resp = make_response(body=[
            {"name_value": "api.example.com"},
            {"name_value": "www.example.com\ndev.example.com"},
        ])
        client = MockAsyncClient(responses={"crt.sh": resp})
        subs = await scanner._enumerate_subdomains("example.com", client)
        assert "api.example.com" in subs
        assert "dev.example.com" in subs

    @pytest.mark.asyncio
    async def test_subdomains_empty(self, scanner):
        client = MockAsyncClient(default=make_response(status=500))
        subs = await scanner._enumerate_subdomains("example.com", client)
        assert subs == []

    @pytest.mark.asyncio
    async def test_wildcard_filtered(self, scanner):
        resp = make_response(body=[
            {"name_value": "*.example.com"},
            {"name_value": "api.example.com"},
        ])
        client = MockAsyncClient(responses={"crt.sh": resp})
        subs = await scanner._enumerate_subdomains("example.com", client)
        assert "*.example.com" not in subs
        assert "api.example.com" in subs

    @pytest.mark.asyncio
    async def test_subdomains_finding_added(self, scanner):
        resp = make_response(body=[
            {"name_value": "api.example.com"},
            {"name_value": "www.example.com"},
        ])
        client = MockAsyncClient(responses={"crt.sh": resp})
        await scanner._enumerate_subdomains("example.com", client)
        info_findings = [f for f in scanner.findings if "subdomain" in f.get("title", "").lower()]
        assert len(info_findings) > 0


class TestDiscoverEndpoints:
    @pytest.mark.asyncio
    async def test_sensitive_file_critical(self, scanner):
        responses = {}
        for path in scanner.COMMON_PATHS:
            if path == "/.env":
                responses[path] = make_response(status=200, body="DB_PASSWORD=secret")
            else:
                responses[path] = make_response(status=404)
        client = MockAsyncClient(responses=responses)
        await scanner._discover_endpoints("https://example.com", client)
        critical = [f for f in scanner.findings if f.get("severity") == "CRITICAL"]
        assert len(critical) > 0

    @pytest.mark.asyncio
    async def test_debug_endpoint_medium(self, scanner):
        responses = {}
        for path in scanner.COMMON_PATHS:
            if path == "/debug":
                responses[path] = make_response(status=200, body="debug info")
            else:
                responses[path] = make_response(status=404)
        client = MockAsyncClient(responses=responses)
        await scanner._discover_endpoints("https://example.com", client)
        medium = [f for f in scanner.findings if f.get("severity") == "MEDIUM"]
        assert len(medium) > 0

    @pytest.mark.asyncio
    async def test_git_config_low(self, scanner):
        responses = {}
        for path in scanner.COMMON_PATHS:
            if path == "/.git/config":
                responses[path] = make_response(status=301)
            else:
                responses[path] = make_response(status=404)
        client = MockAsyncClient(responses=responses)
        await scanner._discover_endpoints("https://example.com", client)
        low = [f for f in scanner.findings if f.get("severity") == "LOW"]
        assert len(low) > 0


class TestFingerprint:
    @pytest.mark.asyncio
    async def test_server_header(self, scanner):
        resp = make_response(
            headers={"server": "nginx/1.21", "content-type": "text/html"},
            body="<html></html>",
        )
        client = MockAsyncClient(default=resp)
        await scanner._fingerprint("https://example.com", client)
        assert len(scanner.findings) > 0

    @pytest.mark.asyncio
    async def test_x_powered_by(self, scanner):
        resp = make_response(
            headers={"x-powered-by": "Express", "content-type": "text/html"},
            body="<html></html>",
        )
        client = MockAsyncClient(default=resp)
        await scanner._fingerprint("https://example.com", client)
        version_findings = [f for f in scanner.findings if "Express" in f.get("title", "")]
        assert len(version_findings) > 0

    @pytest.mark.asyncio
    async def test_connection_error_skipped(self, scanner):
        client = MockAsyncClient(default=make_response(status=0, error="timeout"))
        await scanner._fingerprint("https://down.example.com", client)
        assert len(scanner.findings) == 0


class TestReconExecute:
    @pytest.mark.asyncio
    async def test_execute_full(self, scanner):
        client = MockAsyncClient(default=make_response(
            status=200, body="<html></html>", headers={"content-type": "text/html"}
        ))
        findings = await scanner.execute("https://example.com", client, {})
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_execute_plain_domain(self, scanner):
        client = MockAsyncClient(default=make_response(status=404))
        findings = await scanner.execute("example.com", client, {})
        assert isinstance(findings, list)
