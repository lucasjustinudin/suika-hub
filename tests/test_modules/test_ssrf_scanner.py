"""Tests for modules.ssrf_scanner – SSRFScanner."""
import pytest
from modules.ssrf_scanner import SSRFScanner
from tests.conftest import MockAsyncClient, make_response


@pytest.fixture
def scanner():
    s = SSRFScanner()
    s.reset()
    return s


class TestSSRFInit:
    def test_name(self, scanner):
        assert scanner.name == "ssrf_scanner"

    def test_has_internal_targets(self, scanner):
        assert "http://127.0.0.1" in scanner.INTERNAL_TARGETS
        assert "http://169.254.169.254" in scanner.INTERNAL_TARGETS

    def test_has_bypass_payloads(self, scanner):
        assert len(scanner.BYPASS_PAYLOADS) > 0
        assert any("file://" in p for p in scanner.BYPASS_PAYLOADS)

    def test_has_ssrf_params(self, scanner):
        assert "url" in scanner.SSRF_PARAMS
        assert "redirect" in scanner.SSRF_PARAMS


class TestDetectSSRF:
    def test_detect_passwd(self, scanner):
        resp = {"status": 200, "body": "root:x:0:0:root:/root:/bin/bash"}
        assert scanner._detect_ssrf(resp, "http://127.0.0.1") is True

    def test_detect_aws_metadata(self, scanner):
        resp = {"status": 200, "body": "AccessKeyId: AKIA123\nSecretAccessKey: abc"}
        assert scanner._detect_ssrf(resp, "http://169.254.169.254") is True

    def test_detect_redis(self, scanner):
        resp = {"status": 200, "body": "redis_version:6.0.0"}
        assert scanner._detect_ssrf(resp, "http://127.0.0.1:6379") is True

    def test_detect_gcp_metadata(self, scanner):
        resp = {"status": 200, "body": "computeMetadata/v1/project"}
        assert scanner._detect_ssrf(resp, "http://metadata.google.internal") is True

    def test_no_detect_on_error(self, scanner):
        resp = {"status": 0, "error": "timeout"}
        assert scanner._detect_ssrf(resp, "http://127.0.0.1") is False

    def test_no_detect_on_404(self, scanner):
        resp = {"status": 404, "body": "Not Found"}
        assert scanner._detect_ssrf(resp, "http://127.0.0.1") is False

    def test_detect_large_response(self, scanner):
        resp = {"status": 200, "body": "A" * 200}
        assert scanner._detect_ssrf(resp, "http://127.0.0.1") is True

    def test_no_detect_not_found_body(self, scanner):
        resp = {"status": 200, "body": "The resource was not found on this server"}
        assert scanner._detect_ssrf(resp, "http://127.0.0.1") is False


class TestParamInjection:
    @pytest.mark.asyncio
    async def test_ssrf_via_param(self, scanner):
        resp = make_response(status=200, body="root:x:0:0:root:/root:/bin/bash")
        client = MockAsyncClient(default=resp)
        await scanner._test_param_injection("https://example.com", client, ["/api/fetch"])
        critical = [f for f in scanner.findings if "SSRF" in f.get("title", "")]
        assert len(critical) > 0

    @pytest.mark.asyncio
    async def test_ssrf_not_found(self, scanner):
        resp = make_response(status=404, body="Not Found")
        client = MockAsyncClient(default=resp)
        await scanner._test_param_injection("https://example.com", client, ["/api/fetch"])
        ssrf = [f for f in scanner.findings if "SSRF" in f.get("title", "")]
        assert len(ssrf) == 0


class TestBypasses:
    @pytest.mark.asyncio
    async def test_bypass_found(self, scanner):
        resp = make_response(status=200, body="root:x:0:0:root:/root:/bin/bash")
        client = MockAsyncClient(default=resp)
        await scanner._test_bypasses("https://example.com", client, ["/api/proxy"])
        bypass = [f for f in scanner.findings if "bypass" in f.get("title", "").lower()]
        assert len(bypass) > 0

    @pytest.mark.asyncio
    async def test_bypass_not_found(self, scanner):
        resp = make_response(status=403, body="Forbidden")
        client = MockAsyncClient(default=resp)
        await scanner._test_bypasses("https://example.com", client, ["/api/proxy"])
        bypass = [f for f in scanner.findings if "bypass" in f.get("title", "").lower()]
        assert len(bypass) == 0


class TestCloudMetadata:
    @pytest.mark.asyncio
    async def test_aws_metadata_found(self, scanner):
        resp = make_response(status=200, body='{"AccessKeyId": "AKIA123", "SecretAccessKey": "secret"}')
        client = MockAsyncClient(default=resp)
        await scanner._test_cloud_metadata("https://example.com", client, ["/api/fetch"])
        critical = [f for f in scanner.findings if "Cloud" in f.get("title", "")]
        assert len(critical) > 0

    @pytest.mark.asyncio
    async def test_gcp_metadata_found(self, scanner):
        resp = make_response(status=200, body='{"access_token": "ya29.xxx", "token_type": "Bearer"}')
        client = MockAsyncClient(default=resp)
        await scanner._test_cloud_metadata("https://example.com", client, ["/api/fetch"])
        critical = [f for f in scanner.findings if "Cloud" in f.get("title", "")]
        assert len(critical) > 0

    @pytest.mark.asyncio
    async def test_no_metadata(self, scanner):
        resp = make_response(status=404, body="Not Found")
        client = MockAsyncClient(default=resp)
        await scanner._test_cloud_metadata("https://example.com", client, ["/api/fetch"])
        assert len(scanner.findings) == 0


class TestExecute:
    @pytest.mark.asyncio
    async def test_execute_default_endpoints(self, scanner):
        client = MockAsyncClient(default=make_response(status=404))
        findings = await scanner.execute("https://example.com", client, {})
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_execute_custom_endpoints(self, scanner):
        client = MockAsyncClient(default=make_response(status=404))
        config = {"ssrf_endpoints": ["/api/custom"]}
        findings = await scanner.execute("https://example.com", client, config)
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_execute_finds_ssrf(self, scanner):
        resp = make_response(status=200, body="root:x:0:0:root:/root:/bin/bash")
        client = MockAsyncClient(default=resp)
        findings = await scanner.execute("https://example.com", client, {})
        ssrf = [f for f in findings if "SSRF" in f.get("title", "")]
        assert len(ssrf) > 0
