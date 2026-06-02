"""Tests for modules.upload_scanner – FileUploadScanner."""
import pytest
from modules.upload_scanner import FileUploadScanner
from tests.conftest import MockAsyncClient, make_response


@pytest.fixture
def scanner():
    s = FileUploadScanner()
    s.reset()
    return s


class TestFileUploadInit:
    def test_name(self, scanner):
        assert scanner.name == "upload_scanner"

    def test_has_bypass_files(self, scanner):
        assert len(scanner.BYPASS_FILES) > 0

    def test_has_polyglot_payloads(self, scanner):
        assert len(scanner.POLYGLOT_PAYLOADS) > 0

    def test_has_content_type_bypasses(self, scanner):
        assert "image/jpeg" in scanner.CONTENT_TYPE_BYPASSES

    def test_has_malicious_extensions(self, scanner):
        assert ".php" in scanner.MALICIOUS_EXTENSIONS
        assert ".jsp" in scanner.MALICIOUS_EXTENSIONS


class TestFindUploadEndpoints:
    @pytest.mark.asyncio
    async def test_find_via_options_post(self, scanner):
        resp = make_response(status=200, headers={"allow": "GET, POST, OPTIONS"})
        client = MockAsyncClient(default=resp)
        valid = await scanner._find_upload_endpoints("https://example.com", client, ["/api/upload"])
        assert "/api/upload" in valid

    @pytest.mark.asyncio
    async def test_find_via_post_422(self, scanner):
        resp = make_response(status=422, body={"error": "validation"})
        client = MockAsyncClient(default=resp)
        valid = await scanner._find_upload_endpoints("https://example.com", client, ["/api/upload"])
        assert "/api/upload" in valid

    @pytest.mark.asyncio
    async def test_find_via_post_400(self, scanner):
        resp = make_response(status=400, body={"error": "bad request"})
        client = MockAsyncClient(default=resp)
        valid = await scanner._find_upload_endpoints("https://example.com", client, ["/upload"])
        assert "/upload" in valid

    @pytest.mark.asyncio
    async def test_endpoint_not_found(self, scanner):
        resp = make_response(status=404)
        client = MockAsyncClient(default=resp)
        valid = await scanner._find_upload_endpoints("https://example.com", client, ["/api/upload"])
        assert len(valid) == 0

    @pytest.mark.asyncio
    async def test_multiple_endpoints(self, scanner):
        resp_ok = make_response(status=422)
        resp_not = make_response(status=404)
        client = MockAsyncClient(responses={
            "/api/upload": resp_ok,
            "/api/avatar": resp_not,
        })
        valid = await scanner._find_upload_endpoints("https://example.com", client, ["/api/upload", "/api/avatar"])
        assert "/api/upload" in valid
        assert "/api/avatar" not in valid


class TestExtensionBypass:
    @pytest.mark.asyncio
    async def test_extension_bypass_finding(self, scanner):
        resp = make_response(status=200, body={"url": "/uploads/shell.php.jpg"})
        client = MockAsyncClient(default=resp)
        await scanner._test_extension_bypass("https://example.com", client, "/api/upload")
        critical = [f for f in scanner.findings if f.get("severity") == "CRITICAL"]
        assert len(critical) > 0

    @pytest.mark.asyncio
    async def test_extension_bypass_no_url(self, scanner):
        resp = make_response(status=200, body={"message": "uploaded"})
        client = MockAsyncClient(default=resp)
        await scanner._test_extension_bypass("https://example.com", client, "/api/upload")
        critical = [f for f in scanner.findings if f.get("severity") == "CRITICAL"]
        assert len(critical) == 0

    @pytest.mark.asyncio
    async def test_extension_bypass_rejected(self, scanner):
        resp = make_response(status=403, body={"error": "forbidden"})
        client = MockAsyncClient(default=resp)
        await scanner._test_extension_bypass("https://example.com", client, "/api/upload")
        assert len(scanner.findings) == 0


class TestContentTypeBypass:
    @pytest.mark.asyncio
    async def test_content_type_bypass_finding(self, scanner):
        resp = make_response(status=200, body={"file": "uploaded"})
        client = MockAsyncClient(default=resp)
        await scanner._test_content_type_bypass("https://example.com", client, "/api/upload")
        high = [f for f in scanner.findings if "Content-Type" in f.get("title", "")]
        assert len(high) > 0

    @pytest.mark.asyncio
    async def test_content_type_bypass_rejected(self, scanner):
        resp = make_response(status=415, body={"error": "unsupported media type"})
        client = MockAsyncClient(default=resp)
        await scanner._test_content_type_bypass("https://example.com", client, "/api/upload")
        assert len(scanner.findings) == 0


class TestPolyglot:
    @pytest.mark.asyncio
    async def test_polyglot_finding(self, scanner):
        resp = make_response(status=201, body={"path": "/uploads/polyglot.gif"})
        client = MockAsyncClient(default=resp)
        await scanner._test_polyglot("https://example.com", client, "/api/upload")
        high = [f for f in scanner.findings if "Polyglot" in f.get("title", "")]
        assert len(high) > 0

    @pytest.mark.asyncio
    async def test_polyglot_rejected(self, scanner):
        resp = make_response(status=400, body={"error": "invalid file"})
        client = MockAsyncClient(default=resp)
        await scanner._test_polyglot("https://example.com", client, "/api/upload")
        assert len(scanner.findings) == 0


class TestExecute:
    @pytest.mark.asyncio
    async def test_execute_full(self, scanner):
        client = MockAsyncClient(default=make_response(status=404))
        findings = await scanner.execute("https://example.com", client, {})
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_execute_custom_endpoints(self, scanner):
        client = MockAsyncClient(default=make_response(status=404))
        config = {"upload_endpoints": ["/custom/upload"]}
        findings = await scanner.execute("https://example.com", client, config)
        assert isinstance(findings, list)
