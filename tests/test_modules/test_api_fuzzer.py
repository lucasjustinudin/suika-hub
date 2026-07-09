"""Tests for modules.api_fuzzer – APIFuzzer."""
import pytest

from suika_hub.modules.api_fuzzer import APIFuzzer
from tests.conftest import MockAsyncClient, make_response


@pytest.fixture
def scanner():
    s = APIFuzzer()
    s.reset()
    return s


class TestAPIFuzzerInit:
    def test_name(self, scanner):
        assert scanner.name == "api_fuzzer"

    def test_has_sqli_payloads(self, scanner):
        assert len(scanner.SQLI) > 0

    def test_has_nosql_payloads(self, scanner):
        assert len(scanner.NOSQL) > 0

    def test_has_xss_payloads(self, scanner):
        assert len(scanner.XSS) > 0

    def test_has_boundary_payloads(self, scanner):
        assert len(scanner.BOUNDARY) > 0


class TestSQLIDetection:
    def test_detect_sqli_500_with_sql_error(self, scanner):
        resp = {"status": 500, "body": "MySQL syntax error near 'SELECT'"}
        assert scanner._detect_sqli_response(resp) is True

    def test_detect_sqli_500_postgres(self, scanner):
        resp = {"status": 500, "body": "postgresql error in query"}
        assert scanner._detect_sqli_response(resp) is True

    def test_detect_sqli_500_sqlite(self, scanner):
        resp = {"status": 500, "body": "sqlite3 error"}
        assert scanner._detect_sqli_response(resp) is True

    def test_no_sqli_on_200(self, scanner):
        resp = {"status": 200, "body": "OK"}
        assert scanner._detect_sqli_response(resp) is False

    def test_no_sqli_on_500_without_indicator(self, scanner):
        resp = {"status": 500, "body": "Internal Server Error"}
        assert scanner._detect_sqli_response(resp) is False


class TestNoSQLDetection:
    def test_detect_nosql_200_with_data(self, scanner):
        resp = {"status": 200, "body": {"data": ["user1", "user2"]}}
        assert scanner._detect_nosql_response(resp) is True

    def test_detect_nosql_200_list(self, scanner):
        resp = {"status": 200, "body": ["result1", "result2"]}
        assert scanner._detect_nosql_response(resp) is True

    def test_detect_nosql_500_mongo(self, scanner):
        resp = {"status": 500, "body": "MongoError: invalid BSON"}
        assert scanner._detect_nosql_response(resp) is True

    def test_no_nosql_on_empty(self, scanner):
        resp = {"status": 200, "body": {}}
        assert scanner._detect_nosql_response(resp) is False

    def test_no_nosql_on_404(self, scanner):
        resp = {"status": 404, "body": "not found"}
        assert scanner._detect_nosql_response(resp) is False


class TestSQLITest:
    @pytest.mark.asyncio
    async def test_sqli_finding_on_error(self, scanner):
        resp = make_response(status=500, body="MySQL syntax error near 'OR'")
        client = MockAsyncClient(default=resp)
        await scanner._test_sqli("https://example.com/api/login", client)
        sqli = [f for f in scanner.findings if "SQL Injection" in f.get("title", "")]
        assert len(sqli) > 0

    @pytest.mark.asyncio
    async def test_sqli_no_finding_on_clean(self, scanner):
        resp = make_response(status=200, body={"result": "ok"})
        client = MockAsyncClient(default=resp)
        await scanner._test_sqli("https://example.com/api/login", client)
        sqli = [f for f in scanner.findings if "SQL Injection" in f.get("title", "")]
        assert len(sqli) == 0


class TestNoSQLTest:
    @pytest.mark.asyncio
    async def test_nosql_finding_on_data(self, scanner):
        resp = make_response(status=200, body={"data": ["all_users"]})
        client = MockAsyncClient(default=resp)
        await scanner._test_nosql("https://example.com/api/login", client)
        nosql = [f for f in scanner.findings if "NoSQL" in f.get("title", "")]
        assert len(nosql) > 0

    @pytest.mark.asyncio
    async def test_nosql_no_finding(self, scanner):
        resp = make_response(status=401, body={"error": "unauthorized"})
        client = MockAsyncClient(default=resp)
        await scanner._test_nosql("https://example.com/api/login", client)
        nosql = [f for f in scanner.findings if "NoSQL" in f.get("title", "")]
        assert len(nosql) == 0


class TestXSSTest:
    @pytest.mark.asyncio
    async def test_xss_finding_on_reflection(self, scanner):
        payload = "<script>alert(1)</script>"
        resp = make_response(status=200, body=f"<html>{payload}</html>", headers={"content-type": "text/html"})
        client = MockAsyncClient(default=resp)
        await scanner._test_xss("https://example.com/search", client)
        xss = [f for f in scanner.findings if "XSS" in f.get("title", "")]
        assert len(xss) > 0

    @pytest.mark.asyncio
    async def test_xss_no_finding_on_sanitized(self, scanner):
        resp = make_response(status=200, body="<html>safe output</html>", headers={"content-type": "text/html"})
        client = MockAsyncClient(default=resp)
        await scanner._test_xss("https://example.com/search", client)
        xss = [f for f in scanner.findings if "XSS" in f.get("title", "")]
        assert len(xss) == 0


class TestBoundaryTest:
    @pytest.mark.asyncio
    async def test_boundary_500_error(self, scanner):
        resp = make_response(status=500, body="Internal Server Error")
        client = MockAsyncClient(default=resp)
        await scanner._test_boundary("https://example.com/api/items", client)
        errors = [f for f in scanner.findings if "error" in f.get("title", "").lower()]
        assert len(errors) > 0

    @pytest.mark.asyncio
    async def test_boundary_path_traversal(self, scanner):
        resp = make_response(status=200, body="root:x:0:0:root:/root:/bin/bash")
        client = MockAsyncClient(default=resp)
        await scanner._test_boundary("https://example.com/api/file", client)
        traversal = [f for f in scanner.findings if "Traversal" in f.get("title", "")]
        assert len(traversal) > 0


class TestExecute:
    @pytest.mark.asyncio
    async def test_execute_default_endpoints(self, scanner):
        client = MockAsyncClient(default=make_response(status=200, body={"ok": True}))
        findings = await scanner.execute("https://example.com", client, {})
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_execute_custom_endpoints(self, scanner):
        client = MockAsyncClient(default=make_response(status=200, body={"ok": True}))
        config = {"api_endpoints": ["/api/custom", "/api/test"]}
        findings = await scanner.execute("https://example.com", client, config)
        assert isinstance(findings, list)
