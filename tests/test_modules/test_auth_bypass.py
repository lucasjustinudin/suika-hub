"""Tests for modules.auth_bypass – AuthBypassScanner."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from suika_hub.modules.auth_bypass import AuthBypassScanner
from tests.conftest import MockAsyncClient, make_response


@pytest.fixture
def scanner():
    s = AuthBypassScanner()
    s.reset()
    return s


class TestAuthBypassInit:
    def test_name(self, scanner):
        assert scanner.name == "auth_bypass"

    def test_has_bypass_headers(self, scanner):
        assert len(scanner.BYPASS_HEADERS) > 0

    def test_has_path_bypasses(self, scanner):
        assert "/admin" in scanner.PATH_BYPASSES
        assert "//admin" in scanner.PATH_BYPASSES

    def test_has_method_overrides(self, scanner):
        assert len(scanner.METHOD_OVERRIDES) > 0


class TestHasData:
    def test_dict_with_data(self, scanner):
        resp = {"body": {"data": {"user": "admin"}, "extra": "value"}}
        assert scanner._has_data(resp) is True

    def test_dict_few_keys(self, scanner):
        resp = {"body": {"ok": True}}
        assert scanner._has_data(resp) is False

    def test_long_string(self, scanner):
        resp = {"body": "A" * 200}
        assert scanner._has_data(resp) is True

    def test_string_not_found(self, scanner):
        resp = {"body": "This page not found error"}
        assert scanner._has_data(resp) is False

    def test_short_string(self, scanner):
        resp = {"body": "short"}
        assert scanner._has_data(resp) is False

    def test_none_body(self, scanner):
        resp = {"body": None}
        assert scanner._has_data(resp) is False


class TestNoAuth:
    @pytest.mark.asyncio
    async def test_no_auth_finding(self, scanner):
        """If endpoint returns 200 with data without auth, should flag."""
        resp = make_response(status=200, body={"data": {"users": ["admin"]}, "extra": "val"})
        mock_no_auth = AsyncMock()
        mock_no_auth.get = AsyncMock(return_value=resp)
        mock_no_auth.__aenter__ = AsyncMock(return_value=mock_no_auth)
        mock_no_auth.__aexit__ = AsyncMock(return_value=False)
        mock_no_auth.delay = 0

        with patch("suika_hub.modules.auth_bypass.AsyncClient", return_value=mock_no_auth):
            await scanner._test_no_auth("https://example.com", MagicMock(delay=0), {})

        high_findings = [f for f in scanner.findings if f.get("severity") == "HIGH"]
        assert len(high_findings) > 0

    @pytest.mark.asyncio
    async def test_no_auth_404_no_finding(self, scanner):
        resp = make_response(status=404)
        mock_no_auth = AsyncMock()
        mock_no_auth.get = AsyncMock(return_value=resp)
        mock_no_auth.__aenter__ = AsyncMock(return_value=mock_no_auth)
        mock_no_auth.__aexit__ = AsyncMock(return_value=False)
        mock_no_auth.delay = 0

        with patch("suika_hub.modules.auth_bypass.AsyncClient", return_value=mock_no_auth):
            await scanner._test_no_auth("https://example.com", MagicMock(delay=0), {})

        assert len(scanner.findings) == 0


class TestHeaderBypass:
    @pytest.mark.asyncio
    async def test_header_bypass_finding(self, scanner):
        resp = make_response(status=200, body={"data": "admin panel"})
        client = MockAsyncClient(default=resp)
        await scanner._test_header_bypass("https://example.com", client)
        assert len(scanner.findings) > 0

    @pytest.mark.asyncio
    async def test_header_bypass_no_finding(self, scanner):
        resp = make_response(status=403)
        client = MockAsyncClient(default=resp)
        await scanner._test_header_bypass("https://example.com", client)
        assert len(scanner.findings) == 0


class TestPathBypass:
    @pytest.mark.asyncio
    async def test_path_bypass_baseline_200(self, scanner):
        """If /admin already returns 200, skip bypass testing."""
        resp = make_response(status=200, body={"data": "ok"})
        client = MockAsyncClient(default=resp)
        await scanner._test_path_bypass("https://example.com", client)
        bypass = [f for f in scanner.findings if "bypass" in f.get("title", "").lower()]
        assert len(bypass) == 0

    @pytest.mark.asyncio
    async def test_path_bypass_found(self, scanner):
        """Test path bypass by directly setting up responses that differentiate
        /admin (403) from bypass variants (200)."""
        class BypassClient(MockAsyncClient):
            """Client that returns 403 for exact /admin, 200 for bypass variants."""
            async def get(self, url, **kwargs):
                self.request_count += 1
                self.calls.append(("get", url, kwargs))
                # The baseline request is to /admin (the exact path)
                if url.endswith("/admin") or url.endswith("/admin/"):
                    return make_response(status=403)
                # Bypass variants
                return make_response(status=200, body={"data": "admin access"})

        client = BypassClient()
        await scanner._test_path_bypass("https://example.com", client)
        bypass_findings = [f for f in scanner.findings if "bypass" in f.get("title", "").lower()]
        assert len(bypass_findings) > 0


class TestMethodTampering:
    @pytest.mark.asyncio
    async def test_method_tampering_finding(self, scanner):
        resp = make_response(status=200, body={"data": "modified"})
        client = MockAsyncClient(default=resp)
        await scanner._test_method_tampering("https://example.com", client, {})
        tampering = [f for f in scanner.findings if "tampering" in f.get("title", "").lower()]
        assert len(tampering) > 0

    @pytest.mark.asyncio
    async def test_method_tampering_no_finding(self, scanner):
        resp = make_response(status=405)
        client = MockAsyncClient(default=resp)
        await scanner._test_method_tampering("https://example.com", client, {})
        assert len(scanner.findings) == 0


class TestRoleEscalation:
    @pytest.mark.asyncio
    async def test_role_escalation_found(self, scanner):
        resp = make_response(status=200, body={"role": "admin", "is_admin": True})
        client = MockAsyncClient(default=resp)
        await scanner._test_role_escalation("https://example.com", client, {})
        critical = [f for f in scanner.findings if f.get("severity") == "CRITICAL"]
        assert len(critical) > 0

    @pytest.mark.asyncio
    async def test_role_escalation_no_change(self, scanner):
        resp = make_response(status=200, body={"role": "user"})
        client = MockAsyncClient(default=resp)
        await scanner._test_role_escalation("https://example.com", client, {})
        critical = [f for f in scanner.findings if f.get("severity") == "CRITICAL"]
        assert len(critical) == 0


class TestExecute:
    @pytest.mark.asyncio
    async def test_execute_full(self, scanner):
        client = MockAsyncClient(default=make_response(status=403))

        mock_no_auth = AsyncMock()
        mock_no_auth.get = AsyncMock(return_value=make_response(status=403))
        mock_no_auth.__aenter__ = AsyncMock(return_value=mock_no_auth)
        mock_no_auth.__aexit__ = AsyncMock(return_value=False)
        mock_no_auth.delay = 0

        with patch("suika_hub.modules.auth_bypass.AsyncClient", return_value=mock_no_auth):
            findings = await scanner.execute("https://example.com", client, {})

        assert isinstance(findings, list)
