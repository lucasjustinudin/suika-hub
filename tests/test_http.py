"""Tests for suika_hub.core.http – AsyncClient."""
import json
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from suika_hub.core.http import USER_AGENTS, AsyncClient


class TestUserAgents:
    def test_user_agents_not_empty(self):
        assert len(USER_AGENTS) > 0

    def test_user_agents_are_strings(self):
        for ua in USER_AGENTS:
            assert isinstance(ua, str)
            assert "Mozilla" in ua


class TestAsyncClientConstruction:
    @pytest.mark.asyncio
    async def test_default_headers_contain_user_agent(self):
        client = AsyncClient()
        try:
            headers = client.client.headers
            assert "user-agent" in {k.lower() for k in headers}
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_custom_headers_merged(self):
        client = AsyncClient(headers={"X-Custom": "value"})
        try:
            assert "X-Custom" in client.client.headers
        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_custom_cookies(self):
        client = AsyncClient(cookies={"session": "abc"})
        try:
            # httpx stores cookies; just verify no crash
            assert client.request_count == 0
        finally:
            await client.close()

    def test_concurrency_semaphore(self):
        client = AsyncClient(concurrency=3)
        assert client.semaphore._value == 3


class TestAsyncClientRequests:
    """Test request handling by mocking the underlying httpx client."""

    @pytest.fixture
    def client(self):
        c = AsyncClient(delay=0)
        return c

    def _mock_httpx_response(self, status=200, text="OK", headers=None, content=None):
        """Create a mock httpx.Response."""
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = status
        resp.text = text
        resp.content = content or text.encode()
        resp.headers = headers or {"content-type": "text/html"}

        # Handle json() mock properly
        if text and text.startswith(("{", "[")):
            try:
                parsed = json.loads(text)
                resp.json = MagicMock(return_value=parsed)
            except json.JSONDecodeError:
                resp.json = MagicMock(side_effect=json.JSONDecodeError("", "", 0))
        else:
            resp.json = MagicMock(side_effect=json.JSONDecodeError("", "", 0))
        return resp

    @pytest.mark.asyncio
    async def test_get_success(self, client):
        mock_resp = self._mock_httpx_response(
            status=200,
            text='{"result": "ok"}',
            headers={"content-type": "application/json"},
        )
        client.client.request = AsyncMock(return_value=mock_resp)

        result = await client.get("https://example.com/api")
        assert result["status"] == 200
        assert result["body"] == {"result": "ok"}
        assert result["error"] is None
        assert client.request_count == 1

    @pytest.mark.asyncio
    async def test_get_text_response(self, client):
        mock_resp = self._mock_httpx_response(
            status=200, text="<html>Hello</html>", headers={"content-type": "text/html"}
        )
        client.client.request = AsyncMock(return_value=mock_resp)
        result = await client.get("https://example.com")
        assert result["body"] == "<html>Hello</html>"

    @pytest.mark.asyncio
    async def test_timeout_handling(self, client):
        client.client.request = AsyncMock(side_effect=httpx.TimeoutException("timed out"))
        result = await client.get("https://slow.com")
        assert result["status"] == 0
        assert result["error"] == "timeout"
        assert client.error_count == 1

    @pytest.mark.asyncio
    async def test_connection_error(self, client):
        client.client.request = AsyncMock(side_effect=httpx.ConnectError("refused"))
        result = await client.get("https://down.com")
        assert result["status"] == 0
        assert result["error"] == "connection_error"
        assert client.error_count == 1

    @pytest.mark.asyncio
    async def test_generic_exception(self, client):
        client.client.request = AsyncMock(side_effect=RuntimeError("boom"))
        result = await client.get("https://broken.com")
        assert result["status"] == 0
        assert "boom" in result["error"]

    @pytest.mark.asyncio
    async def test_post(self, client):
        mock_resp = self._mock_httpx_response(status=201, text='{"id": 1}', headers={"content-type": "application/json"})
        client.client.request = AsyncMock(return_value=mock_resp)
        result = await client.post("https://example.com/api/items", json={"name": "test"})
        assert result["status"] == 201
        client.client.request.assert_called_once_with("POST", "https://example.com/api/items", json={"name": "test"})

    @pytest.mark.asyncio
    async def test_put(self, client):
        mock_resp = self._mock_httpx_response(status=200, text='{}', headers={"content-type": "application/json"})
        client.client.request = AsyncMock(return_value=mock_resp)
        result = await client.put("https://example.com/api/items/1", json={"name": "updated"})
        assert result["status"] == 200

    @pytest.mark.asyncio
    async def test_delete(self, client):
        mock_resp = self._mock_httpx_response(status=204, text="", headers={"content-type": "text/plain"})
        client.client.request = AsyncMock(return_value=mock_resp)
        result = await client.delete("https://example.com/api/items/1")
        assert result["status"] == 204

    @pytest.mark.asyncio
    async def test_batch_get(self, client):
        mock_resp = self._mock_httpx_response(status=200, text="ok")
        client.client.request = AsyncMock(return_value=mock_resp)
        results = await client.batch_get(["https://a.com", "https://b.com", "https://c.com"])
        assert len(results) == 3
        assert all(r["status"] == 200 for r in results)

    @pytest.mark.asyncio
    async def test_json_parse_error_falls_back_to_text(self, client):
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200
        mock_resp.text = "not json"
        mock_resp.content = b"not json"
        mock_resp.headers = {"content-type": "application/json"}
        mock_resp.json = MagicMock(side_effect=json.JSONDecodeError("", "", 0))
        client.client.request = AsyncMock(return_value=mock_resp)

        result = await client.get("https://example.com/bad-json")
        assert result["body"] == "not json"


class TestCloudflareDetection:
    def _make_response(self, status, text):
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = status
        resp.text = text
        return resp

    def test_detect_cf_403_challenge(self):
        client = AsyncClient.__new__(AsyncClient)
        resp = self._make_response(403, "<html>Just a moment...</html>")
        assert client._is_cloudflare_challenge(resp) is True

    def test_detect_cf_403_browser_verification(self):
        client = AsyncClient.__new__(AsyncClient)
        resp = self._make_response(403, '<script>cf-browser-verification</script>')
        assert client._is_cloudflare_challenge(resp) is True

    def test_detect_cf_503_cloudflare(self):
        client = AsyncClient.__new__(AsyncClient)
        resp = self._make_response(503, "Cloudflare error page")
        assert client._is_cloudflare_challenge(resp) is True

    def test_no_cf_on_normal_200(self):
        client = AsyncClient.__new__(AsyncClient)
        resp = self._make_response(200, "<html>OK</html>")
        assert client._is_cloudflare_challenge(resp) is False

    def test_no_cf_on_404(self):
        client = AsyncClient.__new__(AsyncClient)
        resp = self._make_response(404, "Not Found")
        assert client._is_cloudflare_challenge(resp) is False

    @pytest.mark.asyncio
    async def test_cloudflare_challenge_response_format(self):
        """When CF challenge detected, response should contain error field."""
        client = AsyncClient(delay=0)
        mock_resp = self._make_response(403, "<html>Just a moment, please...</html>")
        mock_resp.content = mock_resp.text.encode()
        mock_resp.headers = {"content-type": "text/html"}
        client.client.request = AsyncMock(return_value=mock_resp)
        result = await client.get("https://protected.com")
        assert result["error"] == "cloudflare_challenge"


class TestAsyncContextManager:
    @pytest.mark.asyncio
    async def test_context_manager(self):
        client = AsyncClient(delay=0)
        async with client as c:
            assert c is client
        # After exit, client should be closed (no crash)
