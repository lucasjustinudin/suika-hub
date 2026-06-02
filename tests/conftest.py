"""Shared fixtures for suika-hub tests."""
import asyncio
import json
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from suika_hub.core.config import ScanConfig, AuthConfig
from suika_hub.core.module import Finding


# ---------------------------------------------------------------------------
# Sample data factories
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_finding():
    """Return a single sample Finding."""
    return Finding(
        severity="HIGH",
        title="Test Finding",
        description="A test vulnerability finding",
        url="https://example.com/api/vulnerable",
        evidence="Status 200 with sensitive data",
        impact="Data exposure",
        remediation="Fix it",
    )


@pytest.fixture
def sample_findings():
    """Return a list of sample findings with mixed severities."""
    return [
        Finding(
            severity="CRITICAL",
            title="SQL Injection in /api/login",
            description="SQLi via username parameter",
            url="https://example.com/api/login",
        ),
        Finding(
            severity="HIGH",
            title="IDOR in /api/user/{id}",
            description="Cross-user data access",
            url="https://example.com/api/user/2",
        ),
        Finding(
            severity="MEDIUM",
            title="Missing security headers",
            description="X-Frame-Options not set",
            url="https://example.com",
        ),
        Finding(
            severity="LOW",
            title="Server version disclosed",
            description="X-Powered-By header present",
            url="https://example.com",
        ),
        Finding(
            severity="INFO",
            title="Subdomain enumeration",
            description="Found 5 subdomains",
        ),
    ]


@pytest.fixture
def sample_config():
    """Return a basic ScanConfig."""
    return ScanConfig(
        target="https://example.com",
        modules=["recon", "idor"],
        auth=AuthConfig(cookies={"session": "abc123"}, headers={}),
        delay=0.0,   # no delay in tests
        concurrency=2,
        timeout=5,
        output_dir="/tmp/test_reports",
        verbose=False,
    )


@pytest.fixture
def sample_config_dict(sample_config):
    """Return sample config as dict (how modules receive it)."""
    return sample_config.model_dump()


# ---------------------------------------------------------------------------
# Mock HTTP response helpers
# ---------------------------------------------------------------------------

def make_response(
    url: str = "https://example.com/test",
    status: int = 200,
    body: Any = None,
    headers: Dict[str, str] | None = None,
    error: str | None = None,
    length: int = 0,
) -> Dict[str, Any]:
    """Build a fake response dict matching AsyncClient.request() output."""
    if headers is None:
        headers = {"content-type": "application/json"}
    resp: Dict[str, Any] = {
        "url": url,
        "status": status,
        "body": body,
        "headers": headers,
        "error": error,
    }
    if length:
        resp["length"] = length
    else:
        resp["length"] = len(json.dumps(body)) if body else 0
    return resp


@pytest.fixture
def mock_ok_response():
    """A successful JSON response."""
    return make_response(
        body={"data": [{"id": 1, "username": "alice"}, {"id": 2, "username": "bob"}]},
        status=200,
    )


@pytest.fixture
def mock_error_response():
    """A connection-error response."""
    return make_response(status=0, error="connection_error")


@pytest.fixture
def mock_cf_response():
    """A Cloudflare challenge response."""
    return make_response(
        status=403,
        body="<html><head><title>Just a moment...</title></head></html>",
        headers={"content-type": "text/html"},
    )


# ---------------------------------------------------------------------------
# Mock AsyncClient
# ---------------------------------------------------------------------------

class MockAsyncClient:
    """A mock of core.http.AsyncClient that returns configurable responses."""

    def __init__(self, responses: Dict[str, Any] | None = None, default=None):
        # url_substring -> response
        self._responses = responses or {}
        self._default = default or make_response()
        self.request_count = 0
        self.error_count = 0
        self.delay = 0.0
        self.calls: list = []

    async def request(self, method: str, url: str, **kwargs) -> Dict[str, Any]:
        self.request_count += 1
        self.calls.append(("request", method, url, kwargs))
        for pattern, resp in self._responses.items():
            if pattern in url:
                return resp
        return self._default

    async def get(self, url: str, **kwargs) -> Dict[str, Any]:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> Dict[str, Any]:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs) -> Dict[str, Any]:
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> Dict[str, Any]:
        return await self.request("DELETE", url, **kwargs)

    async def batch_get(self, urls: list) -> list:
        return [await self.get(u) for u in urls]

    async def close(self):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


@pytest.fixture
def mock_client():
    """Default mock client returning 404 for everything."""
    return MockAsyncClient(default=make_response(status=404, body={"error": "not found"}))


@pytest.fixture
def mock_client_factory():
    """Factory fixture – call with a dict of url_substring→response."""
    def _factory(responses=None, default=None):
        return MockAsyncClient(responses=responses, default=default)
    return _factory
