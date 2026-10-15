"""Async HTTP client with WAF detection, retry, and per-host rate limiting.

Design notes that matter in practice:

- **Fingerprint coherence.** ``httpx`` sends its own default headers per request.
  Pinning a browser UA while the transport advertises ``python-httpx`` is a
  trivially detectable mismatch, so fingerprint headers are set as one coherent
  set and client hints are derived from the chosen UA.
- **Per-host limits beat a global delay.** A single global sleep makes a scan
  with one slow host as slow as a scan with fifty.
- **Retries must honour Retry-After.** A 429 retried on our own schedule is how
  an IP gets banned; see :mod:`suika_hub.core.retry`.
"""

from __future__ import annotations

import asyncio
import random
from typing import Any

import httpx
from rich.console import Console

from suika_hub.core.ratelimit import ProxyPool, RateLimiter
from suika_hub.core.retry import RetryPolicy, sleep_for

console = Console()

# Realistic, current browser fingerprints, kept in sync with the matching
# sec-ch-ua client hints so the header set stays internally consistent.
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
]

# Signatures of common WAF / challenge products, matched against body + headers.
WAF_SIGNATURES: dict[str, tuple[str, ...]] = {
    "cloudflare": (
        "cloudflare",
        "just a moment",
        "cf-browser-verification",
        "cf-chl-",
        "__cf_chl",
        "cf-ray",
    ),
    "akamai": ("akamai", "ak-bmsc", "_abck"),
    "imperva": ("incapsula", "_incap_ses", "visid_incap"),
    "datadome": ("datadome", "dd_cookie", "geo.captcha-delivery.com"),
    "aws_waf": ("awselb", "aws-waf-token", "x-amzn-waf"),
    "sucuri": ("sucuri", "x-sucuri-id", "cloudproxy"),
    "f5": ("bigipserver", "f5 networks"),
    "azure": ("azurefd", "x-azure-ref"),
}


class AsyncClient:
    """Async HTTP client with retry, per-host rate limiting, and proxy rotation."""

    def __init__(
        self,
        cookies: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        proxy: str | None = None,
        proxies: list[str] | None = None,
        timeout: int = 10,
        concurrency: int = 5,
        delay: float = 1.0,
        rate_limit: float = 5.0,
        burst: int | None = None,
        retry_policy: RetryPolicy | None = None,
        rotate_user_agent: bool = True,
    ):
        self.delay = delay
        self.semaphore = asyncio.Semaphore(concurrency)
        self.request_count = 0
        self.error_count = 0
        self.retry_count = 0
        self.rotate_user_agent = rotate_user_agent

        # Proxy rotation: an explicit list wins; a single proxy becomes a
        # one-entry pool so the reporting path is identical either way.
        pool = list(proxies or [])
        if proxy and proxy not in pool:
            pool.insert(0, proxy)
        self.proxy_pool = ProxyPool(pool)

        self.limiter = RateLimiter(rate=rate_limit, burst=burst, default_delay=delay)
        self.retry_policy = retry_policy or RetryPolicy()
        self._user_agent = random.choice(USER_AGENTS) if rotate_user_agent else USER_AGENTS[0]

        default_headers = {
            "User-Agent": self._user_agent,
            "Accept": "application/json, text/html, */*",
            "Accept-Language": "en-US,en;q=0.9",
            # httpx decodes the body itself; advertising br without the codec
            # installed yields responses it cannot decode.
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
        }
        default_headers.update(_client_hints(self._user_agent))
        if headers:
            default_headers.update(headers)

        self.client = httpx.AsyncClient(
            headers=default_headers,
            cookies=cookies or {},
            timeout=timeout,
            follow_redirects=True,
            http2=True,
            verify=True,
        )

    async def request(
        self,
        method: str,
        url: str,
        **kwargs,
    ) -> dict[str, Any]:
        """Make a request, retrying transient failures with backoff."""
        async with self.semaphore:
            await self.limiter.acquire(url)

            last: dict[str, Any] = {}
            for attempt in range(1, self.retry_policy.max_attempts + 1):
                last = await self._once(method, url, **kwargs)

                if not self.retry_policy.should_retry(last):
                    return last
                if attempt >= self.retry_policy.max_attempts:
                    break

                wait = self.retry_policy.delay_for(attempt, last)
                self.retry_count += 1
                await sleep_for(wait)

            return last

    async def _once(self, method: str, url: str, **kwargs) -> dict[str, Any]:
        """Perform a single attempt, mapping transport errors to response dicts."""
        proxy = self.proxy_pool.next()
        request_kwargs = dict(kwargs)
        if proxy and "proxy" not in request_kwargs:
            request_kwargs["proxy"] = proxy

        try:
            self.request_count += 1
            response = await self.client.request(method, url, **request_kwargs)
        except httpx.TimeoutException:
            self.error_count += 1
            self.proxy_pool.report_failure(proxy)
            return {"url": url, "status": 0, "error": "timeout", "body": None, "headers": {}}
        except httpx.ConnectError:
            self.error_count += 1
            self.proxy_pool.report_failure(proxy)
            return {"url": url, "status": 0, "error": "connection_error", "body": None, "headers": {}}
        except httpx.HTTPError as exc:
            self.error_count += 1
            self.proxy_pool.report_failure(proxy)
            return {"url": url, "status": 0, "error": type(exc).__name__.lower(), "body": None, "headers": {}}
        except Exception as exc:  # noqa: BLE001 - surfaced to the caller as a non-finding error
            self.error_count += 1
            self.proxy_pool.report_failure(proxy)
            return {"url": url, "status": 0, "error": str(exc), "body": None, "headers": {}}

        self.proxy_pool.report_success(proxy)
        headers = dict(response.headers)

        waf = self.detect_waf(response)
        if waf:
            return {
                "url": url,
                "status": response.status_code,
                "error": "waf_blocked",
                "waf": waf,
                "body": None,
                "headers": headers,
            }

        body: Any
        content_type = headers.get("content-type", "")
        if "json" in content_type:
            try:
                body = response.json()
            except Exception:
                body = response.text
        else:
            body = response.text

        return {
            "url": url,
            "status": response.status_code,
            "body": body,
            "headers": headers,
            "error": None,
            "length": len(response.content),
        }

    async def get(self, url: str, **kwargs) -> dict[str, Any]:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> dict[str, Any]:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs) -> dict[str, Any]:
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> dict[str, Any]:
        return await self.request("DELETE", url, **kwargs)

    async def batch_get(self, urls: list[str]) -> list[dict[str, Any]]:
        """Batch GET requests with concurrency control."""
        tasks = [self.get(url) for url in urls]
        return list(await asyncio.gather(*tasks))

    def detect_waf(self, response: httpx.Response) -> str | None:
        """Identify the WAF/challenge product blocking a response, if any.

        Only inspects responses that could plausibly be a block page, and only
        the first 4 KB: scanning a multi-megabyte application response for
        vendor strings is wasted work and false-positives on pages that merely
        mention a vendor.
        """
        if response.status_code not in (401, 403, 406, 429, 503):
            return None

        haystack = response.text[:4000].lower()
        raw_headers = getattr(response, "headers", None) or {}
        try:
            header_blob = " ".join(f"{k}:{v}" for k, v in raw_headers.items()).lower()
        except AttributeError:
            header_blob = ""

        for name, needles in WAF_SIGNATURES.items():
            for needle in needles:
                if needle in haystack or needle in header_blob:
                    return name
        return None

    # Retained under the historical name for module compatibility.
    def _is_cloudflare_challenge(self, response: httpx.Response) -> bool:
        """Return True when the response looks like a Cloudflare challenge."""
        return self.detect_waf(response) == "cloudflare"

    def stats(self) -> dict[str, Any]:
        """Request/error/retry counters plus proxy pool state."""
        return {
            "requests": self.request_count,
            "errors": self.error_count,
            "retries": self.retry_count,
            "proxies": self.proxy_pool.stats(),
        }

    async def close(self):
        await self.client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()


def _client_hints(user_agent: str) -> dict[str, str]:
    """Derive sec-ch-ua client hints matching ``user_agent``.

    Firefox does not send client hints at all, so emitting them alongside a
    Firefox UA would itself be the tell.
    """
    if "Firefox" in user_agent:
        return {}

    if "Windows" in user_agent:
        platform = '"Windows"'
    elif "Macintosh" in user_agent:
        platform = '"macOS"'
    else:
        platform = '"Linux"'

    return {
        "sec-ch-ua": '"Chromium";v="131", "Not_A Brand";v="24", "Google Chrome";v="131"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": platform,
    }
