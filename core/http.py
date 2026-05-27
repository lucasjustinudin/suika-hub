"""Async HTTP client with Cloudflare bypass and smart retry"""
import asyncio
import random
from typing import Dict, Optional, Any
import httpx
from rich.console import Console

console = Console()

# Realistic browser fingerprints
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
]


class AsyncClient:
    """Async HTTP client with smart features"""

    def __init__(
        self,
        cookies: Dict[str, str] = None,
        headers: Dict[str, str] = None,
        proxy: Optional[str] = None,
        timeout: int = 10,
        concurrency: int = 5,
        delay: float = 1.0,
    ):
        self.delay = delay
        self.semaphore = asyncio.Semaphore(concurrency)
        self.request_count = 0
        self.error_count = 0

        # Build headers
        default_headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "application/json, text/html, */*",
            "Accept-Language": "en-US,en;q=0.9",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Sec-Fetch-Dest": "empty",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Site": "same-origin",
        }
        if headers:
            default_headers.update(headers)

        # Build client
        self.client = httpx.AsyncClient(
            headers=default_headers,
            cookies=cookies or {},
            proxy=proxy,
            timeout=timeout,
            follow_redirects=True,
            http2=True,
        )

    async def request(
        self,
        method: str,
        url: str,
        **kwargs,
    ) -> Dict[str, Any]:
        """Make a request with rate limiting and error handling"""
        async with self.semaphore:
            # Rate limiting with jitter
            jitter = random.uniform(0, self.delay * 0.3)
            await asyncio.sleep(self.delay + jitter)

            try:
                self.request_count += 1
                response = await self.client.request(method, url, **kwargs)

                # Detect Cloudflare challenge
                if self._is_cloudflare_challenge(response):
                    return {
                        "url": url,
                        "status": response.status_code,
                        "error": "cloudflare_challenge",
                        "body": None,
                        "headers": dict(response.headers),
                    }

                # Parse response body
                body = None
                content_type = response.headers.get("content-type", "")
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
                    "headers": dict(response.headers),
                    "error": None,
                    "length": len(response.content),
                }

            except httpx.TimeoutException:
                self.error_count += 1
                return {"url": url, "status": 0, "error": "timeout", "body": None, "headers": {}}
            except httpx.ConnectError:
                self.error_count += 1
                return {"url": url, "status": 0, "error": "connection_error", "body": None, "headers": {}}
            except Exception as e:
                self.error_count += 1
                return {"url": url, "status": 0, "error": str(e), "body": None, "headers": {}}

    async def get(self, url: str, **kwargs) -> Dict[str, Any]:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs) -> Dict[str, Any]:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs) -> Dict[str, Any]:
        return await self.request("PUT", url, **kwargs)

    async def delete(self, url: str, **kwargs) -> Dict[str, Any]:
        return await self.request("DELETE", url, **kwargs)

    async def batch_get(self, urls: list) -> list:
        """Batch GET requests with concurrency control"""
        tasks = [self.get(url) for url in urls]
        return await asyncio.gather(*tasks)

    def _is_cloudflare_challenge(self, response: httpx.Response) -> bool:
        """Detect Cloudflare challenge page"""
        if response.status_code == 403:
            text = response.text[:500]
            if "Just a moment" in text or "cf-browser-verification" in text:
                return True
        if response.status_code == 503 and "cloudflare" in response.text.lower()[:500]:
            return True
        return False

    async def close(self):
        await self.client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()
