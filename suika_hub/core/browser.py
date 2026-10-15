"""Browser automation for Cloudflare bypass and dynamic content."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

try:
    from playwright.async_api import Browser, Page, async_playwright

    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

    Browser = Any  # type: ignore[assignment,misc]
    Page = Any  # type: ignore[assignment,misc]


class BrowserSession:
    """Playwright-based browser session for Cloudflare bypass"""

    def __init__(self, headless: bool = True):
        if not HAS_PLAYWRIGHT:
            raise ImportError("playwright not installed. Run: pip install playwright && playwright install chromium")
        self.headless = headless
        self.browser: Browser | None = None
        self.page: Page | None = None
        self.cookies: dict[str, str] = {}
        self.pw: Any | None = None

    async def start(self):
        """Start browser session"""
        self.pw = await async_playwright().start()
        self.browser = await self.pw.chromium.launch(
            headless=self.headless,
            args=[
                "--disable-blink-features=AutomationControlled",
                "--no-sandbox",
            ],
        )
        context = await self.browser.new_context(
            viewport={"width": 1920, "height": 1080},
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        )
        self.page = await context.new_page()

        # Anti-detection
        await self.page.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
            Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3, 4, 5]});
            window.chrome = {runtime: {}};
        """)

    async def navigate(self, url: str, wait_for_cf: bool = True) -> str:
        """Navigate to a URL and wait for any Cloudflare challenge to clear."""
        assert self.page is not None, "browser session not started"
        await self.page.goto(url, wait_until="domcontentloaded")

        if wait_for_cf:
            # Wait for Cloudflare challenge to resolve
            for _ in range(30):
                title = await self.page.title()
                if "Just a moment" not in title:
                    break
                await asyncio.sleep(1)

        assert self.page is not None, "browser session not started"
        return str(await self.page.content())

    async def get_cookies(self) -> dict[str, str]:
        """Extract cookies after Cloudflare bypass."""
        assert self.page is not None, "browser session not started"
        cookies = await self.page.context.cookies()
        return {c["name"]: c["value"] for c in cookies}

    async def execute_js(self, script: str) -> Any:
        """Execute JavaScript in page context."""
        assert self.page is not None, "browser session not started"
        return await self.page.evaluate(script)

    async def intercept_api(self, url_pattern: str, callback: Callable[..., Awaitable[Any]]) -> None:
        """Intercept API calls."""
        assert self.page is not None, "browser session not started"
        await self.page.route(url_pattern, callback)

    async def get_har(self) -> list[dict[str, Any]]:
        """Capture response entries observed by the page."""
        entries: list[dict[str, Any]] = []

        async def handle_response(response):
            try:
                body = await response.body()
                entries.append(
                    {
                        "url": response.url,
                        "status": response.status,
                        "headers": await response.all_headers(),
                        "body": body.decode("utf-8", errors="replace")[:10000],
                    }
                )
            except Exception:
                pass

        assert self.page is not None, "browser session not started"
        self.page.on("response", handle_response)
        return entries

    async def close(self):
        """Close browser"""
        if self.browser:
            await self.browser.close()
        if self.pw:
            await self.pw.stop()

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, *args):
        await self.close()
