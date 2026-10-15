"""Tests for suika_hub.core.ratelimit -- RateLimiter and ProxyPool."""

import asyncio
import time

import pytest

from suika_hub.core.ratelimit import ProxyPool, RateLimiter, host_of


class TestHostOf:
    def test_extracts_hostname(self):
        assert host_of("https://api.example.com/v1/users") == "api.example.com"

    def test_ignores_port(self):
        assert host_of("http://localhost:8080/x") == "localhost"

    def test_garbage_falls_back_to_input(self):
        assert host_of("not a url") == "not a url"


class TestRateLimiterDisabled:
    def test_rate_zero_disables(self):
        assert RateLimiter(rate=0).enabled is False

    @pytest.mark.asyncio
    async def test_disabled_limiter_does_not_block(self):
        limiter = RateLimiter(rate=0)
        start = time.monotonic()
        for _ in range(20):
            await limiter.acquire("https://example.com/x")
        assert time.monotonic() - start < 0.5


class TestRateLimiterEnabled:
    @pytest.mark.asyncio
    async def test_burst_allows_immediate_requests(self):
        """A bucket of size 5 must let 5 requests through without waiting."""
        limiter = RateLimiter(rate=1.0, burst=5)
        start = time.monotonic()
        for _ in range(5):
            await limiter.acquire("https://example.com/x")
        assert time.monotonic() - start < 0.5

    @pytest.mark.asyncio
    async def test_exceeding_burst_waits(self):
        limiter = RateLimiter(rate=20.0, burst=1)
        await limiter.acquire("https://example.com/x")
        start = time.monotonic()
        await limiter.acquire("https://example.com/x")
        # At 20 rps the refill for one token takes ~50ms.
        assert time.monotonic() - start >= 0.02

    @pytest.mark.asyncio
    async def test_hosts_have_independent_buckets(self):
        """Exhausting host A must not throttle host B."""
        limiter = RateLimiter(rate=1.0, burst=1)
        await limiter.acquire("https://a.example.com/x")
        start = time.monotonic()
        await limiter.acquire("https://b.example.com/x")
        assert time.monotonic() - start < 0.2

    @pytest.mark.asyncio
    async def test_concurrent_acquires_respect_bucket(self):
        """The per-host lock must stop concurrent callers overrunning the bucket."""
        limiter = RateLimiter(rate=50.0, burst=2)
        start = time.monotonic()
        await asyncio.gather(*[limiter.acquire("https://example.com/x") for _ in range(6)])
        # 6 requests with a 2-token bucket at 50 rps needs ~80ms of refill.
        assert time.monotonic() - start >= 0.05

    @pytest.mark.asyncio
    async def test_default_delay_applied(self):
        limiter = RateLimiter(rate=0, default_delay=0.05)
        start = time.monotonic()
        await limiter.acquire("https://example.com/x")
        assert time.monotonic() - start >= 0.04


class TestProxyPoolEmpty:
    def test_falsy_when_empty(self):
        assert not ProxyPool()

    def test_next_returns_none_when_empty(self):
        assert ProxyPool().next() is None

    def test_report_calls_are_safe_without_proxies(self):
        pool = ProxyPool()
        pool.report_success(None)
        pool.report_failure(None)
        assert pool.stats()["total"] == 0


class TestProxyPoolRotation:
    def test_round_robin_cycles(self):
        pool = ProxyPool(["p1", "p2", "p3"], strategy="round_robin")
        seen = [pool.next() for _ in range(6)]
        assert seen == ["p1", "p2", "p3", "p1", "p2", "p3"]

    def test_random_only_returns_pool_members(self):
        pool = ProxyPool(["p1", "p2"], strategy="random")
        assert all(pool.next() in {"p1", "p2"} for _ in range(20))

    def test_len_reports_pool_size(self):
        assert len(ProxyPool(["a", "b"])) == 2

    def test_empty_strings_filtered(self):
        assert len(ProxyPool(["", None, "p1"])) == 1


class TestProxyPoolCooldown:
    def test_failures_below_threshold_keep_proxy_available(self):
        pool = ProxyPool(["p1"], cooldown_after=3)
        pool.report_failure("p1")
        pool.report_failure("p1")
        assert pool.stats()["available"] == 1

    def test_threshold_parks_proxy(self):
        pool = ProxyPool(["p1", "p2"], cooldown_after=2)
        pool.report_failure("p1")
        pool.report_failure("p1")
        assert "p1" in pool.stats()["cooling_down"]
        assert pool.stats()["available"] == 1
        assert pool.next() == "p2"

    def test_success_clears_cooldown(self):
        pool = ProxyPool(["p1"], cooldown_after=1)
        pool.report_failure("p1")
        assert pool.stats()["available"] == 0
        pool.report_success("p1")
        assert pool.stats()["available"] == 1

    def test_all_cooling_down_still_returns_something(self):
        """An exhausted pool degrades to the soonest-expiring proxy, not a crash."""
        pool = ProxyPool(["p1", "p2"], cooldown_after=1, cooldown_seconds=60)
        pool.report_failure("p1")
        pool.report_failure("p2")
        assert pool.stats()["available"] == 0
        assert pool.next() in {"p1", "p2"}

    def test_cooldown_expires(self):
        pool = ProxyPool(["p1"], cooldown_after=1, cooldown_seconds=0.05)
        pool.report_failure("p1")
        assert pool.stats()["available"] == 0
        time.sleep(0.08)
        assert pool.stats()["available"] == 1
