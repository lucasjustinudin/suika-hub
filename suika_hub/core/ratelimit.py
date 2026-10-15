"""Per-host rate limiting and proxy rotation.

A single global semaphore plus a fixed delay is the wrong shape for scanning:
the limit that matters is *per host*, and one slow or hostile host should not
consume the whole scan's budget. This module provides:

- :class:`RateLimiter` -- token-bucket limiter keyed by host, so
  ``api.example.com`` and ``cdn.example.com`` get independent budgets;
- :class:`ProxyPool` -- round-robin/random rotation with automatic cooldown of
  proxies that keep failing, which is what makes rotation useful rather than
  cosmetic.
"""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse


def host_of(url: str) -> str:
    """Return the hostname of a URL, falling back to the raw string."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return url
    return parsed.hostname or url


@dataclass
class _Bucket:
    """Token bucket for a single host."""

    capacity: float
    refill_per_second: float
    tokens: float = 0.0
    updated: float = field(default_factory=time.monotonic)

    def __post_init__(self) -> None:
        if self.tokens == 0.0:
            self.tokens = self.capacity

    def take(self) -> float:
        """Reserve one token and return the seconds the caller must wait.

        The balance is allowed to go negative so that each successive concurrent
        caller gets a *later* wake time. Consuming a token and then sleeping
        without reserving would let N callers read the same empty bucket, sleep
        the same duration, and all fire at once -- rate limiting that only works
        when nothing is concurrent.
        """
        now = time.monotonic()
        elapsed = now - self.updated
        self.updated = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_second)

        self.tokens -= 1.0
        if self.tokens >= 0.0 or self.refill_per_second <= 0:
            return 0.0
        return -self.tokens / self.refill_per_second


class RateLimiter:
    """Per-host token-bucket limiter.

    ``rate`` is requests per second per host; ``burst`` is the bucket size.
    A ``rate`` of 0 disables limiting, which is what the tests and offline
    module runs want.
    """

    def __init__(self, rate: float = 5.0, burst: int | None = None, default_delay: float = 0.0):
        self.rate = max(0.0, rate)
        self.burst = burst if burst is not None else max(1, int(rate) or 1)
        self.default_delay = max(0.0, default_delay)
        self._buckets: dict[str, _Bucket] = {}
        self._locks: dict[str, asyncio.Lock] = {}

    @property
    def enabled(self) -> bool:
        return self.rate > 0

    def _bucket_for(self, host: str) -> _Bucket:
        bucket = self._buckets.get(host)
        if bucket is None:
            bucket = _Bucket(capacity=float(self.burst), refill_per_second=self.rate)
            self._buckets[host] = bucket
        return bucket

    def _lock_for(self, host: str) -> asyncio.Lock:
        lock = self._locks.get(host)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[host] = lock
        return lock

    async def acquire(self, url: str) -> float:
        """Block until a request to ``url``'s host is allowed. Returns wait time."""
        total_wait = self.default_delay
        if self.default_delay > 0:
            await asyncio.sleep(self.default_delay)

        if not self.enabled:
            return total_wait

        host = host_of(url)
        # The lock serialises token accounting per host; without it, concurrent
        # coroutines can all read the same token balance and overrun the bucket.
        async with self._lock_for(host):
            wait = self._bucket_for(host).take()

        if wait > 0:
            await asyncio.sleep(wait)
            total_wait += wait
        return total_wait


class ProxyPool:
    """Rotate proxies, cooling down the ones that keep failing.

    ``cooldown_after`` consecutive failures parks a proxy for
    ``cooldown_seconds``. Dead proxies are not removed permanently, because
    most failures are transient upstream blips rather than a dead endpoint.
    """

    def __init__(
        self,
        proxies: list[str] | None = None,
        strategy: str = "round_robin",
        cooldown_after: int = 3,
        cooldown_seconds: float = 60.0,
    ):
        self.proxies = [p for p in (proxies or []) if p]
        self.strategy = strategy if strategy in {"round_robin", "random"} else "round_robin"
        self.cooldown_after = max(1, cooldown_after)
        self.cooldown_seconds = max(0.0, cooldown_seconds)
        self._index = 0
        self._failures: dict[str, int] = {}
        self._blocked_until: dict[str, float] = {}

    def __bool__(self) -> bool:
        return bool(self.proxies)

    def __len__(self) -> int:
        return len(self.proxies)

    def _available(self) -> list[str]:
        now = time.monotonic()
        return [p for p in self.proxies if self._blocked_until.get(p, 0.0) <= now]

    def next(self) -> str | None:
        """Return the next usable proxy, or None when the pool is empty/exhausted."""
        if not self.proxies:
            return None

        candidates = self._available()
        if not candidates:
            # Everything is cooling down: use the one whose cooldown expires
            # soonest rather than failing the request outright.
            return min(self.proxies, key=lambda p: self._blocked_until.get(p, 0.0))

        if self.strategy == "random":
            return random.choice(candidates)

        proxy = candidates[self._index % len(candidates)]
        self._index += 1
        return proxy

    def report_success(self, proxy: str | None) -> None:
        """Clear the failure streak for a proxy that just worked."""
        if proxy:
            self._failures.pop(proxy, None)
            self._blocked_until.pop(proxy, None)

    def report_failure(self, proxy: str | None) -> None:
        """Record a failure and start a cooldown once the threshold is reached."""
        if not proxy:
            return
        count = self._failures.get(proxy, 0) + 1
        self._failures[proxy] = count
        if count >= self.cooldown_after:
            self._blocked_until[proxy] = time.monotonic() + self.cooldown_seconds
            self._failures[proxy] = 0

    def stats(self) -> dict[str, object]:
        """Snapshot of pool state, for reporting."""
        now = time.monotonic()
        return {
            "total": len(self.proxies),
            "available": len(self._available()),
            "cooling_down": [p for p in self.proxies if self._blocked_until.get(p, 0.0) > now],
            "strategy": self.strategy,
        }
