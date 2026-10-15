"""Retry policy with exponential backoff, jitter, and Retry-After support.

The engine hits real targets behind CDNs and WAFs, so a naive retry loop either
hammers a rate-limited host or gives up on a transient 502. This module encodes
the policy that works in practice:

- retry only on transient conditions (429, 5xx, connection/timeout errors);
- honour ``Retry-After`` when the server sends it, because ignoring it is how a
  scanner earns a hard IP ban;
- back off exponentially with full jitter so concurrent workers do not
  re-synchronise into a thundering herd;
- cap total attempts and total wall-clock so one dead host cannot stall a scan.
"""

from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from typing import Any

# Status codes worth a second attempt. 4xx other than 429 are deterministic
# rejections: retrying them wastes budget and looks like an attack.
RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504, 520, 521, 522, 523, 524})

# Error strings produced by AsyncClient when the request never completed.
RETRYABLE_ERRORS = frozenset(
    {
        "timeout",
        "connecttimeout",
        "readtimeout",
        "connect_error",
        "connection_error",
        "readerror",
        "remoteprotocolerror",
        "pooltimeout",
    }
)


@dataclass
class RetryPolicy:
    """Configuration for retry behaviour.

    ``max_attempts`` counts the initial attempt, so ``3`` means at most two
    retries.
    """

    max_attempts: int = 3
    base_delay: float = 0.5
    max_delay: float = 30.0
    jitter: bool = True
    respect_retry_after: bool = True
    total_budget: float = 120.0
    retryable_status: frozenset[int] = field(default_factory=lambda: RETRYABLE_STATUS)

    def should_retry(self, response: dict[str, Any]) -> bool:
        """Return True when a response dict warrants another attempt."""
        error = response.get("error")
        if error:
            return str(error).lower().replace(" ", "") in RETRYABLE_ERRORS
        status = response.get("status", 0)
        if status == 0:
            # No status and no error means the response never landed.
            return True
        return status in self.retryable_status

    def delay_for(self, attempt: int, response: dict[str, Any] | None = None) -> float:
        """Seconds to wait before ``attempt`` (1-based, attempt 1 = first retry)."""
        if self.respect_retry_after and response:
            server_delay = parse_retry_after(response.get("headers") or {})
            if server_delay is not None:
                # Trust the server, but never sleep past our own ceiling.
                return min(server_delay, self.max_delay)

        # Exponential backoff, optionally with full jitter (AWS-style): the
        # jittered value is drawn uniformly from [0, cap] so parallel workers
        # spread out instead of retrying in lockstep.
        cap: float = min(float(self.base_delay) * (2 ** (attempt - 1)), float(self.max_delay))
        if self.jitter:
            return float(random.uniform(0, cap))
        return cap


def parse_retry_after(headers: dict[str, Any]) -> float | None:
    """Extract a delay in seconds from a ``Retry-After`` header.

    The header is either a delta-seconds integer or an HTTP-date. Returns
    ``None`` when absent or unparseable, so callers can fall back to backoff.
    """
    raw = None
    for key, value in headers.items():
        if str(key).lower() == "retry-after":
            raw = value
            break
    if raw is None:
        return None

    text = str(raw).strip()
    if not text:
        return None

    try:
        return max(0.0, float(text))
    except (TypeError, ValueError):
        pass

    # Fall through to HTTP-date parsing below.

    try:
        when = parsedate_to_datetime(text)
    except (TypeError, ValueError):
        return None
    if when is None:
        return None

    import datetime as _dt

    now = _dt.datetime.now(tz=when.tzinfo) if when.tzinfo else _dt.datetime.now()
    return max(0.0, float((when - now).total_seconds()))


async def sleep_for(delay: float) -> None:
    """Await ``delay`` seconds. Split out so tests can patch it."""
    if delay > 0:
        await asyncio.sleep(delay)
