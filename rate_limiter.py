"""In-memory per-user sliding-window rate limiter.

This is the IAM side of the rate-limiting extension. Authentication has
already identified the caller before ``SlidingWindowRateLimiter.check`` runs,
so a quota can be applied per account rather than per IP address. A later
backpressure design can replace this class and keep the same ``check`` result.
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass

from config import RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW_SECONDS


@dataclass(frozen=True)
class RateLimitDecision:
    """Outcome of one rate-limit check.

    ``retry_after`` is zero when the request is allowed. When it is blocked,
    ``retry_after`` is the whole number of seconds the caller should wait.
    """

    allowed: bool
    limit: int
    remaining: int
    retry_after: int


class SlidingWindowRateLimiter:
    """Allow up to ``max_requests`` hits per key inside a rolling time window."""

    def __init__(self, max_requests: int, window_seconds: int) -> None:
        if max_requests < 1:
            raise ValueError("max_requests must be at least 1")
        if window_seconds < 1:
            raise ValueError("window_seconds must be at least 1")
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> RateLimitDecision:
        """Record a hit for ``key`` and report whether it is still under the quota.

        A rejected call is not stored, so clients that keep retrying do not
        push their own window further into the future.
        """
        now = time.monotonic()
        cutoff = now - self.window_seconds
        with self._lock:
            hits = self._hits.setdefault(key, deque())
            while hits and hits[0] <= cutoff:
                hits.popleft()
            if len(hits) >= self.max_requests:
                retry_after = max(1, int(hits[0] + self.window_seconds - now) + 1)
                return RateLimitDecision(
                    allowed=False,
                    limit=self.max_requests,
                    remaining=0,
                    retry_after=retry_after,
                )
            hits.append(now)
            remaining = self.max_requests - len(hits)
            return RateLimitDecision(
                allowed=True,
                limit=self.max_requests,
                remaining=remaining,
                retry_after=0,
            )

    def reset(self) -> None:
        """Forget every counter. Used by local checks and a process restart."""
        with self._lock:
            self._hits.clear()


rate_limiter = SlidingWindowRateLimiter(
    max_requests=RATE_LIMIT_REQUESTS,
    window_seconds=RATE_LIMIT_WINDOW_SECONDS,
)
