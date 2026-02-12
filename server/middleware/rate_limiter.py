"""
Token Bucket Rate Limiter

Addresses audit P0: "No rate limiting — Vulnerable to DoS attacks"

Implements per-IP token bucket rate limiting with configurable
rates for different endpoint groups:
- /v1/analyze: 30 req/min (model inference is expensive)
- /v1/policy/*: 60 req/min (lightweight OPA calls)
- /v1/knowledge/*: 60 req/min
- /v1/audit/*: 30 req/min
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("claw.ratelimit")


@dataclass
class TokenBucket:
    """Per-client token bucket for rate limiting."""
    tokens: float
    max_tokens: float
    refill_rate: float  # tokens per second
    last_refill: float

    def consume(self) -> bool:
        """Try to consume a token. Returns True if allowed."""
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.max_tokens, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False

    @property
    def retry_after(self) -> float:
        """Seconds until next token is available."""
        if self.tokens >= 1.0:
            return 0.0
        return (1.0 - self.tokens) / self.refill_rate


# Rate limits: (max_burst, requests_per_minute)
RATE_LIMITS = {
    "/v1/analyze": (10, 30),
    "/v1/policy": (20, 60),
    "/v1/knowledge": (20, 60),
    "/v1/audit": (10, 30),
}
DEFAULT_LIMIT = (20, 60)


class RateLimiter(BaseHTTPMiddleware):
    """
    Per-IP token bucket rate limiter.

    Buckets are keyed by (client_ip, endpoint_group).
    Old buckets are cleaned up periodically.
    """

    def __init__(self, app, enabled: bool = True):
        super().__init__(app)
        self.enabled = enabled
        self._buckets: dict[str, TokenBucket] = {}
        self._last_cleanup = time.monotonic()
        self._cleanup_interval = 300  # 5 minutes

    async def dispatch(self, request: Request, call_next):
        if not self.enabled:
            return await call_next(request)

        # Skip rate limiting for health checks
        if request.url.path in ("/v1/health", "/docs", "/openapi.json"):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        endpoint_group = self._get_endpoint_group(request.url.path)
        bucket_key = f"{client_ip}:{endpoint_group}"

        # Create or get bucket
        bucket = self._get_or_create_bucket(bucket_key, endpoint_group)

        if not bucket.consume():
            retry_after = bucket.retry_after
            logger.warning(
                f"Rate limit exceeded for {client_ip} on {endpoint_group} "
                f"(retry in {retry_after:.1f}s)"
            )
            return JSONResponse(
                status_code=429,
                content={
                    "error": "rate_limit_exceeded",
                    "message": f"Too many requests. Retry after {retry_after:.1f} seconds.",
                    "retry_after_seconds": round(retry_after, 1),
                },
                headers={"Retry-After": str(int(retry_after) + 1)},
            )

        # Periodic cleanup
        self._maybe_cleanup()

        return await call_next(request)

    def _get_endpoint_group(self, path: str) -> str:
        """Map request path to rate limit group."""
        for prefix in RATE_LIMITS:
            if path.startswith(prefix):
                return prefix
        return "default"

    def _get_or_create_bucket(self, key: str, group: str) -> TokenBucket:
        """Get existing bucket or create new one."""
        if key not in self._buckets:
            max_burst, rpm = RATE_LIMITS.get(group, DEFAULT_LIMIT)
            self._buckets[key] = TokenBucket(
                tokens=float(max_burst),
                max_tokens=float(max_burst),
                refill_rate=rpm / 60.0,
                last_refill=time.monotonic(),
            )
        return self._buckets[key]

    def _maybe_cleanup(self) -> None:
        """Remove stale buckets periodically."""
        now = time.monotonic()
        if now - self._last_cleanup < self._cleanup_interval:
            return

        self._last_cleanup = now
        stale_threshold = now - 600  # 10 minutes
        stale_keys = [
            k for k, v in self._buckets.items()
            if v.last_refill < stale_threshold
        ]
        for k in stale_keys:
            del self._buckets[k]

        if stale_keys:
            logger.debug(f"Cleaned up {len(stale_keys)} stale rate limit buckets")
