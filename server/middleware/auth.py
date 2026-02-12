"""
API Key Authentication Middleware

Addresses audit P0: "No authentication — /v1/analyze endpoint is completely open"

Implements bearer token authentication with constant-time comparison
to prevent timing attacks. API keys are configured via environment
variable CLAW_API_KEYS (comma-separated list).

Unauthenticated endpoints: /v1/health, /docs, /openapi.json
All other endpoints require: Authorization: Bearer <api_key>
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os

from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("claw.auth")

# Endpoints that don't require authentication
PUBLIC_PATHS = {
    "/v1/health",
    "/docs",
    "/openapi.json",
    "/redoc",
    "/",
}


class APIKeyAuth(BaseHTTPMiddleware):
    """
    Bearer token authentication middleware.

    Configure via CLAW_API_KEYS env var (comma-separated).
    If CLAW_API_KEYS is not set, authentication is disabled
    (development mode) with a warning.
    """

    def __init__(self, app, api_keys: list[str] | None = None):
        super().__init__(app)
        if api_keys is None:
            raw = os.environ.get("CLAW_API_KEYS", "")
            self.api_keys = [k.strip() for k in raw.split(",") if k.strip()]
        else:
            self.api_keys = api_keys

        # Pre-hash keys for constant-time comparison
        self._key_hashes = [
            hashlib.sha256(k.encode()).digest()
            for k in self.api_keys
        ]

        if not self.api_keys:
            logger.warning(
                "CLAW_API_KEYS not set — authentication DISABLED. "
                "Set CLAW_API_KEYS for production use."
            )
            self.enabled = False
        else:
            logger.info(f"API key auth enabled with {len(self.api_keys)} key(s)")
            self.enabled = True

    async def dispatch(self, request: Request, call_next):
        # Skip auth for public paths
        if request.url.path in PUBLIC_PATHS:
            return await call_next(request)

        # Skip OPTIONS (CORS preflight)
        if request.method == "OPTIONS":
            return await call_next(request)

        # If auth is disabled (dev mode), allow everything
        if not self.enabled:
            return await call_next(request)

        # Extract bearer token
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            raise HTTPException(
                status_code=401,
                detail="Missing or invalid Authorization header. Use: Bearer <api_key>",
                headers={"WWW-Authenticate": "Bearer"},
            )

        token = auth_header[7:]  # Strip "Bearer "
        token_hash = hashlib.sha256(token.encode()).digest()

        # Constant-time comparison against all valid keys
        is_valid = any(
            hmac.compare_digest(token_hash, key_hash)
            for key_hash in self._key_hashes
        )

        if not is_valid:
            logger.warning(
                f"Auth failed for {request.url.path} from {request.client.host}"
            )
            raise HTTPException(
                status_code=403,
                detail="Invalid API key",
            )

        return await call_next(request)
