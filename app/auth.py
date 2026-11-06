"""
auth.py - simple API-key protection.

The client must send the header:   X-API-Key: <value from .env>
WHY: anyone on the same Wi-Fi can reach the server, so writes, AI calls and
reports need a password-like key. Reads of dashboard data stay open for the demo.
"""
import secrets

from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader

from app import config

# Using APIKeyHeader (instead of a plain Header) adds an "Authorize" button in /docs.
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def require_api_key(api_key: str | None = Security(api_key_header)) -> None:
    """Add `dependencies=[Depends(require_api_key)]` to any endpoint to protect it."""
    if not config.API_KEY:
        # Fail closed: if the server has no key configured, refuse instead of allowing everyone.
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR,
                            "Server misconfigured: API_KEY is not set in .env")
    # compare_digest avoids leaking the key through response-time differences.
    if api_key is None or not secrets.compare_digest(api_key, config.API_KEY):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing or invalid X-API-Key header")
