"""SlowAPI rate limiter configuration and contract error handler."""

from fastapi import Request
from fastapi.responses import JSONResponse
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded

from app.config import settings
from app.core.errors import get_request_id


def get_client_ip(request: Request) -> str:
    """Extracts client IP from X-Forwarded-For if TRUST_PROXY_HEADERS is enabled, else socket host."""
    if settings.TRUST_PROXY_HEADERS:
        x_forwarded = request.headers.get("X-Forwarded-For")
        if x_forwarded:
            return x_forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


# Singleton SlowAPI Limiter configured per client IP
limiter = Limiter(
    key_func=get_client_ip,
    default_limits=[],
    headers_enabled=False,
)


def custom_rate_limit_exceeded_handler(request: Request, exc: RateLimitExceeded) -> JSONResponse:
    """Returns 429 RATE_LIMITED response matching API contract."""
    req_id = get_request_id(request)
    return JSONResponse(
        status_code=429,
        content={
            "error": {
                "code": "RATE_LIMITED",
                "message": "Rate limit exceeded. Please try again shortly.",
                "request_id": req_id,
            }
        },
        headers={
            "Cache-Control": "no-store",
            "X-Request-ID": req_id or "",
            "Retry-After": str(exc.detail or 60),
        },
    )
