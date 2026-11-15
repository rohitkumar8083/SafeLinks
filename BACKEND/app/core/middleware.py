"""Custom middleware for request ID correlation and security headers."""

import re
import uuid
from collections.abc import Awaitable, Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from app.constants import (
    HEADER_CACHE_CONTROL,
    HEADER_CACHE_CONTROL_VALUE,
    HEADER_REQUEST_ID,
)
from app.core.logging import request_id_ctx

# Validate sane incoming request ID (alphanumeric, hyphen, underscore, 8 to 64 chars)
SANE_REQUEST_ID_REGEX = re.compile(r"^[a-zA-Z0-9_\-]{8,64}$")


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Assigns or propagates correlation request ID and sets security headers."""

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        incoming_id = request.headers.get(HEADER_REQUEST_ID)
        if incoming_id and SANE_REQUEST_ID_REGEX.match(incoming_id):
            req_id = incoming_id
        else:
            req_id = str(uuid.uuid4())

        # Store in request state and logging context
        request.state.request_id = req_id
        token = request_id_ctx.set(req_id)

        try:
            response = await call_next(request)
        finally:
            request_id_ctx.reset(token)

        # Inject contract headers
        response.headers[HEADER_REQUEST_ID] = req_id
        response.headers[HEADER_CACHE_CONTROL] = HEADER_CACHE_CONTROL_VALUE
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"

        return response
