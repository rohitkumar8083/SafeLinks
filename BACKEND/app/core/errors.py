"""Custom application errors and FastAPI exception handlers."""

import logging
from typing import Any

from fastapi import Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.schemas.errors import ErrorCode

logger = logging.getLogger("safelinks.errors")


class SafeLinksAppError(Exception):
    """Base exception for application-level managed errors."""

    def __init__(self, code: ErrorCode, status_code: int, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.status_code = status_code
        self.message = message


class InvalidUrlError(SafeLinksAppError):
    def __init__(self, message: str = "Invalid URL provided") -> None:
        super().__init__(ErrorCode.INVALID_URL, 422, message)


class InvalidRequestError(SafeLinksAppError):
    def __init__(self, message: str = "Invalid request payload") -> None:
        super().__init__(ErrorCode.INVALID_REQUEST, 422, message)


class UnsupportedSchemeError(SafeLinksAppError):
    def __init__(self, message: str = "Scheme is not supported; only http and https are allowed") -> None:
        super().__init__(ErrorCode.UNSUPPORTED_SCHEME, 422, message)


class BlockedTargetError(SafeLinksAppError):
    def __init__(self, message: str = "Target host or IP address is blocked by security policy") -> None:
        super().__init__(ErrorCode.BLOCKED_TARGET, 422, message)


class NotFoundError(SafeLinksAppError):
    def __init__(self, message: str = "Resource not found or has expired") -> None:
        super().__init__(ErrorCode.NOT_FOUND, 404, message)


class RateLimitedError(SafeLinksAppError):
    def __init__(self, message: str = "The server is busy, please try again shortly") -> None:
        super().__init__(ErrorCode.RATE_LIMITED, 429, message)


class InternalError(SafeLinksAppError):
    def __init__(self, message: str = "An internal server error occurred") -> None:
        super().__init__(ErrorCode.INTERNAL, 500, message)


def get_request_id(request: Request) -> str | None:
    """Helper to retrieve request ID from request state or header."""
    return getattr(request.state, "request_id", None) or request.headers.get("X-Request-ID")


def make_error_payload(code: ErrorCode | str, message: str, request_id: str | None) -> dict[str, Any]:
    return {
        "error": {
            "code": code.value if isinstance(code, ErrorCode) else code,
            "message": message,
            "request_id": request_id,
        }
    }


async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Handles FastAPI/Pydantic validation errors."""
    req_id = get_request_id(request)
    errors = exc.errors()

    # Determine if 'url' field caused the validation error
    is_url_error = any("url" in err.get("loc", ()) for err in errors)

    if is_url_error:
        code = ErrorCode.INVALID_URL
        # Extract first human-readable error message
        first_msg = errors[0].get("msg", "Invalid URL provided")
        message = f"Invalid URL: {first_msg}"
    else:
        code = ErrorCode.INVALID_REQUEST
        first_msg = errors[0].get("msg", "Invalid request parameters")
        loc_desc = " -> ".join(str(loc) for loc in errors[0].get("loc", ()))
        message = f"Invalid request ({loc_desc}): {first_msg}"

    logger.warning("Validation error on %s %s [%s]: %s", request.method, request.url.path, req_id, message)
    return JSONResponse(
        status_code=422,
        content=make_error_payload(code, message, req_id),
        headers={"Cache-Control": "no-store", "X-Request-ID": req_id or ""},
    )


async def safelinks_app_error_handler(request: Request, exc: SafeLinksAppError) -> JSONResponse:
    """Handles known SafeLinks application domain exceptions."""
    req_id = get_request_id(request)
    logger.info(
        "Application error on %s %s [%s] code=%s: %s",
        request.method,
        request.url.path,
        req_id,
        exc.code.value,
        exc.message,
    )
    return JSONResponse(
        status_code=exc.status_code,
        content=make_error_payload(exc.code, exc.message, req_id),
        headers={"Cache-Control": "no-store", "X-Request-ID": req_id or ""},
    )


async def starlette_http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    """Handles standard Starlette HTTP exceptions like 404 or 405."""
    req_id = get_request_id(request)

    if exc.status_code == 404:
        code = ErrorCode.NOT_FOUND
        msg = "The requested resource was not found or has expired."
    elif exc.status_code == 429:
        code = ErrorCode.RATE_LIMITED
        msg = "Rate limit exceeded. Please try again shortly."
    else:
        code = ErrorCode.INVALID_REQUEST if exc.status_code == 400 else ErrorCode.INTERNAL
        msg = exc.detail if isinstance(exc.detail, str) else "HTTP request error"

    return JSONResponse(
        status_code=exc.status_code,
        content=make_error_payload(code, msg, req_id),
        headers={"Cache-Control": "no-store", "X-Request-ID": req_id or ""},
    )


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catches unexpected exceptions, logs traceback with request ID, and returns safe response."""
    req_id = get_request_id(request)
    logger.exception("Unhandled server exception processing [%s] %s %s: %s", req_id, request.method, request.url.path, exc)
    return JSONResponse(
        status_code=500,
        content=make_error_payload(
            ErrorCode.INTERNAL,
            "An unexpected internal error occurred. Please try again later.",
            req_id,
        ),
        headers={"Cache-Control": "no-store", "X-Request-ID": req_id or ""},
    )
