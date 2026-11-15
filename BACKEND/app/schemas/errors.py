"""Error schemas matching the SafeLinks API contract."""

from enum import StrEnum

from pydantic import BaseModel, Field


class ErrorCode(StrEnum):
    INVALID_URL = "INVALID_URL"
    INVALID_REQUEST = "INVALID_REQUEST"
    UNSUPPORTED_SCHEME = "UNSUPPORTED_SCHEME"
    BLOCKED_TARGET = "BLOCKED_TARGET"
    NOT_FOUND = "NOT_FOUND"
    RATE_LIMITED = "RATE_LIMITED"
    INTERNAL = "INTERNAL"


class ErrorBody(BaseModel):
    code: ErrorCode
    message: str
    request_id: str | None = None


class ErrorResponse(BaseModel):
    error: ErrorBody = Field(..., description="Error payload details")
