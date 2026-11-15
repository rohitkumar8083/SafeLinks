"""Logging configuration with request ID tracking and sensitive data sanitization."""

import contextvars
import logging
import re
import sys

# Context variable to hold active request ID
request_id_ctx: contextvars.ContextVar[str | None] = contextvars.ContextVar("request_id_ctx", default=None)

# Pattern to redact API keys and secrets in query parameters or logs
KEY_REDACT_PATTERN = re.compile(r"(key|api_key|token|auth)=([a-zA-Z0-9_\-\.]+)", re.IGNORECASE)


class RequestIdFilter(logging.Filter):
    """Injects current request ID from contextvars into log record."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_ctx.get() or "-"
        return True


class RedactingFormatter(logging.Formatter):
    """Sanitizes sensitive information from log messages."""

    def format(self, record: logging.LogRecord) -> str:
        original = super().format(record)
        # Redact any key=... query parameters
        return KEY_REDACT_PATTERN.sub(r"\1=[REDACTED]", original)


def setup_logging(log_level: str = "INFO") -> None:
    """Configures application-wide logging."""
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)

    # Remove existing handlers to avoid duplicates
    for handler in list(root_logger.handlers):
        root_logger.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(numeric_level)

    formatter = RedactingFormatter(
        fmt="%(asctime)s [%(levelname)s] [req:%(request_id)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )
    handler.setFormatter(formatter)
    handler.addFilter(RequestIdFilter())
    root_logger.addHandler(handler)

    # Silence noisy low-level HTTP client libraries
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
