"""FastAPI application factory, lifespan management, middleware, routers, and error handlers."""

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import RedirectResponse
from slowapi.errors import RateLimitExceeded
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.deps import get_repository
from app.api.v1.router import api_v1_router
from app.config import Settings, settings
from app.core.errors import (
    SafeLinksAppError,
    safelinks_app_error_handler,
    starlette_http_exception_handler,
    unhandled_exception_handler,
    validation_exception_handler,
)
from app.core.http_client import set_shared_client
from app.core.logging import setup_logging
from app.core.middleware import RequestIdMiddleware
from app.core.rate_limit import custom_rate_limit_exceeded_handler, limiter
from app.ml.predict import PhishingPredictor, set_shared_predictor
from app.repositories.scan_repo import InMemoryScanRepository
from app.services.scan_orchestrator import cancel_all_tasks

logger = logging.getLogger("safelinks.main")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Manages application lifecycle: logging, shared HTTP client, and background tasks."""
    # 1. Initialize logging
    setup_logging(settings.LOG_LEVEL)
    logger.info("Starting %s v%s in %s mode", settings.APP_NAME, settings.APP_VERSION, settings.ENVIRONMENT)

    # 2. Initialize shared httpx AsyncClient
    client = httpx.AsyncClient(
        timeout=httpx.Timeout(settings.HTTP_TIMEOUT_SECONDS),
        follow_redirects=False,
    )
    set_shared_client(client)

    # 3. Start repository background purge worker if applicable
    repo = get_repository()
    if isinstance(repo, InMemoryScanRepository):
        repo.start_purge_worker()

    # 4. Load ML phishing model
    predictor = PhishingPredictor(model_path=settings.MODEL_PATH)
    set_shared_predictor(predictor)
    app.state.ml_predictor = predictor

    try:
        yield
    finally:
        logger.info("Shutting down %s...", settings.APP_NAME)
        # Cancel any active scan tasks
        await cancel_all_tasks()

        # Stop repository purge worker
        if isinstance(repo, InMemoryScanRepository):
            repo.stop_purge_worker()

        # Close shared HTTP client
        await client.aclose()
        set_shared_client(None)
        set_shared_predictor(None)
        logger.info("Shutdown complete.")


def create_app(app_settings: Settings | None = None) -> FastAPI:
    """Creates and configures the FastAPI application instance."""
    cfg = app_settings or settings

    app = FastAPI(
        title=cfg.APP_NAME,
        version=cfg.APP_VERSION,
        description="Asynchronous URL security scanner providing multi-vector risk reports covering phishing, malware, reputation, domain age, and SSL.",
        docs_url="/docs",
        redoc_url=None,
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # -------------------------------------------------------------------------
    # Exception Handlers
    # -------------------------------------------------------------------------
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, custom_rate_limit_exceeded_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(SafeLinksAppError, safelinks_app_error_handler)
    app.add_exception_handler(StarletteHTTPException, starlette_http_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)

    # -------------------------------------------------------------------------
    # Middleware Stack (executed from bottom to top for incoming requests)
    # -------------------------------------------------------------------------
    # 1. Request ID and Security Headers
    app.add_middleware(RequestIdMiddleware)

    # 2. GZip Compression
    app.add_middleware(GZipMiddleware, minimum_size=1000)

    # 3. CORS Configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.cors_origins_list,
        allow_origin_regex=cfg.ALLOWED_ORIGIN_REGEX,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["Content-Type", "X-Request-ID"],
        expose_headers=["X-Request-ID"],
        max_age=600,
        allow_credentials=False,
    )

    # -------------------------------------------------------------------------
    # Routers & Redirects
    # -------------------------------------------------------------------------
    app.include_router(api_v1_router)

    @app.get("/", include_in_schema=False)
    async def root_redirect() -> RedirectResponse:
        """Redirects root path directly to interactive API documentation."""
        return RedirectResponse(url="/docs")

    return app


app = create_app()
