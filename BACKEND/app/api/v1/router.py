"""Aggregation router for API v1 routes."""

from fastapi import APIRouter

from app.api.v1.routes_health import router as health_router
from app.api.v1.routes_scans import router as scans_router

api_v1_router = APIRouter(prefix="/api/v1")
api_v1_router.include_router(health_router)
api_v1_router.include_router(scans_router)
