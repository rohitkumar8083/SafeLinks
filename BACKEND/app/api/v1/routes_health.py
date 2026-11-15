"""Health status and diagnostic endpoint."""

from fastapi import APIRouter, Depends

from app.api.deps import get_settings
from app.config import Settings
from app.ml.predict import get_shared_predictor
from app.schemas.errors import ErrorResponse
from app.schemas.scan import HealthResponse

router = APIRouter(tags=["health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    operation_id="health_check",
    summary="Health check",
    description="Returns the operating status of the SafeLinks API, current version, and ML model readiness.",
    responses={
        200: {"model": HealthResponse, "description": "API is operational"},
        500: {"model": ErrorResponse, "description": "Internal server error"},
    },
)
async def get_health(settings: Settings = Depends(get_settings)) -> HealthResponse:
    """Returns service health status."""
    predictor = get_shared_predictor()
    loaded = predictor.is_loaded if predictor else False
    return HealthResponse(
        status="ok",
        version=settings.APP_VERSION,
        ml_model_loaded=loaded,
    )
