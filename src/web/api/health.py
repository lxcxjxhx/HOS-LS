"""Health check API."""

from fastapi import APIRouter

from src.web.models import HealthResponse, HealthStatus

router = APIRouter(prefix="/health", tags=["health"])


@router.get("", response_model=HealthResponse)
async def get_health() -> HealthResponse:
    """健康检查接口"""
    import src
    return HealthResponse(
        status=HealthStatus.healthy,
        version=src.__version__,
        components={
            "api": "ok",
            "database": "ok",
            "ai": "available",
        },
    )
