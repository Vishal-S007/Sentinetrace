"""Liveness and readiness probes (public, contain no sensitive data)."""

from fastapi import APIRouter, Response, status
from pydantic import BaseModel

from app.core.config import get_settings
from app.db.session import check_database

router = APIRouter(tags=["health"])


class HealthResponse(BaseModel):
    status: str
    version: str


class ReadinessResponse(BaseModel):
    status: str
    database: str


@router.get("/health", response_model=HealthResponse, summary="Liveness probe")
def health() -> HealthResponse:
    """The process is up. Does not touch the database."""
    return HealthResponse(status="ok", version=get_settings().version)


@router.get(
    "/ready",
    response_model=ReadinessResponse,
    summary="Readiness probe",
    responses={503: {"model": ReadinessResponse}},
)
def ready(response: Response) -> ReadinessResponse:
    """The service can handle requests: the database is reachable."""
    if check_database():
        return ReadinessResponse(status="ready", database="ok")
    response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return ReadinessResponse(status="not_ready", database="unavailable")
