"""Health check endpoints for GuardRail control plane."""

from fastapi import APIRouter, status
from fastapi.responses import JSONResponse

from app.ledger.database import check_db_health
from app.ledger.schemas import HealthResponse

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthResponse)
def get_health() -> HealthResponse | JSONResponse:
    """Return health status of the control plane and verify database connectivity.

    Returns HTTP 200 and {"status": "ok"} when healthy.
    Returns HTTP 503 if the database backend is unreachable.
    """
    if not check_db_health():
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "unhealthy", "detail": "Database unavailable"},
        )
    return HealthResponse(status="ok")
