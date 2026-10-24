"""FastAPI application entrypoint for GuardRail control plane."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.api.routes_evaluate import router as evaluate_router
from app.api.routes_health import router as health_router
from app.api.routes_runs import router as runs_router
from app.config import get_settings
from app.ledger.database import SessionLocal, init_db
from app.ledger.models import Run


def seed_demo_data() -> None:
    """Ensure the idempotent demo seed record exists."""
    db = SessionLocal()
    try:
        existing = db.query(Run).filter(Run.sandbox_name == "sbx-seeddemo1").first()
        if not existing:
            demo_run = Run(
                run_id="run_seeddemo1",
                sandbox_name="sbx-seeddemo1",
                problem_id="prompt_injection_exfil",
                defense_profile="baseline",
                state="deleted",
                execution_target="celesto_sandbox",
                success=True,
                wall_clock_s=18.5,
                boot_to_ready_s=0.52,
                cost_usd=0.015,
                attack_success=False,
                run_metadata={
                    "seeded": True,
                    "note": "Illustrative infrastructure demo data, not real Celesto execution",
                },
            )
            db.add(demo_run)
            db.commit()
    except Exception:
        db.rollback()
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Lifespan manager: initialize tables and ensure demo data on startup."""
    try:
        init_db()
        seed_demo_data()
    except Exception:
        # If database is not yet ready, routes_health will report 503
        pass
    yield


app = FastAPI(
    title="GuardRail Control Plane",
    description="Control plane and run ledger for AI agent security evaluations.",
    version="0.1.0",
    lifespan=lifespan,
)


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Return HTTP 400 Bad Request for validation errors.

    The hackathon specification requires that invalid execution_target,
    bad sandbox_name, or unsupported states receive HTTP 400.
    """
    error_details = []
    for err in exc.errors():
        field_path = " -> ".join(str(loc) for loc in err.get("loc", []))
        error_details.append(f"{field_path}: {err.get('msg', 'validation error')}")
    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={"detail": "; ".join(error_details)},
    )


# Register API routes
app.include_router(health_router)
app.include_router(runs_router)
app.include_router(evaluate_router)


if __name__ == "__main__":
    import uvicorn

    settings = get_settings()
    uvicorn.run("app.main:app", host="0.0.0.0", port=settings.api_port, reload=False)
