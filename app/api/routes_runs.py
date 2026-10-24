"""Run ledger management endpoints for GuardRail."""

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.ledger.database import get_db
from app.ledger.repository import DuplicateEntityError, LedgerRepository, RepositoryError
from app.ledger.schemas import RunCreate, RunResponse

router = APIRouter(prefix="/api/runs", tags=["Runs"])


@router.get("", response_model=list[RunResponse])
def list_runs(
    limit: int = Query(default=50, ge=1, le=100, description="Max number of runs to return"),
    offset: int = Query(default=0, ge=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
) -> list[RunResponse]:
    """List persisted runs with bounded pagination, ordered newest first."""
    repo = LedgerRepository(db)
    runs = repo.list_runs(limit=limit, offset=offset)
    return [RunResponse.model_validate(r) for r in runs]


@router.post("", response_model=RunResponse, status_code=status.HTTP_201_CREATED)
def create_run(
    run_in: RunCreate,
    db: Session = Depends(get_db),
) -> RunResponse:
    """Create and persist a new run in the ledger.

    Returns HTTP 201 on success.
    Enforces execution_target must be 'celesto_sandbox'.
    Returns HTTP 400 for bad parameters, and HTTP 409 on duplicate identifier.
    """
    repo = LedgerRepository(db)
    try:
        created = repo.create_run(run_in)
        return RunResponse.model_validate(created)
    except DuplicateEntityError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(exc),
        ) from exc
    except RepositoryError as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(exc),
        ) from exc


@router.get("/{run_id}", response_model=RunResponse)
def get_run(
    run_id: str,
    db: Session = Depends(get_db),
) -> RunResponse:
    """Retrieve details of a single run by run_id."""
    repo = LedgerRepository(db)
    run = repo.get_run(run_id)
    if not run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Run '{run_id}' not found.",
        )
    return RunResponse.model_validate(run)
