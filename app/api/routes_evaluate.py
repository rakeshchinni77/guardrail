"""Evaluation endpoints for GuardRail (Phase 7 Evaluation Runner & Metrics)."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.evaluation.runner import EvaluationHarness
from app.ledger.database import get_db
from app.ledger.repository import LedgerRepository
from app.ledger.schemas import EvaluationCreate, EvaluationResponse

router = APIRouter(prefix="/api/evaluate", tags=["Evaluation"])


@router.post("", status_code=status.HTTP_200_OK)
def start_evaluation(
    eval_in: EvaluationCreate,
    execute: bool = Query(
        False, description="If True, executes the 20-run evaluation matrix synchronously."
    ),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Submit an evaluation request across defense configurations.

    If `execute=True`, executes the 20-run evaluation matrix across defense configurations.
    Otherwise, queues the evaluation request in the ledger with status 'queued'.
    """
    repo = LedgerRepository(db)
    if execute:
        import uuid

        eval_id = f"eval_{uuid.uuid4().hex[:12]}"
        harness = EvaluationHarness(ledger_repo=repo)
        records, metrics, _ = harness.run_evaluation_matrix(
            evaluation_id=eval_id,
            batch_task_prompt=eval_in.task,
        )
        return {
            "evaluation_id": eval_id,
            "runs": len(records),
            "status": "completed",
            "success_rate": metrics.success_rate,
            "containment_rate": metrics.containment_rate,
        }

    record = repo.create_evaluation(eval_in)
    return {
        "evaluation_id": record.evaluation_id,
        "runs": record.run_count,
        "status": record.status,
    }


@router.get("/{evaluation_id}", response_model=EvaluationResponse)
def get_evaluation_status(
    evaluation_id: str,
    db: Session = Depends(get_db),
) -> EvaluationResponse:
    """Retrieve evaluation details and benchmark results by evaluation_id."""
    repo = LedgerRepository(db)
    record = repo.get_evaluation(evaluation_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evaluation '{evaluation_id}' not found.",
        )
    return EvaluationResponse.model_validate(record)
