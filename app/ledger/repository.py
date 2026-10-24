"""Repository layer for persisting and retrieving GuardRail ledger entities."""

import uuid

from sqlalchemy import desc, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.ledger.models import CommandAttempt, Evaluation, Event, PolicyDecision, Run
from app.ledger.schemas import (
    CommandAttemptCreate,
    EvaluationCreate,
    EventCreate,
    PolicyDecisionCreate,
    RunCreate,
)


class DuplicateEntityError(Exception):
    """Raised when an entity with duplicate unique constraint is inserted."""

    pass


class RepositoryError(Exception):
    """Generic repository exception wrapping database errors."""

    pass


class LedgerRepository:
    """Data access repository for GuardRail ledger models."""

    def __init__(self, db: Session):
        self.db = db

    # -------------------------------------------------------------------------
    # Run operations
    # -------------------------------------------------------------------------
    def create_run(self, run_in: RunCreate) -> Run:
        """Create and persist a new Run record."""
        # Pre-check for duplicate identifiers to avoid session identity conflicts
        if self.get_run(run_in.run_id):
            raise DuplicateEntityError(f"Run '{run_in.run_id}' already exists.")
        if run_in.sandbox_name:
            stmt = select(Run).where(Run.sandbox_name == run_in.sandbox_name)
            if self.db.scalars(stmt).first():
                raise DuplicateEntityError(f"Sandbox '{run_in.sandbox_name}' already exists.")

        run = Run(
            run_id=run_in.run_id,
            sandbox_name=run_in.sandbox_name,
            problem_id=run_in.problem_id,
            defense_profile=run_in.defense_profile,
            state=run_in.state,
            execution_target=run_in.execution_target,
            started_at=run_in.started_at,
            finished_at=run_in.finished_at,
            success=run_in.success,
            wall_clock_s=run_in.wall_clock_s,
            boot_to_ready_s=run_in.boot_to_ready_s,
            cost_usd=run_in.cost_usd,
            attack_success=run_in.attack_success,
            evidence_path=run_in.evidence_path,
            run_metadata=run_in.run_metadata,
        )
        self.db.add(run)
        try:
            self.db.commit()
            self.db.refresh(run)
            return run
        except IntegrityError as exc:
            self.db.rollback()
            raise DuplicateEntityError(
                f"Run '{run_in.run_id}' or sandbox '{run_in.sandbox_name}' already exists."
            ) from exc
        except Exception as exc:
            self.db.rollback()
            raise RepositoryError("Failed to persist run record.") from exc

    def get_run(self, run_id: str) -> Run | None:
        """Retrieve a Run record by its run_id."""
        stmt = select(Run).where(Run.run_id == run_id)
        return self.db.scalars(stmt).first()

    def list_runs(self, limit: int = 50, offset: int = 0) -> list[Run]:
        """List runs with pagination, ordered by creation time descending."""
        bounded_limit = min(max(1, limit), 100)
        bounded_offset = max(0, offset)
        stmt = (
            select(Run).order_by(desc(Run.created_at)).offset(bounded_offset).limit(bounded_limit)
        )
        return list(self.db.scalars(stmt).all())

    def update_run(self, run_id: str, **kwargs) -> Run:
        """Update mutable fields on an existing Run record."""
        run = self.get_run(run_id)
        if not run:
            raise RepositoryError(f"Run '{run_id}' does not exist.")
        for key, value in kwargs.items():
            if hasattr(run, key):
                setattr(run, key, value)
        try:
            self.db.commit()
            self.db.refresh(run)
            return run
        except Exception as exc:
            self.db.rollback()
            raise RepositoryError(f"Failed to update run '{run_id}'.") from exc

    # -------------------------------------------------------------------------
    # Event operations
    # -------------------------------------------------------------------------
    def create_event(self, event_in: EventCreate) -> Event:
        """Create and persist a new lifecycle or audit event."""
        # Check foreign key target exists
        if not self.get_run(event_in.run_id):
            raise RepositoryError(f"Run '{event_in.run_id}' does not exist.")

        event = Event(
            event_id=event_in.event_id,
            run_id=event_in.run_id,
            event_type=event_in.event_type,
            details=event_in.details,
        )
        if event_in.timestamp:
            event.timestamp = event_in.timestamp

        self.db.add(event)
        try:
            self.db.commit()
            self.db.refresh(event)
            return event
        except IntegrityError as exc:
            self.db.rollback()
            raise DuplicateEntityError(f"Event '{event_in.event_id}' already exists.") from exc
        except Exception as exc:
            self.db.rollback()
            raise RepositoryError("Failed to persist event record.") from exc

    def list_events_for_run(self, run_id: str) -> list[Event]:
        """List all events for a given run ordered by timestamp."""
        stmt = select(Event).where(Event.run_id == run_id).order_by(Event.timestamp)
        return list(self.db.scalars(stmt).all())

    # -------------------------------------------------------------------------
    # CommandAttempt operations
    # -------------------------------------------------------------------------
    def create_command_attempt(self, attempt_in: CommandAttemptCreate) -> CommandAttempt:
        """Create and persist a command attempt record."""
        if not self.get_run(attempt_in.run_id):
            raise RepositoryError(f"Run '{attempt_in.run_id}' does not exist.")

        attempt = CommandAttempt(
            attempt_id=attempt_in.attempt_id,
            run_id=attempt_in.run_id,
            command=attempt_in.command,
            decision=attempt_in.decision,
            reason=attempt_in.reason,
            risk_level=attempt_in.risk_level,
            execution_target=attempt_in.execution_target,
            canary_detected=attempt_in.canary_detected,
        )
        if attempt_in.timestamp:
            attempt.timestamp = attempt_in.timestamp

        self.db.add(attempt)
        try:
            self.db.commit()
            self.db.refresh(attempt)
            return attempt
        except IntegrityError as exc:
            self.db.rollback()
            raise DuplicateEntityError(
                f"Command attempt '{attempt_in.attempt_id}' already exists."
            ) from exc
        except Exception as exc:
            self.db.rollback()
            raise RepositoryError("Failed to persist command attempt record.") from exc

    def list_command_attempts_for_run(self, run_id: str) -> list[CommandAttempt]:
        """List all command attempts for a given run ordered by timestamp."""
        stmt = (
            select(CommandAttempt)
            .where(CommandAttempt.run_id == run_id)
            .order_by(CommandAttempt.timestamp)
        )
        return list(self.db.scalars(stmt).all())

    # -------------------------------------------------------------------------
    # PolicyDecision operations
    # -------------------------------------------------------------------------
    def create_policy_decision(self, decision_in: PolicyDecisionCreate) -> PolicyDecision:
        """Create and persist a policy evaluation decision."""
        if not self.get_run(decision_in.run_id):
            raise RepositoryError(f"Run '{decision_in.run_id}' does not exist.")

        decision = PolicyDecision(
            decision_id=decision_in.decision_id,
            run_id=decision_in.run_id,
            attempt_id=decision_in.attempt_id,
            policy_name=decision_in.policy_name,
            decision=decision_in.decision,
            risk_level=decision_in.risk_level,
            reason=decision_in.reason,
            decision_metadata=decision_in.decision_metadata,
        )
        if decision_in.timestamp:
            decision.timestamp = decision_in.timestamp

        self.db.add(decision)
        try:
            self.db.commit()
            self.db.refresh(decision)
            return decision
        except IntegrityError as exc:
            self.db.rollback()
            raise DuplicateEntityError(
                f"Policy decision '{decision_in.decision_id}' already exists."
            ) from exc
        except Exception as exc:
            self.db.rollback()
            raise RepositoryError("Failed to persist policy decision record.") from exc

    def list_policy_decisions_for_run(self, run_id: str) -> list[PolicyDecision]:
        """List all policy evaluation decisions for a specific run."""
        stmt = (
            select(PolicyDecision)
            .where(PolicyDecision.run_id == run_id)
            .order_by(PolicyDecision.timestamp.asc())
        )
        return list(self.db.scalars(stmt).all())

    # -------------------------------------------------------------------------
    # Evaluation operations
    # -------------------------------------------------------------------------
    def create_evaluation(
        self, eval_in: EvaluationCreate, evaluation_id: str | None = None
    ) -> Evaluation:
        """Create and persist an Evaluation batch request."""
        eval_id = evaluation_id or f"eval_{uuid.uuid4().hex[:12]}"
        eval_record = Evaluation(
            evaluation_id=eval_id,
            task=eval_in.task,
            source_url=eval_in.source_url,
            defense_profile=eval_in.defense_profile,
            run_count=eval_in.run_count,
            status="queued",
            result_metadata={
                "phase": "phase_2_stub",
                "message": "Evaluation queued. Real sandbox runner will be linked in Phase 7.",
            },
        )
        self.db.add(eval_record)
        try:
            self.db.commit()
            self.db.refresh(eval_record)
            return eval_record
        except IntegrityError as exc:
            self.db.rollback()
            raise DuplicateEntityError(f"Evaluation '{eval_id}' already exists.") from exc
        except Exception as exc:
            self.db.rollback()
            raise RepositoryError("Failed to persist evaluation record.") from exc

    def get_evaluation(self, evaluation_id: str) -> Evaluation | None:
        """Retrieve an evaluation record by ID."""
        stmt = select(Evaluation).where(Evaluation.evaluation_id == evaluation_id)
        return self.db.scalars(stmt).first()
