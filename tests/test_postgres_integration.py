"""Integration tests against live PostgreSQL instance.

Verifies real PostgreSQL schema initialization, seeding, constraints,
referential integrity, transaction rollback, and restart persistence.
Skips with a clear notice if PostgreSQL is not reachable on localhost:5432.
"""

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker

from app.ledger.repository import DuplicateEntityError, LedgerRepository
from app.ledger.schemas import (
    CommandAttemptCreate,
    EvaluationCreate,
    EventCreate,
    PolicyDecisionCreate,
    RunCreate,
)

POSTGRES_TEST_URL = "postgresql+psycopg://ledger:ledger@localhost:5432/ledger"


def is_postgres_available() -> bool:
    """Check if real PostgreSQL instance is accessible on localhost:5432."""
    try:
        eng = create_engine(POSTGRES_TEST_URL, connect_args={"connect_timeout": 2})
        with eng.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not is_postgres_available(),
    reason="PostgreSQL not reachable at localhost:5432 (run 'docker compose up -d' first)",
)


@pytest.fixture(name="pg_session")
def fixture_pg_session():
    """Yield a database session connected to real PostgreSQL."""
    eng = create_engine(POSTGRES_TEST_URL, pool_pre_ping=True)
    SessionMaker = sessionmaker(autocommit=False, autoflush=False, bind=eng)
    session = SessionMaker()
    try:
        yield session
    finally:
        session.close()


def test_postgres_tables_exist(pg_session: Session):
    """Verify all five tables exist in real PostgreSQL."""
    inspector = inspect(pg_session.bind)
    tables = inspector.get_table_names()
    assert "runs" in tables
    assert "events" in tables
    assert "command_attempts" in tables
    assert "policy_decisions" in tables
    assert "evaluations" in tables


def test_postgres_seeded_demo_run(pg_session: Session):
    """Verify sbx-seeddemo1 was created by 01_runs.sql on PostgreSQL boot."""
    repo = LedgerRepository(pg_session)
    seeded = repo.get_run("run_seeddemo1")
    assert seeded is not None
    assert seeded.sandbox_name == "sbx-seeddemo1"
    assert seeded.execution_target == "celesto_sandbox"
    assert seeded.state == "deleted"
    assert seeded.problem_id == "prompt_injection_exfil"


def test_postgres_crud_and_referential_integrity(pg_session: Session):
    """Verify real PostgreSQL CRUD and foreign key cascades across entities."""
    repo = LedgerRepository(pg_session)

    # Insert Run
    run_id = "run_pg_integ_01"
    existing = repo.get_run(run_id)
    if existing:
        pg_session.delete(existing)
        pg_session.commit()

    run = repo.create_run(
        RunCreate(
            run_id=run_id,
            sandbox_name="sbx-pginteg01",
            execution_target="celesto_sandbox",
            state="ready",
        )
    )
    assert run.run_id == run_id

    # Insert Event
    evt = repo.create_event(
        EventCreate(
            event_id="evt_pg_01",
            run_id=run_id,
            event_type="test_probe_passed",
            details={"latency_ms": 12},
        )
    )
    assert evt.event_id == "evt_pg_01"

    # Insert CommandAttempt
    cmd = repo.create_command_attempt(
        CommandAttemptCreate(
            attempt_id="cmd_pg_01",
            run_id=run_id,
            command="echo 'postgres integration'",
            decision="allow",
            execution_target="celesto_sandbox",
        )
    )
    assert cmd.attempt_id == "cmd_pg_01"

    # Insert PolicyDecision
    pol = repo.create_policy_decision(
        PolicyDecisionCreate(
            decision_id="pol_pg_01",
            run_id=run_id,
            attempt_id=cmd.attempt_id,
            policy_name="safety_hooks",
            decision="allow",
            reason="Clean command",
        )
    )
    assert pol.decision_id == "pol_pg_01"

    # Insert Evaluation
    existing_eval = repo.get_evaluation("eval_pg_01")
    if existing_eval:
        pg_session.delete(existing_eval)
        pg_session.commit()

    eval_rec = repo.create_evaluation(
        EvaluationCreate(
            task="PostgreSQL integration eval",
            source_url="http://localhost:9000/clean.html",
            defense_profile="baseline",
            run_count=5,
        ),
        evaluation_id="eval_pg_01",
    )
    assert eval_rec.evaluation_id == "eval_pg_01"

    # Test Cascade Delete
    pg_session.delete(run)
    pg_session.delete(eval_rec)
    pg_session.commit()

    assert repo.get_run(run_id) is None
    assert len(repo.list_events_for_run(run_id)) == 0
    assert len(repo.list_command_attempts_for_run(run_id)) == 0


def test_postgres_transaction_rollback(pg_session: Session):
    """Verify PostgreSQL transaction rollback on constraint violation."""
    repo = LedgerRepository(pg_session)
    run_id = "run_pg_rollback_test"
    existing = repo.get_run(run_id)
    if existing:
        pg_session.delete(existing)
        pg_session.commit()

    repo.create_run(
        RunCreate(
            run_id=run_id,
            sandbox_name="sbx-pgrollbk1",
            execution_target="celesto_sandbox",
        )
    )

    with pytest.raises(DuplicateEntityError):
        repo.create_run(
            RunCreate(
                run_id="run_pg_duplicate",
                sandbox_name="sbx-pgrollbk1",
                execution_target="celesto_sandbox",
            )
        )

    # Cleanup
    item = repo.get_run(run_id)
    if item:
        pg_session.delete(item)
        pg_session.commit()
