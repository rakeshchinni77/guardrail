import pytest
from sqlalchemy.orm import Session

from app.ledger.models import CommandAttempt, Event, PolicyDecision
from app.ledger.repository import DuplicateEntityError, LedgerRepository
from app.ledger.schemas import (
    CommandAttemptCreate,
    EvaluationCreate,
    EventCreate,
    PolicyDecisionCreate,
    RunCreate,
)


def test_all_five_models_instantiation_and_persistence(db_session: Session):
    """Verify Run, Event, CommandAttempt, PolicyDecision, Evaluation persist cleanly."""
    repo = LedgerRepository(db_session)

    # 1. Run
    run_in = RunCreate(
        run_id="run_five_models_01",
        sandbox_name="sbx-fivemodel01",
        problem_id="prompt_injection_exfil",
        defense_profile="defense_in_depth",
        state="running",
        execution_target="celesto_sandbox",
    )
    run = repo.create_run(run_in)
    assert run.run_id == "run_five_models_01"

    # 2. Event
    event_in = EventCreate(
        event_id="evt_01",
        run_id=run.run_id,
        event_type="sandbox_booted",
        details={"boot_s": 0.45},
    )
    event = repo.create_event(event_in)
    assert event.event_id == "evt_01"
    assert event.run_id == run.run_id

    # 3. CommandAttempt
    cmd_in = CommandAttemptCreate(
        attempt_id="cmd_01",
        run_id=run.run_id,
        command="curl http://malicious.exfil.test",
        decision="block",
        reason="Blocked by safety hook",
        risk_level="critical",
        execution_target="celesto_sandbox",
        canary_detected=True,
    )
    cmd = repo.create_command_attempt(cmd_in)
    assert cmd.attempt_id == "cmd_01"
    assert cmd.canary_detected is True

    # 4. PolicyDecision
    policy_in = PolicyDecisionCreate(
        decision_id="pol_01",
        run_id=run.run_id,
        attempt_id=cmd.attempt_id,
        policy_name="safety_hooks",
        decision="block",
        risk_level="critical",
        reason="Pre-command regex matched exfiltration pattern",
    )
    policy = repo.create_policy_decision(policy_in)
    assert policy.decision_id == "pol_01"
    assert policy.attempt_id == cmd.attempt_id

    # 5. Evaluation
    eval_in = EvaluationCreate(
        task="Summarize page and test injection containment",
        source_url="http://localhost:9000/pages/pi-01-direct.html",
        defense_profile="defense_in_depth",
        run_count=20,
    )
    evaluation = repo.create_evaluation(eval_in, evaluation_id="eval_test_five_01")
    assert evaluation.evaluation_id == "eval_test_five_01"
    assert evaluation.status == "queued"

    # Verify relationship traversal
    db_session.refresh(run)
    assert len(run.events) == 1
    assert run.events[0].event_type == "sandbox_booted"
    assert len(run.command_attempts) == 1
    assert run.command_attempts[0].decision == "block"
    assert len(run.policy_decisions) == 1
    assert run.policy_decisions[0].policy_name == "safety_hooks"


def test_cascade_delete_integrity(db_session: Session):
    """Verify deleting a run cascades cleanly to events, commands, and policy decisions."""
    repo = LedgerRepository(db_session)
    run = repo.create_run(
        RunCreate(
            run_id="run_cascade_test_01",
            sandbox_name="sbx-cascadetest1",
            execution_target="celesto_sandbox",
        )
    )
    repo.create_event(EventCreate(event_id="evt_casc_1", run_id=run.run_id, event_type="start"))
    cmd = repo.create_command_attempt(
        CommandAttemptCreate(
            attempt_id="cmd_casc_1",
            run_id=run.run_id,
            command="ls -la",
            decision="allow",
            execution_target="celesto_sandbox",
        )
    )
    repo.create_policy_decision(
        PolicyDecisionCreate(
            decision_id="pol_casc_1",
            run_id=run.run_id,
            attempt_id=cmd.attempt_id,
            policy_name="safety_hooks",
            decision="allow",
        )
    )

    # Delete run and verify children are deleted
    db_session.delete(run)
    db_session.commit()

    assert db_session.query(Event).filter(Event.run_id == "run_cascade_test_01").count() == 0
    assert (
        db_session.query(CommandAttempt)
        .filter(CommandAttempt.run_id == "run_cascade_test_01")
        .count()
        == 0
    )
    assert (
        db_session.query(PolicyDecision)
        .filter(PolicyDecision.run_id == "run_cascade_test_01")
        .count()
        == 0
    )


def test_transaction_rollback_on_error(db_session: Session):
    """Verify database transaction rolls back on integrity error without leaking state."""
    repo = LedgerRepository(db_session)
    repo.create_run(
        RunCreate(
            run_id="run_unique_first",
            sandbox_name="sbx-uniquename1",
            execution_target="celesto_sandbox",
        )
    )

    # Attempt inserting duplicate sandbox_name
    with pytest.raises(DuplicateEntityError):
        repo.create_run(
            RunCreate(
                run_id="run_unique_second",
                sandbox_name="sbx-uniquename1",
                execution_target="celesto_sandbox",
            )
        )

    # Database session must remain usable after rollback
    run_lookup = repo.get_run("run_unique_first")
    assert run_lookup is not None
    assert run_lookup.sandbox_name == "sbx-uniquename1"
