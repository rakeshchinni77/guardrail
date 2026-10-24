"""Automated test suite for Phase 6: Ten-Step Workflow & Deterministic Step 7 Recovery."""

import json
import uuid

from app.agent.audit import CommandAuditLogger
from app.ledger.repository import LedgerRepository
from app.ledger.schemas import RunCreate
from app.sandbox.client import FakeCelestoClient
from app.sandbox.manager import SandboxLifecycleManager
from app.workflow import (
    SNAPSHOT_LIMITATION_NOTE,
    SNAPSHOT_PROVIDER_CAPABILITY_STATUS,
    STEP_NAMES,
    VALID_WORKFLOW_TRANSITIONS,
    FailureTraceGenerator,
    RecoveryPolicy,
    TenStepWorkflowEngine,
    WorkflowState,
    WorkflowStepId,
)


class TestTenStepWorkflowExecution:
    """Verify the exact 10-step pipeline and state transitions."""

    def test_exact_ten_step_ordering_and_completion(self, db_session):
        repo = LedgerRepository(db_session)
        audit = CommandAuditLogger(ledger_repo=repo)
        engine = TenStepWorkflowEngine(ledger_repo=repo, audit_logger=audit)

        run_id = f"run_10step_{uuid.uuid4().hex[:6]}"
        repo.create_run(
            RunCreate(
                run_id=run_id,
                problem_id="clean_research",
                defense_profile="defense_in_depth",
                execution_target="celesto_sandbox",
            )
        )

        summary = engine.execute_workflow(
            run_id=run_id,
            source_id="clean-01",
            inject_step7_failure=False,
        )

        assert summary.success is True
        assert summary.final_state == WorkflowState.SUCCEEDED
        assert summary.completed_steps == [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        assert len(summary.step_records) == 10

        # Verify exact step identifiers and ordering
        for idx, rec in enumerate(summary.step_records, start=1):
            assert rec.step == idx
            assert rec.step_name == STEP_NAMES[WorkflowStepId(idx)]
            assert rec.status == "completed"

        # Verify PostgreSQL database state
        db_run = repo.get_run(run_id)
        assert db_run is not None
        assert db_run.state == "succeeded"
        assert db_run.success is True
        assert db_run.run_metadata["total_steps"] == 10
        assert db_run.run_metadata["completed_steps"] == [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

    def test_valid_and_invalid_state_transitions(self):
        init_transitions = VALID_WORKFLOW_TRANSITIONS[WorkflowState.INITIALIZED]
        assert WorkflowState.SOURCE_SELECTED in init_transitions

        draft_transitions = VALID_WORKFLOW_TRANSITIONS[WorkflowState.DRAFT_SYNTHESIZED]
        assert WorkflowState.MID_TASK_FAILURE in draft_transitions

        mid_fail_transitions = VALID_WORKFLOW_TRANSITIONS[WorkflowState.MID_TASK_FAILURE]
        assert WorkflowState.RESUMED in mid_fail_transitions

        assert WorkflowState.SUCCEEDED not in VALID_WORKFLOW_TRANSITIONS[WorkflowState.CREATED]
        assert WorkflowState.SUCCEEDED not in mid_fail_transitions


class TestStep7FailureInjection:
    """Verify deterministic, synthetic fault injection strictly at Step 7 of 10."""

    def test_deterministic_step7_failure_without_recovery(self, db_session):
        repo = LedgerRepository(db_session)
        audit = CommandAuditLogger(ledger_repo=repo)
        engine = TenStepWorkflowEngine(ledger_repo=repo, audit_logger=audit)

        run_id = f"run_step7_fail_{uuid.uuid4().hex[:6]}"
        repo.create_run(
            RunCreate(
                run_id=run_id,
                problem_id="step7_fault_test",
                defense_profile="baseline",
                execution_target="celesto_sandbox",
            )
        )

        summary = engine.execute_workflow(
            run_id=run_id,
            source_id="clean-01",
            inject_step7_failure=True,
            recovery_policy=None,  # No recovery policy -> must fail
        )

        assert summary.success is False
        assert summary.final_state == WorkflowState.MID_TASK_FAILURE
        assert summary.injected_failure is True
        assert summary.failed_step == 7
        assert "SyntheticStep7Fault" in (summary.error_message or "")

        # Verify steps 1-6 completed
        assert summary.completed_steps == [1, 2, 3, 4, 5, 6]

        # GUARANTEE: Steps 8, 9, 10 did NOT execute!
        assert 7 not in summary.completed_steps
        assert 8 not in summary.completed_steps
        assert 9 not in summary.completed_steps
        assert 10 not in summary.completed_steps

        # Verify step 7 failure is persisted in PostgreSQL
        events = repo.list_events_for_run(run_id)
        step7_fail_events = [e for e in events if e.event_type == "workflow.step_7.failed"]
        assert len(step7_fail_events) >= 1
        assert step7_fail_events[0].details["is_synthetic"] is True
        assert step7_fail_events[0].details["failed_step"] == 7


class TestRecoveryPolicies:
    """Verify resume, rollback, and fresh recovery policies."""

    def test_resume_policy_completes_without_repeating_steps_1_to_6(self, db_session):
        repo = LedgerRepository(db_session)
        audit = CommandAuditLogger(ledger_repo=repo)
        engine = TenStepWorkflowEngine(ledger_repo=repo, audit_logger=audit)

        run_id = f"run_resume_{uuid.uuid4().hex[:6]}"
        repo.create_run(
            RunCreate(
                run_id=run_id,
                problem_id="step7_resume_test",
                defense_profile="baseline",
                execution_target="celesto_sandbox",
            )
        )

        summary = engine.execute_workflow(
            run_id=run_id,
            source_id="clean-01",
            inject_step7_failure=True,
            recovery_policy=RecoveryPolicy.RESUME,
        )

        assert summary.success is True
        assert summary.final_state == WorkflowState.SUCCEEDED
        assert summary.injected_failure is True
        assert summary.failed_step == 7
        assert summary.recovery_policy_applied == "resume"
        assert summary.recovery_succeeded is True

        # All 10 steps eventually completed
        assert summary.completed_steps == [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

        # Verify steps 1-6 were executed only once (no duplicate execution records)
        completed_records = [r for r in summary.step_records if r.status == "completed"]
        completed_step_nums = [r.step for r in completed_records]
        for step_num in range(1, 7):
            assert completed_step_nums.count(step_num) == 1, f"Step {step_num} was repeated!"

        # Verify policy_applied event in PostgreSQL
        events = repo.list_events_for_run(run_id)
        pol_evts = [e for e in events if e.event_type == "policy_applied"]
        assert len(pol_evts) >= 1
        assert pol_evts[0].details["policy"] == "resume"
        assert len(pol_evts[0].details["rationale"]) >= 200

    def test_rollback_policy_and_explicit_snapshot_limitation(self, db_session):
        repo = LedgerRepository(db_session)
        audit = CommandAuditLogger(ledger_repo=repo)
        engine = TenStepWorkflowEngine(ledger_repo=repo, audit_logger=audit)

        run_id = f"run_rollback_{uuid.uuid4().hex[:6]}"
        repo.create_run(
            RunCreate(
                run_id=run_id,
                problem_id="step7_rollback_test",
                defense_profile="baseline",
                execution_target="celesto_sandbox",
            )
        )

        summary = engine.execute_workflow(
            run_id=run_id,
            source_id="clean-01",
            inject_step7_failure=True,
            recovery_policy=RecoveryPolicy.ROLLBACK,
        )

        assert summary.success is True
        assert summary.recovery_policy_applied == "rollback"
        assert summary.recovery_succeeded is True

        # Verify honest declaration of UNVERIFIED provider snapshot capability
        events = repo.list_events_for_run(run_id)
        rb_evts = [e for e in events if e.event_type == "workflow.rollback_check"]
        assert len(rb_evts) >= 1
        assert rb_evts[0].details["provider_snapshot_status"] == SNAPSHOT_PROVIDER_CAPABILITY_STATUS
        assert rb_evts[0].details["note"] == SNAPSHOT_LIMITATION_NOTE
        assert rb_evts[0].details["method"] == "simulated_checkpoint_rollback"

    def test_fresh_recovery_policy_with_fake_client(self, db_session):
        repo = LedgerRepository(db_session)
        fake_client = FakeCelestoClient()
        fake_client.is_fake = True
        sandbox_mgr = SandboxLifecycleManager(client=fake_client, ledger_repo=repo)
        audit = CommandAuditLogger(ledger_repo=repo)
        engine = TenStepWorkflowEngine(
            ledger_repo=repo,
            audit_logger=audit,
            sandbox_manager=sandbox_mgr,
        )

        run_id = f"run_fresh_{uuid.uuid4().hex[:6]}"
        repo.create_run(
            RunCreate(
                run_id=run_id,
                problem_id="step7_fresh_test",
                defense_profile="baseline",
                execution_target="celesto_sandbox",
            )
        )

        h1 = sandbox_mgr.create_sandbox(run_id=run_id)
        assert h1.provider_id in fake_client.computers

        summary = engine.execute_workflow(
            run_id=run_id,
            source_id="clean-01",
            sandbox_handle=h1,
            inject_step7_failure=True,
            recovery_policy=RecoveryPolicy.FRESH,
        )

        assert summary.success is True
        assert summary.recovery_policy_applied == "fresh"
        assert summary.recovery_succeeded is True

        # Old sandbox was cleaned up and deleted
        comp1 = fake_client.get_computer(h1.provider_id)
        assert comp1.get("status") == "deleted"

    def test_retry_cap_enforcement(self, db_session):
        repo = LedgerRepository(db_session)
        audit = CommandAuditLogger(ledger_repo=repo)
        engine = TenStepWorkflowEngine(ledger_repo=repo, audit_logger=audit)

        run_id = f"run_retry_cap_{uuid.uuid4().hex[:6]}"
        repo.create_run(
            RunCreate(
                run_id=run_id,
                problem_id="step7_retry_test",
                defense_profile="baseline",
                execution_target="celesto_sandbox",
            )
        )

        # max_retries = 0 -> cannot recover
        summary = engine.execute_workflow(
            run_id=run_id,
            source_id="clean-01",
            inject_step7_failure=True,
            recovery_policy=RecoveryPolicy.RESUME,
            max_retries=0,
        )

        assert summary.success is False
        assert "Exceeded max recovery retries" in (summary.error_message or "")


class TestCleanupOnFailurePaths:
    """Verify guaranteed cleanup and terminal status on all workflow failure paths."""

    def test_cleanup_verified_on_step7_failure(self, db_session):
        repo = LedgerRepository(db_session)
        fake_client = FakeCelestoClient()
        fake_client.is_fake = True
        sandbox_mgr = SandboxLifecycleManager(client=fake_client, ledger_repo=repo)
        audit = CommandAuditLogger(ledger_repo=repo)
        engine = TenStepWorkflowEngine(
            ledger_repo=repo,
            audit_logger=audit,
            sandbox_manager=sandbox_mgr,
        )

        run_id = f"run_fail_clean_{uuid.uuid4().hex[:6]}"
        repo.create_run(
            RunCreate(
                run_id=run_id,
                problem_id="fail_cleanup_test",
                defense_profile="baseline",
                execution_target="celesto_sandbox",
            )
        )

        handle = sandbox_mgr.create_sandbox(run_id=run_id)

        summary = engine.execute_workflow(
            run_id=run_id,
            source_id="clean-01",
            sandbox_handle=handle,
            inject_step7_failure=True,
            recovery_policy=None,
        )

        assert summary.success is False

        # Guaranteed cleanup ran in finally block!
        info = fake_client.get_computer(handle.provider_id)
        assert info.get("status") == "deleted"


class TestFailureTraceAndContract9:
    """Verify generation of reports/failure_trace.jsonl and reports/failure_policy.json."""

    def test_failure_trace_and_policy_json_generation(self, tmp_path, db_session):
        repo = LedgerRepository(db_session)
        audit = CommandAuditLogger(ledger_repo=repo)
        engine = TenStepWorkflowEngine(ledger_repo=repo, audit_logger=audit)

        run_id = f"run_contract9_{uuid.uuid4().hex[:6]}"
        repo.create_run(
            RunCreate(
                run_id=run_id,
                problem_id="contract9_eval",
                defense_profile="baseline",
                execution_target="celesto_sandbox",
            )
        )

        summary = engine.execute_workflow(
            run_id=run_id,
            source_id="clean-01",
            inject_step7_failure=True,
            recovery_policy=RecoveryPolicy.RESUME,
        )

        generator = FailureTraceGenerator(output_dir=tmp_path, ledger_repo=repo)
        paths = generator.generate_trace_artifacts(summary=summary, policy=RecoveryPolicy.RESUME)

        # 1. Verify failure_policy.json (Graded Contract 9)
        assert paths["failure_policy"].exists()
        with open(paths["failure_policy"], encoding="utf-8") as f:
            policy_json = json.load(f)

        assert policy_json["failed_step"] == 7
        assert policy_json["total_steps"] == 10
        assert policy_json["policy"] == "resume"
        assert len(policy_json["rationale"]) >= 200

        # 2. Verify failure_trace.jsonl (Chronological JSONL)
        assert paths["failure_trace"].exists()
        with open(paths["failure_trace"], encoding="utf-8") as f:
            lines = [json.loads(line) for line in f if line.strip()]

        assert len(lines) >= 10
        pol_lines = [entry for entry in lines if entry.get("event_type") == "policy_applied"]
        assert len(pol_lines) >= 1
        assert pol_lines[0]["details"]["policy"] == "resume"
        assert pol_lines[0]["details"]["failed_step"] == 7
