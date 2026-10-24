"""Tests for Phase 8 Concurrency, Lifecycle Faults, and Reliability (Contract 10)."""

import json

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.concurrency.harness import ConcurrencyHarness
from app.concurrency.report import ConcurrencyReportGenerator
from app.concurrency.schemas import ConcurrencyReportSchema
from app.ledger.models import Base
from app.ledger.repository import LedgerRepository
from app.ledger.schemas import RunCreate
from app.sandbox.client import FakeCelestoClient
from app.sandbox.exceptions import (
    GuestCommandExecutionError,
    SandboxCreationError,
    SandboxReadinessTimeoutError,
)
from app.sandbox.manager import SandboxLifecycleManager
from app.sandbox.naming import generate_sandbox_name, validate_sandbox_name


@pytest.fixture
def thread_safe_db_engine(tmp_path):
    """Create a file-backed SQLite database for multithreaded workers."""
    db_file = tmp_path / "concurrent_workers.db"
    engine = create_engine(
        f"sqlite:///{db_file}",
        connect_args={"check_same_thread": False},
        echo=False,
    )
    Base.metadata.create_all(bind=engine)
    return engine


class TestConcurrentSandboxExecution:
    """Verify simultaneous execution of 5+ sandboxes with zero collisions and isolation."""

    def test_simultaneous_executions_and_zero_collisions(self, thread_safe_db_engine, tmp_path):
        """Execute 6 concurrent guest workloads and verify collision avoidance and cleanup."""
        session_factory = sessionmaker(bind=thread_safe_db_engine, autoflush=False)
        rep_gen = ConcurrencyReportGenerator(output_dir=tmp_path)
        harness = ConcurrencyHarness(session_factory=session_factory, report_generator=rep_gen)

        report, jobs = harness.run_concurrent_matrix(concurrency=5, test_id="test_concurrent_eval")

        # 1. Total jobs >= 5
        assert len(jobs) >= 5
        assert report.total_jobs >= 5

        # 2. All run IDs and sandbox names are unique
        run_ids = [j.run_id for j in jobs]
        sandbox_names = [j.sandbox_name for j in jobs]
        assert len(set(run_ids)) == len(jobs)
        assert len(set(sandbox_names)) == len(jobs)
        assert report.identifier_collisions == 0

        # 3. Every sandbox name adheres to regex
        for name in sandbox_names:
            assert validate_sandbox_name(name) is True

        # 4. Mixed success / failure handling
        assert report.successful_jobs >= 1
        assert report.failed_jobs >= 1  # Planned failure job (spec 05) was retained!

        # 5. Guaranteed cleanup on all concurrent paths
        for j in jobs:
            assert j.cleanup_status == "deleted"
            assert j.cleanup_error is None

        # 6. Database ledger consistency
        assert report.ledger_consistency_verified is True

        # 7. Provenance is explicitly local_fake
        assert report.execution_provenance == "local_fake"
        for j in jobs:
            assert j.provenance == "local_fake"


class TestLifecycleAndFailureConditions:
    """Exercise lifecycle failure conditions and verify error preservation and cleanup."""

    def test_guest_creation_failure(self, db_session):
        """Verify SandboxCreationError is raised and no resources leak."""
        repo = LedgerRepository(db_session)
        fake_client = FakeCelestoClient()
        fake_client.fail_on_create = True
        fake_client.create_error_msg = "Simulated VM quota exceeded"
        manager = SandboxLifecycleManager(client=fake_client, ledger_repo=repo)

        run_id = f"run_fail_create_{generate_sandbox_name()}"
        repo.create_run(
            RunCreate(
                run_id=run_id,
                problem_id="test_create_failure",
                defense_profile="baseline",
                execution_target="celesto_sandbox",
            )
        )

        with pytest.raises(SandboxCreationError, match="Simulated VM quota exceeded"):
            manager.create_sandbox(run_id=run_id)

        # Zero computers created in client
        assert len(fake_client.computers) == 0

    def test_readiness_timeout_and_guaranteed_cleanup(self, db_session):
        """Verify readiness timeout triggers teardown in session finally block."""
        repo = LedgerRepository(db_session)
        fake_client = FakeCelestoClient()
        fake_client.fail_on_readiness = True
        manager = SandboxLifecycleManager(client=fake_client, ledger_repo=repo)

        run_id = f"run_readiness_timeout_{generate_sandbox_name()}"
        repo.create_run(
            RunCreate(
                run_id=run_id,
                problem_id="test_readiness_timeout",
                defense_profile="baseline",
                execution_target="celesto_sandbox",
            )
        )

        with pytest.raises(SandboxReadinessTimeoutError):
            with manager.session(run_id=run_id, readiness_timeout=0.05):
                pass  # Should not be reached

        # Computer was created but guaranteed cleanup deleted it
        assert "deleted" in fake_client.terminal_states.values()

    def test_command_execution_error_recorded(self, db_session):
        """Verify command execution error is recorded and raises GuestCommandExecutionError."""
        repo = LedgerRepository(db_session)
        fake_client = FakeCelestoClient()
        fake_client.fail_on_command = True
        manager = SandboxLifecycleManager(client=fake_client, ledger_repo=repo)

        run_id = f"run_cmd_fail_{generate_sandbox_name()}"
        repo.create_run(
            RunCreate(
                run_id=run_id,
                problem_id="test_cmd_fail",
                defense_profile="baseline",
                execution_target="celesto_sandbox",
            )
        )

        handle = manager.create_sandbox(run_id=run_id)
        with pytest.raises(GuestCommandExecutionError):
            manager.execute_command(handle, "cat /invalid/path", run_id=run_id)

        # Cleanup
        manager.cleanup(handle, run_id=run_id)
        assert fake_client.get_computer(handle.provider_id)["status"] == "deleted"

    def test_cleanup_failure_preserves_primary_exception(self, db_session):
        """Verify that when cleanup also fails, the primary exception is not masked."""
        repo = LedgerRepository(db_session)
        fake_client = FakeCelestoClient()
        fake_client.fail_on_delete = True
        manager = SandboxLifecycleManager(client=fake_client, ledger_repo=repo)

        run_id = f"run_cleanup_fail_{generate_sandbox_name()}"
        repo.create_run(
            RunCreate(
                run_id=run_id,
                problem_id="test_cleanup_fail",
                defense_profile="baseline",
                execution_target="celesto_sandbox",
            )
        )

        # In manager.session(), a primary exception occurs, and then cleanup also fails.
        # The primary exception must be preserved, with cleanup failure attached as note!
        with pytest.raises(RuntimeError, match="Primary worker error") as exc_info:
            with manager.session(run_id=run_id):
                raise RuntimeError("Primary worker error")

        # Check that note about cleanup failure was attached
        notes = getattr(exc_info.value, "__notes__", [])
        assert any("Guaranteed cleanup also failed" in n for n in notes)

    def test_idempotent_multiple_cleanup_calls(self, db_session):
        """Verify that calling cleanup multiple times on the same handle is safe and idempotent."""
        repo = LedgerRepository(db_session)
        fake_client = FakeCelestoClient()
        manager = SandboxLifecycleManager(client=fake_client, ledger_repo=repo)

        run_id = f"run_idempotent_cleanup_{generate_sandbox_name()}"
        repo.create_run(
            RunCreate(
                run_id=run_id,
                problem_id="test_idempotent_cleanup",
                defense_profile="baseline",
                execution_target="celesto_sandbox",
            )
        )

        handle = manager.create_sandbox(run_id=run_id)
        # First cleanup
        res1 = manager.cleanup(handle, run_id=run_id)
        assert res1.success is True
        assert res1.verified_absent is True
        assert handle.state == "deleted"

        # Second cleanup on already deleted handle returns immediately
        res2 = manager.cleanup(handle, run_id=run_id)
        assert res2.success is True
        assert res2.verified_absent is True


class TestConcurrencyReportValidation:
    """Validate reports/concurrency.json schema and independent recalculation."""

    def test_concurrency_report_contract10_compliance(self, thread_safe_db_engine, tmp_path):
        """Verify concurrency report conforms to Contract 10 requirements."""
        session_factory = sessionmaker(bind=thread_safe_db_engine, autoflush=False)
        rep_gen = ConcurrencyReportGenerator(output_dir=tmp_path)
        harness = ConcurrencyHarness(session_factory=session_factory, report_generator=rep_gen)

        report, _ = harness.run_concurrent_matrix(concurrency=5)
        report_path = tmp_path / "concurrency.json"
        assert report_path.exists()

        with open(report_path, encoding="utf-8") as f:
            data = json.load(f)

        # 1. Validate schema via Pydantic model
        validated = ConcurrencyReportSchema.model_validate(data)
        assert validated.total_jobs >= 5
        assert len(validated.breakage_notes) >= 40

        # 2. Independent recalculation directly from the jobs list in JSON
        raw_jobs = data["jobs"]
        recalculated_runs = {j["run_id"] for j in raw_jobs}
        recalculated_sbx = {j["sandbox_name"] for j in raw_jobs}

        assert len(recalculated_runs) == len(raw_jobs)
        assert len(recalculated_sbx) == len(raw_jobs)
        assert data["identifier_collisions"] == 0

        recalc_succeeded = sum(1 for j in raw_jobs if j["status"] == "succeeded")
        recalc_failed = sum(1 for j in raw_jobs if j["status"] == "failed")
        assert recalc_succeeded == data["successful_jobs"]
        assert recalc_failed == data["failed_jobs"]

        # 3. All sandboxes have cleanup_status == "deleted"
        for j in raw_jobs:
            assert j["cleanup_status"] == "deleted"
            assert j["provenance"] == "local_fake"
