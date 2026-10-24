"""Unit tests for Phase 3 Celesto sandbox lifecycle integration and microVM adapter.

Runs entirely in-memory using FakeCelestoClient with zero cloud credits consumed.
"""

import pytest

from app.ledger.repository import LedgerRepository
from app.ledger.schemas import RunCreate
from app.sandbox import (
    FakeCelestoClient,
    GuestCommandExecutionError,
    GuestCommandTimeoutError,
    HostExecutionForbiddenError,
    SandboxCleanupError,
    SandboxCreationError,
    SandboxLifecycleManager,
    SandboxReadinessTimeoutError,
    generate_sandbox_name,
    validate_sandbox_name,
)
from app.sandbox.client import sanitize_text


class TestSandboxNaming:
    """Test sandbox name generation, validation, and collision resistance."""

    def test_sandbox_name_format_and_contract(self):
        """Confirm generated names strictly match `^sbx-[a-z0-9]{8,}$`."""
        name = generate_sandbox_name()
        assert name.startswith("sbx-")
        assert len(name) >= 12  # 'sbx-' + 10 hex chars
        assert validate_sandbox_name(name) is True

    def test_sandbox_name_uniqueness_across_concurrency(self):
        """Verify that 200 sequentially generated names are 100% unique."""
        generated = {generate_sandbox_name() for _ in range(200)}
        assert len(generated) == 200

    @pytest.mark.parametrize(
        ("invalid_name", "expected_valid"),
        [
            ("sbx", False),
            ("sbx-123", False),  # Less than 8 characters
            ("sandbox-12345678", False),  # Wrong prefix
            ("sbx-ABCDEFGH", False),  # Uppercase not allowed
            ("sbx-abc_12345", False),  # Underscore not allowed
            ("sbx-12345678", True),  # Exactly 8 lowercase alphanumeric
            ("sbx-abcdef0123456789", True),  # Valid 16 chars
        ],
    )
    def test_validate_sandbox_name(self, invalid_name, expected_valid):
        """Verify regex boundary validation for sandbox names."""
        assert validate_sandbox_name(invalid_name) is expected_valid


class TestSandboxLifecycle:
    """Test state machine transitions and execution behavior."""

    @pytest.fixture
    def fake_client(self):
        """Provide in-memory fake Celesto client."""
        client = FakeCelestoClient()
        client.is_fake = True
        return client

    @pytest.fixture
    def manager(self, fake_client):
        """Provide lifecycle manager backed by fake client."""
        return SandboxLifecycleManager(client=fake_client)

    def test_create_sandbox_success(self, manager, fake_client):
        """Verify sandbox creation returns handle in 'created' state."""
        handle = manager.create_sandbox()
        assert handle.state == "created"
        assert handle.provider_id.startswith("cmp_fake_")
        assert handle.sandbox_name.startswith("sbx-")
        assert handle.provider == "cloud"
        assert handle.provider_id in fake_client.computers

    def test_create_sandbox_failure(self, manager, fake_client):
        """Verify SandboxCreationError is raised when client fails."""
        fake_client.fail_on_create = True
        with pytest.raises(SandboxCreationError) as exc_info:
            manager.create_sandbox()
        assert "Simulated cloud allocation capacity exceeded" in str(exc_info.value)

    def test_readiness_probe_success(self, manager, fake_client):
        """Verify readiness probe polls guest and transitions to 'ready'."""
        handle = manager.create_sandbox()
        result = manager.wait_until_ready(handle, timeout=10.0, poll_interval=0.01)

        assert result.ready is True
        assert result.boot_to_ready_s >= 0.0
        assert result.attempts >= 1
        assert handle.state == "ready"
        assert handle.boot_to_ready_s == result.boot_to_ready_s

    def test_readiness_probe_timeout(self, manager, fake_client):
        """Verify readiness probe timeout raises SandboxReadinessTimeoutError."""
        fake_client.fail_on_readiness = True
        handle = manager.create_sandbox()

        with pytest.raises(SandboxReadinessTimeoutError) as exc_info:
            manager.wait_until_ready(handle, timeout=0.1, poll_interval=0.02)

        assert "Readiness probe timed out" in str(exc_info.value)
        assert handle.state == "failed"

    def test_command_execution_success(self, manager, fake_client):
        """Verify bounded command execution inside guest."""
        handle = manager.create_sandbox()
        manager.wait_until_ready(handle, timeout=5.0, poll_interval=0.01)

        fake_client.set_command_response(
            "uname -a", exit_code=0, stdout="Linux celesto-guest 6.6.0\n", stderr=""
        )
        result = manager.execute_command(handle, "uname -a", timeout=15)

        assert result.exit_code == 0
        assert "Linux celesto-guest" in result.stdout
        assert result.stderr == ""
        assert result.execution_target == "celesto_sandbox"
        assert result.timed_out is False
        assert handle.state == "running"

    def test_command_execution_timeout(self, manager, fake_client):
        """Verify command timeout raises GuestCommandTimeoutError."""
        handle = manager.create_sandbox()
        manager.wait_until_ready(handle, timeout=5.0, poll_interval=0.01)

        fake_client.timeout_on_command = True
        with pytest.raises(GuestCommandTimeoutError):
            manager.execute_command(handle, "sleep 100", timeout=5)

    def test_command_execution_in_terminal_state_rejected(self, manager):
        """Verify executing commands in 'deleted' or 'failed' state is rejected."""
        handle = manager.create_sandbox()
        handle.state = "deleted"

        with pytest.raises(GuestCommandExecutionError) as exc_info:
            manager.execute_command(handle, "ls")
        assert "Cannot execute command: sandbox is in 'deleted' state" in str(exc_info.value)

    def test_command_output_truncation(self, manager, fake_client):
        """Verify long guest output is safely truncated to bounded size."""
        manager.max_output_bytes = 100
        handle = manager.create_sandbox()
        manager.wait_until_ready(handle, timeout=5.0, poll_interval=0.01)

        long_output = "A" * 500
        fake_client.set_command_response("cat bigfile", exit_code=0, stdout=long_output)

        res = manager.execute_command(handle, "cat bigfile")
        assert res.output_truncated is True
        assert len(res.stdout) < 200
        assert "TRUNCATED AT 100 BYTES" in res.stdout

    def test_idempotent_cleanup(self, manager, fake_client):
        """Verify cleanup is safe to call repeatedly."""
        handle = manager.create_sandbox()
        assert handle.provider_id in fake_client.computers

        # First cleanup
        res1 = manager.cleanup(handle)
        assert res1.success is True
        assert handle.state == "deleted"
        assert handle.provider_id not in fake_client.computers

        # Second cleanup (idempotent no-op)
        res2 = manager.cleanup(handle)
        assert res2.success is True
        assert handle.state == "deleted"

    def test_cleanup_failure_reporting(self, manager, fake_client):
        """Verify SandboxCleanupError is raised and surfaced when delete fails."""
        handle = manager.create_sandbox()
        fake_client.fail_on_delete = True

        with pytest.raises(SandboxCleanupError) as exc_info:
            manager.cleanup(handle)
        assert "Simulated deletion API failure" in str(exc_info.value)


class TestContextManagerAndGuaranteedCleanup:
    """Test context-manager semantics and cleanup on error/interruption."""

    @pytest.fixture
    def fake_client(self):
        client = FakeCelestoClient()
        client.is_fake = True
        return client

    def test_session_successful_workflow(self, fake_client):
        """Verify normal complete session executes commands and cleans up."""
        manager = SandboxLifecycleManager(client=fake_client)
        captured_provider_id = None

        with manager.session(boot_timeout=10.0, readiness_timeout=5.0) as sbx:
            captured_provider_id = sbx.provider_id
            assert sbx.state == "ready"
            assert captured_provider_id in fake_client.computers

            res = manager.execute_command(sbx, "echo GuardRail")
            assert res.exit_code == 0

        # After block: verify deletion was performed
        assert captured_provider_id in fake_client.deleted_computers
        assert captured_provider_id not in fake_client.computers

    def test_session_cleanup_on_exception_in_body(self, fake_client):
        """Verify cleanup runs when an unhandled exception occurs inside user block."""
        manager = SandboxLifecycleManager(client=fake_client)
        captured_provider_id = None

        with pytest.raises(RuntimeError, match="Simulated step failure in agent loop"):
            with manager.session(boot_timeout=10.0, readiness_timeout=5.0) as sbx:
                captured_provider_id = sbx.provider_id
                raise RuntimeError("Simulated step failure in agent loop")

        assert captured_provider_id is not None
        assert captured_provider_id in fake_client.deleted_computers
        assert captured_provider_id not in fake_client.computers

    def test_session_cleanup_on_readiness_timeout(self, fake_client):
        """Verify cleanup runs when readiness probe times out."""
        fake_client.fail_on_readiness = True
        manager = SandboxLifecycleManager(client=fake_client)

        with pytest.raises(SandboxReadinessTimeoutError):
            with manager.session(readiness_timeout=0.05):
                pass

        # Since readiness failed, computer was created and then cleaned up
        assert len(fake_client.deleted_computers) == 1


class TestPostgresLedgerEventIntegration:
    """Test persistence of lifecycle events to PostgreSQL ledger."""

    def test_lifecycle_events_persisted_to_ledger(self, db_session):
        """Verify creation, readiness, command, and cleanup events persist in db."""
        repo = LedgerRepository(db_session)
        run_in = RunCreate(
            run_id="run_lifecycle_test_01",
            problem_id="prompt_injection_exfil",
            defense_profile="baseline",
            execution_target="celesto_sandbox",
        )
        repo.create_run(run_in)

        fake_client = FakeCelestoClient()
        fake_client.is_fake = True
        manager = SandboxLifecycleManager(client=fake_client, ledger_repo=repo)

        with manager.session(run_id="run_lifecycle_test_01", readiness_timeout=5.0) as sbx:
            manager.execute_command(sbx, "id", run_id="run_lifecycle_test_01")

        # Inspect persisted events
        events = repo.list_events_for_run("run_lifecycle_test_01")
        event_types = [e.event_type for e in events]

        assert "sandbox.create.requested" in event_types
        assert "sandbox.create.succeeded" in event_types
        assert "sandbox.readiness.probe_started" in event_types
        assert "sandbox.readiness.ready" in event_types
        assert "sandbox.command.started" in event_types
        assert "sandbox.command.completed" in event_types
        assert "sandbox.cleanup.requested" in event_types
        assert "sandbox.cleanup.succeeded" in event_types

        # Verify run record was updated
        run_record = repo.get_run("run_lifecycle_test_01")
        assert run_record.state == "deleted"
        assert run_record.boot_to_ready_s is not None
        assert run_record.sandbox_name == sbx.sandbox_name


class TestSafetyAndRedaction:
    """Test prohibition of host execution fallback and secret redaction."""

    def test_prohibit_host_execution_fallback(self):
        """Verify HostExecutionForbiddenError is raised if non-cloud provider is set."""
        fake_client = FakeCelestoClient()
        fake_client.is_fake = False  # Enforce real check
        manager = SandboxLifecycleManager(client=fake_client)

        handle = manager.create_sandbox()
        handle.provider = "host"  # Illegal attempt

        with pytest.raises(HostExecutionForbiddenError) as exc_info:
            manager.execute_command(handle, "rm -rf /")
        assert "Host execution is strictly forbidden" in str(exc_info.value)

    def test_secret_redaction(self):
        """Verify API keys are masked in error messages and ledger event details."""
        raw_token = "celesto_live_abc1234567890def_secret_token"
        sanitized = sanitize_text(f"Connection failed with key {raw_token}")
        assert raw_token not in sanitized
        assert "[REDACTED_SECRET]" in sanitized
