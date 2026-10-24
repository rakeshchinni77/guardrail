"""Celesto sandbox lifecycle manager with bounded readiness probing and guaranteed cleanup."""

import logging
import time
import uuid
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime

from app.config import Settings, get_settings
from app.ledger.repository import LedgerRepository
from app.ledger.schemas import EventCreate
from app.sandbox.client import CelestoClientInterface, sanitize_text
from app.sandbox.exceptions import (
    GuestCommandExecutionError,
    GuestCommandTimeoutError,
    HostExecutionForbiddenError,
    SandboxCleanupError,
    SandboxCreationError,
    SandboxReadinessTimeoutError,
)
from app.sandbox.naming import generate_sandbox_name, validate_sandbox_name
from app.sandbox.types import (
    DeletionResult,
    GuestCommandResult,
    ReadinessProbeResult,
    SandboxHandle,
)

logger = logging.getLogger(__name__)


class SandboxLifecycleManager:
    """Manages creation, readiness probing, command execution, and cleanup of Celesto sandboxes."""

    def __init__(
        self,
        client: CelestoClientInterface,
        settings: Settings | None = None,
        ledger_repo: LedgerRepository | None = None,
        max_output_bytes: int | None = None,
    ) -> None:
        self.client = client
        self.settings = settings or get_settings()
        self.ledger_repo = ledger_repo
        self.max_output_bytes = max_output_bytes or self.settings.celesto_max_output_bytes

    def _record_event(
        self, run_id: str | None, event_type: str, details: dict | None = None
    ) -> None:
        """Safely record a lifecycle event to the PostgreSQL ledger if configured."""
        if not run_id or not self.ledger_repo:
            return

        sanitized_details = {k: sanitize_text(str(v)) for k, v in (details or {}).items()}
        event_in = EventCreate(
            event_id=f"evt_{uuid.uuid4().hex[:12]}",
            run_id=run_id,
            event_type=event_type,
            details=sanitized_details,
            timestamp=datetime.now(UTC),
        )
        try:
            self.ledger_repo.create_event(event_in)
        except Exception as exc:
            logger.warning(
                "Observability degradation: failed to persist event '%s' for run '%s': %s",
                event_type,
                run_id,
                exc,
            )

    def _update_run(self, run_id: str | None, **kwargs) -> None:
        """Safely update run attributes in the PostgreSQL ledger."""
        if not run_id or not self.ledger_repo:
            return
        try:
            self.ledger_repo.update_run(run_id, **kwargs)
        except Exception as exc:
            logger.warning(
                "Observability degradation: failed to update run '%s': %s",
                run_id,
                exc,
            )

    def create_sandbox(
        self,
        name: str | None = None,
        boot_timeout: float | None = None,
        run_id: str | None = None,
    ) -> SandboxHandle:
        """Provision a new Celesto sandbox with a verified unique name."""
        sandbox_name = name or generate_sandbox_name()
        if not validate_sandbox_name(sandbox_name):
            msg = (
                f"Invalid sandbox name '{sandbox_name}'. Must start with 'sbx-' "
                "followed by at least 8 lowercase alphanumeric characters."
            )
            raise SandboxCreationError(msg)

        effective_timeout = boot_timeout or self.settings.celesto_boot_timeout_seconds

        self._record_event(
            run_id,
            "sandbox.create.requested",
            {"sandbox_name": sandbox_name, "boot_timeout": effective_timeout},
        )

        try:
            create_data = self.client.create_computer(
                name=sandbox_name, boot_timeout=effective_timeout
            )
            provider_id = create_data.get("computer_id")
            if not provider_id:
                msg = f"Provider failed to return a computer ID for sandbox '{sandbox_name}'."
                raise SandboxCreationError(msg)

            handle = SandboxHandle(
                sandbox_name=sandbox_name,
                provider_id=provider_id,
                provider="cloud",
                state="created",
                metadata={"provider_data": create_data},
            )

            self._record_event(
                run_id,
                "sandbox.create.succeeded",
                {"sandbox_name": sandbox_name, "provider_id": provider_id},
            )
            self._update_run(run_id, sandbox_name=sandbox_name, state="created")
            return handle

        except Exception as exc:
            self._record_event(
                run_id,
                "sandbox.create.failed",
                {"sandbox_name": sandbox_name, "error": sanitize_text(str(exc))},
            )
            self._update_run(run_id, state="failed")
            if isinstance(exc, SandboxCreationError):
                raise
            raise SandboxCreationError(
                f"Failed to create sandbox '{sandbox_name}': {sanitize_text(str(exc))}"
            ) from exc

    def wait_until_ready(
        self,
        handle: SandboxHandle,
        timeout: float = 45.0,
        poll_interval: float = 2.0,
        run_id: str | None = None,
    ) -> ReadinessProbeResult:
        """Probe guest computer for readiness with bounded retries and timeout."""
        start_time = time.monotonic()
        deadline = start_time + timeout
        probe_command = "echo READY"
        attempts = 0

        self._record_event(
            run_id,
            "sandbox.readiness.probe_started",
            {"provider_id": handle.provider_id, "timeout": timeout},
        )

        last_error = None
        while time.monotonic() < deadline:
            attempts += 1
            try:
                # Probing with POSIX shell command (Ubuntu 24.04 scratch does not have python3)
                result = self.client.run_command(handle.provider_id, probe_command, timeout=10)
                if result.get("exit_code") == 0 and "READY" in (result.get("stdout") or ""):
                    boot_to_ready_s = round(time.monotonic() - start_time, 2)
                    handle.state = "ready"
                    handle.boot_to_ready_s = boot_to_ready_s

                    self._record_event(
                        run_id,
                        "sandbox.readiness.ready",
                        {
                            "provider_id": handle.provider_id,
                            "boot_to_ready_s": boot_to_ready_s,
                            "attempts": attempts,
                        },
                    )
                    self._update_run(run_id, state="ready", boot_to_ready_s=boot_to_ready_s)
                    return ReadinessProbeResult(
                        ready=True,
                        boot_to_ready_s=boot_to_ready_s,
                        attempts=attempts,
                        probe_command=probe_command,
                    )
            except Exception as exc:
                last_error = str(exc)

            time.sleep(poll_interval)

        # Timeout reached
        elapsed = round(time.monotonic() - start_time, 2)
        handle.state = "failed"
        self._record_event(
            run_id,
            "sandbox.readiness.timeout",
            {
                "provider_id": handle.provider_id,
                "elapsed_s": elapsed,
                "attempts": attempts,
                "last_error": sanitize_text(last_error or ""),
            },
        )
        self._update_run(run_id, state="failed")
        msg = (
            f"Readiness probe timed out after {elapsed}s ({attempts} attempts) "
            f"for computer '{handle.provider_id}'."
        )
        raise SandboxReadinessTimeoutError(msg)

    def execute_command(
        self,
        handle: SandboxHandle,
        command: str,
        timeout: int = 30,
        run_id: str | None = None,
    ) -> GuestCommandResult:
        """Execute a bounded shell command strictly inside the Celesto sandbox."""
        if handle.state in ("deleted", "failed"):
            msg = f"Cannot execute command: sandbox is in '{handle.state}' state."
            raise GuestCommandExecutionError(msg)

        # Enforce prohibition of host execution
        if handle.provider != "cloud" and not getattr(self.client, "is_fake", False):
            msg = (
                f"Invalid provider '{handle.provider}'. Execution must target "
                "Celesto sandbox microVM. Host execution is strictly forbidden."
            )
            raise HostExecutionForbiddenError(msg)

        handle.state = "running"
        self._record_event(
            run_id,
            "sandbox.command.started",
            {
                "provider_id": handle.provider_id,
                "command": sanitize_text(command),
                "timeout": timeout,
            },
        )
        self._update_run(run_id, state="running")

        t0 = time.perf_counter()
        try:
            result_data = self.client.run_command(handle.provider_id, command, timeout=timeout)
            duration_ms = round((time.perf_counter() - t0) * 1000.0, 2)

            exit_code = result_data.get("exit_code", -1)
            raw_stdout = result_data.get("stdout") or ""
            raw_stderr = result_data.get("stderr") or ""

            # Check output truncation limit
            output_truncated = False
            if len(raw_stdout) > self.max_output_bytes:
                raw_stdout = (
                    raw_stdout[: self.max_output_bytes]
                    + f"\n[... TRUNCATED AT {self.max_output_bytes} BYTES ...]"
                )
                output_truncated = True
            if len(raw_stderr) > self.max_output_bytes:
                raw_stderr = (
                    raw_stderr[: self.max_output_bytes]
                    + f"\n[... TRUNCATED AT {self.max_output_bytes} BYTES ...]"
                )
                output_truncated = True

            cmd_result = GuestCommandResult(
                exit_code=exit_code,
                stdout=raw_stdout,
                stderr=raw_stderr,
                duration_ms=duration_ms,
                timed_out=False,
                execution_target="celesto_sandbox",
                output_truncated=output_truncated,
            )

            event_type = (
                "sandbox.command.completed" if exit_code == 0 else "sandbox.command.non_zero_exit"
            )
            self._record_event(
                run_id,
                event_type,
                {
                    "provider_id": handle.provider_id,
                    "exit_code": exit_code,
                    "duration_ms": duration_ms,
                },
            )
            return cmd_result

        except GuestCommandTimeoutError:
            duration_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            self._record_event(
                run_id,
                "sandbox.command.timeout",
                {"provider_id": handle.provider_id, "duration_ms": duration_ms},
            )
            raise
        except Exception as exc:
            duration_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            self._record_event(
                run_id,
                "sandbox.command.failed",
                {
                    "provider_id": handle.provider_id,
                    "duration_ms": duration_ms,
                    "error": sanitize_text(str(exc)),
                },
            )
            if isinstance(exc, (GuestCommandExecutionError, HostExecutionForbiddenError)):
                raise
            raise GuestCommandExecutionError(
                f"Guest execution failed: {sanitize_text(str(exc))}"
            ) from exc

    def cleanup(
        self,
        handle: SandboxHandle | None,
        run_id: str | None = None,
    ) -> DeletionResult:
        """Guaranteed and idempotent teardown of the Celesto sandbox."""
        if not handle or not handle.provider_id:
            return DeletionResult(success=True, provider_id="", verified_absent=True)

        if handle.state == "deleted":
            # Idempotent cleanup: already deleted
            return DeletionResult(
                success=True,
                provider_id=handle.provider_id,
                verified_absent=True,
            )

        self._record_event(
            run_id,
            "sandbox.cleanup.requested",
            {"provider_id": handle.provider_id, "sandbox_name": handle.sandbox_name},
        )

        try:
            self.client.delete_computer(handle.provider_id)

            # Query exact computer status post-deletion
            terminal_status = None
            try:
                comp_info = self.client.get_computer(handle.provider_id)
                terminal_status = comp_info.get("status")
            except Exception as exc:
                logger.debug("get_computer for terminal state: %s", exc)

            # Verify deletion through list_computers
            try:
                active_computers = self.client.list_computers(limit=100)
                active_ids = {c.get("computer_id") for c in active_computers}
                verified_absent = handle.provider_id not in active_ids
            except Exception as exc:
                logger.warning("Could not verify absence via list: %s", exc)
                verified_absent = True

            handle.state = "deleted"
            effective_status = terminal_status or ("deleted" if verified_absent else "unknown")
            self._record_event(
                run_id,
                "sandbox.cleanup.succeeded",
                {
                    "provider_id": handle.provider_id,
                    "verified_absent": verified_absent,
                    "terminal_status": effective_status,
                },
            )
            self._update_run(run_id, state="deleted")
            return DeletionResult(
                success=True,
                provider_id=handle.provider_id,
                verified_absent=verified_absent,
                terminal_status=effective_status,
            )

        except Exception as exc:
            err_msg = sanitize_text(str(exc))
            self._record_event(
                run_id,
                "sandbox.cleanup.failed",
                {"provider_id": handle.provider_id, "error": err_msg},
            )
            raise SandboxCleanupError(
                f"Failed to cleanup sandbox '{handle.provider_id}': {err_msg}"
            ) from exc

    @contextmanager
    def session(
        self,
        sandbox_name: str | None = None,
        run_id: str | None = None,
        boot_timeout: float | None = None,
        readiness_timeout: float = 45.0,
    ) -> Generator[SandboxHandle, None, None]:
        """Context manager guaranteeing sandbox provisioning, readiness, and teardown."""
        handle: SandboxHandle | None = None
        primary_exception: BaseException | None = None

        try:
            handle = self.create_sandbox(
                name=sandbox_name, boot_timeout=boot_timeout, run_id=run_id
            )
            self.wait_until_ready(handle, timeout=readiness_timeout, run_id=run_id)
            yield handle
            # Normal completion
            handle.state = "succeeded"
            self._update_run(run_id, state="succeeded", success=True)

        except BaseException as exc:
            primary_exception = exc
            if handle:
                handle.state = "failed"
            self._update_run(run_id, state="failed", success=False)
            raise

        finally:
            if handle:
                try:
                    self.cleanup(handle, run_id=run_id)
                except Exception as cleanup_exc:
                    logger.error(
                        "Cleanup failure for sandbox '%s': %s",
                        handle.provider_id,
                        cleanup_exc,
                    )
                    if primary_exception is None:
                        raise
                    # If primary exception exists, preserve it and attach cleanup failure
                    primary_exception.add_note(
                        f"Guaranteed cleanup also failed: {sanitize_text(str(cleanup_exc))}"
                    )
